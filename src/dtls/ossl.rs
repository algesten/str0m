use openssl::asn1::Asn1Type;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::srtp::SrtpProfileId;
use openssl::ssl::{HandshakeError, MidHandshakeSslStream, Ssl, SslStream};
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode};
use openssl::x509::X509Name;
use openssl::x509::X509;

use std::io;
use std::mem;
use std::ops::Deref;
use std::panic::UnwindSafe;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;

use crate::io::DATAGRAM_MTU;

use super::DtlsError;
use super::Fingerprint;
use super::SrtpProfile;

const RSA_F4: u32 = 0x10001;
const DTLS_CIPHERS: &str = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
const DTLS_EC_CURVE: Nid = Nid::X9_62_PRIME256V1;
const DTLS_KEY_LABEL: &str = "EXTRACTOR-dtls_srtp";

// libWebRTC says "WebRTC" here when doing OpenSSL, for BoringSSL they seem
// to generate a random 8 characters.
// https://webrtc.googlesource.com/src/+/1568f1b1330f94494197696fe235094e6293b258/rtc_base/rtc_certificate_generator.cc#27
//
// Pion also sets this to "WebRTC", maybe for compatibility reasons.
// https://github.com/pion/webrtc/blob/eed2bb2d3b9f204f9de1cd7e1046ca5d652778d2/constants.go#L31
const DTLS_CERT_IDENTITY: &str = "WebRTC";

// extern "C" {
//     pub fn DTLSv1_2_method() -> *const openssl_sys::SSL_METHOD;
// }

/// Certificate used for DTLS.
#[derive(Debug, Clone)]
pub struct DtlsCert {
    pkey: PKey<Private>,
    x509: X509,
}

impl DtlsCert {
    /// Creates a new (self signed) DTLS certificate.
    pub fn new() -> Self {
        Self::self_signed().expect("create dtls cert")
    }

    // The libWebRTC code we try to match is at:
    // https://webrtc.googlesource.com/src/+/1568f1b1330f94494197696fe235094e6293b258/rtc_base/openssl_certificate.cc#58
    fn self_signed() -> Result<Self, DtlsError> {
        let f4 = BigNum::from_u32(RSA_F4).unwrap();
        let key = Rsa::generate_with_e(2048, &f4)?;
        let pkey = PKey::from_rsa(key)?;

        let mut x509b = X509::builder()?;
        x509b.set_version(2)?; // X509.V3 (zero indexed)

        // For firefox, we must increase the serial number for each generated certificate.
        // See https://github.com/versatica/mediasoup/issues/127#issuecomment-474460153
        static SERIAL: AtomicU32 = AtomicU32::new(1);
        let serial = SERIAL.fetch_add(1, Ordering::SeqCst);

        let serial_bn = BigNum::from_u32(serial)?;
        let serial = Asn1Integer::from_bn(&serial_bn)?;
        x509b.set_serial_number(&serial)?;
        let before = Asn1Time::from_unix(unix_time() - 3600)?;
        x509b.set_not_before(&before)?;
        let after = Asn1Time::days_from_now(7)?;
        x509b.set_not_after(&after)?;
        x509b.set_pubkey(&pkey)?;

        // The libWebRTC code for this is:
        //
        // !X509_NAME_add_entry_by_NID(name.get(), NID_commonName, MBSTRING_UTF8,
        // (unsigned char*)params.common_name.c_str(), -1, -1, 0) ||
        //
        // libWebRTC allows this name to be configured by the user of the library.
        // That's a future TODO for str0m.
        let mut nameb = X509Name::builder()?;
        nameb.append_entry_by_nid_with_type(
            Nid::COMMONNAME,
            DTLS_CERT_IDENTITY,
            Asn1Type::UTF8STRING,
        )?;

        let name = nameb.build();

        x509b.set_subject_name(&name)?;
        x509b.set_issuer_name(&name)?;

        x509b.sign(&pkey, MessageDigest::sha1())?;
        let x509 = x509b.build();

        Ok(DtlsCert { pkey, x509 })
    }

    /// Produce a (public) fingerprint of the cert.
    ///
    /// This is sent via SDP to the other peer to lock down the DTLS
    /// to this specific certificate.
    pub fn fingerprint(&self) -> Fingerprint {
        let digest: &[u8] = &self
            .x509
            .digest(MessageDigest::sha256())
            .expect("digest to fingerprint");

        Fingerprint {
            hash_func: "sha-256".into(),
            bytes: digest.to_vec(),
        }
    }
}

pub fn dtls_create_ctx(cert: &DtlsCert) -> Result<SslContext, DtlsError> {
    // TODO: Technically we want to disallow DTLS < 1.2, but that requires
    // us to use this commented out unsafe. We depend on browsers disallowing
    // it instead.
    // let method = unsafe { SslMethod::from_ptr(DTLSv1_2_method()) };
    let mut ctx = SslContextBuilder::new(SslMethod::dtls())?;

    ctx.set_cipher_list(DTLS_CIPHERS)?;
    let srtp_profiles = {
        // Rust can't join directly to a string, need to allocate a vec first :(
        // This happens very rarely so the extra allocations don't matter
        let all: Vec<_> = SrtpProfile::ALL
            .iter()
            .map(SrtpProfile::openssl_name)
            .collect();

        all.join(":")
    };
    ctx.set_tlsext_use_srtp(&srtp_profiles)?;

    let mut mode = SslVerifyMode::empty();
    mode.insert(SslVerifyMode::PEER);
    mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    ctx.set_verify_callback(mode, |_ok, _ctx| true);

    ctx.set_private_key(&cert.pkey)?;
    ctx.set_certificate(&cert.x509)?;

    let mut options = SslOptions::empty();
    options.insert(SslOptions::SINGLE_ECDH_USE);
    options.insert(SslOptions::NO_DTLSV1);
    ctx.set_options(options);

    let ctx = ctx.build();

    Ok(ctx)
}

pub fn dtls_ssl_create(ctx: &SslContext) -> Result<Ssl, DtlsError> {
    let mut ssl = Ssl::new(ctx)?;
    ssl.set_mtu(DATAGRAM_MTU as u32)?;

    let eckey = EcKey::from_curve_name(DTLS_EC_CURVE)?;
    ssl.set_tmp_ecdh(&eckey)?;

    Ok(ssl)
}

/// Keying material used as master key for SRTP.
pub struct KeyingMaterial(Vec<u8>);

impl KeyingMaterial {
    #[cfg(test)]
    pub fn new(m: &[u8]) -> Self {
        KeyingMaterial(m.into())
    }
}

impl Deref for KeyingMaterial {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for KeyingMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyingMaterial")
    }
}

pub struct TlsStream<S> {
    active: Option<bool>,
    state: State<S>,
    keying_mat: Option<(KeyingMaterial, SrtpProfile, Fingerprint)>,
    exported: bool,
}

pub enum State<S> {
    Init(Ssl, S),
    Handshaking(MidHandshakeSslStream<S>),
    Established(SslStream<S>),
    Empty,
}

/// This is okay because there is no way for a user of Rtc to interact with the Dtls subsystem
/// in a way that would allow them to observe a potentially broken invariant when catching a panic.
impl<S> UnwindSafe for State<S> {}

impl<S> TlsStream<S>
where
    S: io::Read + io::Write + UnwindSafe,
{
    pub fn new(ssl: Ssl, stream: S) -> Self {
        TlsStream {
            active: None,
            state: State::Init(ssl, stream),
            keying_mat: None,
            exported: false,
        }
    }

    pub fn is_inited(&self) -> bool {
        self.active.is_some()
    }

    pub fn is_active(&self) -> Option<bool> {
        self.active
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, State::Established(_))
    }

    pub fn set_active(&mut self, active: bool) {
        assert!(
            self.active.is_none(),
            "set_active should called exactly once"
        );
        self.active = Some(active);
    }

    pub fn complete_handshake_until_block(&mut self) -> Result<bool, DtlsError> {
        if let Err(e) = self.handshaken() {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(false)
            } else {
                Err(e.into())
            }
        } else {
            Ok(true)
        }
    }

    pub fn is_handshaken(&self) -> bool {
        matches!(self.state, State::Established(_))
    }

    pub fn handshaken(&mut self) -> Result<&mut SslStream<S>, io::Error> {
        let active = self.is_active().expect("set_active must be called");
        let v = self.state.handshaken(active)?;

        // first time we complete the handshake, we extract the keying material for SRTP.
        if !self.exported {
            let keying_mat = export_srtp_keying_material(v)?;
            self.exported = true;
            self.keying_mat = Some(keying_mat);
        }

        Ok(v)
    }

    pub fn take_srtp_keying_material(
        &mut self,
    ) -> Option<(KeyingMaterial, SrtpProfile, Fingerprint)> {
        self.keying_mat.take()
    }

    pub fn inner_mut(&mut self) -> &mut S {
        match &mut self.state {
            State::Init(_, s) => s,
            State::Handshaking(v) => v.get_mut(),
            State::Established(v) => v.get_mut(),
            State::Empty => panic!("inner_mut on empty dtls state"),
        }
    }
}

impl<S> State<S>
where
    S: io::Read + io::Write + UnwindSafe,
{
    fn handshaken(&mut self, active: bool) -> Result<&mut SslStream<S>, io::Error> {
        if let State::Established(v) = self {
            return Ok(v);
        }

        let taken = mem::replace(self, State::Empty);

        let result = match taken {
            State::Empty | State::Established(_) => unreachable!(),
            State::Init(ssl, stream) => {
                if active {
                    debug!("Connect");
                    ssl.connect(stream)
                } else {
                    debug!("Accept");
                    ssl.accept(stream)
                }
            }
            State::Handshaking(mid) => mid.handshake(),
        };

        match result {
            Ok(v) => {
                debug!("Established version: {:}", v.ssl().version_str());

                let _ = mem::replace(self, State::Established(v));

                // recursively return the &mut SslStream.
                self.handshaken(active)
            }
            Err(e) => Err(match e {
                HandshakeError::WouldBlock(e) => {
                    let _ = mem::replace(self, State::Handshaking(e));
                    io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock")
                }
                HandshakeError::SetupFailure(e) => {
                    debug!("DTLS setup failed: {:?}", e);
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                }
                HandshakeError::Failure(e) => {
                    let e = e.into_error();
                    debug!("DTLS failure: {:?}", e);
                    io::Error::new(io::ErrorKind::InvalidData, e)
                }
            }),
        }
    }
}

fn export_srtp_keying_material<S>(
    stream: &mut SslStream<S>,
) -> Result<(KeyingMaterial, SrtpProfile, Fingerprint), io::Error> {
    let ssl = stream.ssl();

    // remote peer certificate fingerprint
    let x509 = ssl
        .peer_certificate()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No remote X509 cert"))?;
    let digest: &[u8] = &x509.digest(MessageDigest::sha256())?;

    let fp = Fingerprint {
        hash_func: "sha-256".into(),
        bytes: digest.to_vec(),
    };

    let srtp_profile_id = ssl
        .selected_srtp_profile()
        .map(|s| s.id())
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to negotiate SRTP profile"))?;
    let srtp_profile: SrtpProfile = srtp_profile_id.try_into()?;

    // extract SRTP keying material
    let mut buf = vec![0_u8; srtp_profile.keying_material_len()];
    ssl.export_keying_material(&mut buf, DTLS_KEY_LABEL, None)?;

    let mat = KeyingMaterial(buf);

    Ok((mat, srtp_profile, fp))
}

impl<S> io::Read for TlsStream<S>
where
    S: io::Read + io::Write + UnwindSafe,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handshaken()?.read(buf)
    }
}

impl<S> io::Write for TlsStream<S>
where
    S: io::Read + io::Write + UnwindSafe,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handshaken()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handshaken()?.flush()
    }
}

impl TryFrom<SrtpProfileId> for SrtpProfile {
    type Error = io::Error;

    fn try_from(value: SrtpProfileId) -> Result<Self, Self::Error> {
        match value {
            SrtpProfileId::SRTP_AES128_CM_SHA1_80 => Ok(SrtpProfile::Aes128CmSha1_80),
            SrtpProfileId::SRTP_AEAD_AES_128_GCM => Ok(SrtpProfile::AeadAes128Gcm),
            x => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unsupported SRTP profile {:x}", x.as_raw()),
            )),
        }
    }
}

// TODO: Refactor away this use of System::now, to instead go via InstantExt
// and base the time on the first Instant. This would require lazy init of
// Dtls, or that we pass a first ever Instant into the creation of Rtc.
//
// This is not a super high priority since it's only used for setting a before
// time in the generated certificate, and one hour back from that.
pub fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
