use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{HandshakeError, MidHandshakeSslStream, Ssl, SslStream};
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode};
use openssl::x509::X509;
use std::io;
use std::mem;
use std::ops::Deref;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;

use crate::io::DATAGRAM_MTU;
use crate::Fingerprint;

use super::DtlsError;

const RSA_F4: u32 = 0x10001;
const DTLS_CIPHERS: &str = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
const DTLS_SRTP: &str = "SRTP_AES128_CM_SHA1_80";
const DTLS_EC_CURVE: Nid = Nid::X9_62_PRIME256V1;
const DTLS_KEY_LABEL: &str = "EXTRACTOR-dtls_srtp";

extern "C" {
    pub fn DTLSv1_2_method() -> *const openssl_sys::SSL_METHOD;
}

pub fn dtls_create_ctx() -> Result<(SslContext, Fingerprint), DtlsError> {
    let method = unsafe { SslMethod::from_ptr(DTLSv1_2_method()) };
    let mut ctx = SslContextBuilder::new(method)?;

    ctx.set_cipher_list(DTLS_CIPHERS)?;
    ctx.set_tlsext_use_srtp(DTLS_SRTP)?;

    let mut mode = SslVerifyMode::empty();
    mode.insert(SslVerifyMode::PEER);
    mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    ctx.set_verify_callback(mode, |_ok, _ctx| true);

    let f4 = BigNum::from_u32(RSA_F4).unwrap();
    let key = Rsa::generate_with_e(2048, &f4)?;
    let pkey = PKey::from_rsa(key)?;
    ctx.set_private_key(&pkey)?;

    let mut x509 = X509::builder()?;

    // For firefox, we must increase the serial number for each generated certificate.
    // See https://github.com/versatica/mediasoup/issues/127#issuecomment-474460153
    static SERIAL: AtomicU32 = AtomicU32::new(1);
    let serial = SERIAL.fetch_add(1, Ordering::SeqCst);

    let serial_bn = BigNum::from_u32(serial)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    x509.set_serial_number(&serial)?;
    let before = Asn1Time::from_unix(unix_time() - 3600)?;
    x509.set_not_before(&before)?;
    let after = Asn1Time::days_from_now(7)?;
    x509.set_not_after(&after)?;
    x509.set_pubkey(&pkey)?;

    x509.sign(&pkey, MessageDigest::sha1())?;
    let cert = x509.build();

    ctx.set_certificate(&cert)?;

    let mut options = SslOptions::empty();
    options.insert(SslOptions::SINGLE_ECDH_USE);
    options.insert(SslOptions::NO_DTLSV1);
    ctx.set_options(options);

    let ctx = ctx.build();

    let digest: &[u8] = &cert.digest(MessageDigest::sha256())?;
    let fp = Fingerprint {
        hash_func: "sha-256".into(),
        bytes: digest.to_vec(),
    };

    Ok((ctx, fp))
}

pub fn dtls_ssl_create(ctx: &SslContext) -> Result<Ssl, DtlsError> {
    let mut ssl = Ssl::new(ctx)?;
    ssl.set_mtu(DATAGRAM_MTU as u32)?;

    let eckey = EcKey::from_curve_name(DTLS_EC_CURVE)?;
    ssl.set_tmp_ecdh(&eckey)?;

    Ok(ssl)
}

/// Keying material used as master key for SRTP.
pub struct KeyingMaterial([u8; 60]);

impl KeyingMaterial {
    #[cfg(test)]
    pub fn new(m: [u8; 60]) -> Self {
        KeyingMaterial(m)
    }
}

impl Deref for KeyingMaterial {
    type Target = [u8; 60];

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
    keying_mat: Option<(KeyingMaterial, Fingerprint)>,
    exported: bool,
}

pub enum State<S> {
    Init(Ssl, S),
    Handshaking(MidHandshakeSslStream<S>),
    Established(SslStream<S>),
    Empty,
}

impl<S> TlsStream<S>
where
    S: io::Read + io::Write,
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
        let state_init = matches!(self.state, State::Init(_, _));
        !state_init
    }

    pub fn is_active(&self) -> Option<bool> {
        self.active
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

    pub fn take_srtp_keying_material(&mut self) -> Option<(KeyingMaterial, Fingerprint)> {
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
    S: io::Read + io::Write,
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
                debug!("Established");

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
) -> Result<(KeyingMaterial, Fingerprint), io::Error> {
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

    // extract SRTP keying material
    let mut buf = [0_u8; 60];
    ssl.export_keying_material(&mut buf, DTLS_KEY_LABEL, None)?;

    let mat = KeyingMaterial(buf);

    Ok((mat, fp))
}

impl<S> io::Read for TlsStream<S>
where
    S: io::Read + io::Write,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handshaken()?.read(buf)
    }
}

impl<S> io::Write for TlsStream<S>
where
    S: io::Read + io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handshaken()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handshaken()?.flush()
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
