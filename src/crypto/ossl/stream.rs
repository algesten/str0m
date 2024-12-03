use std::panic::UnwindSafe;
use std::{io, mem};

use openssl::hash::MessageDigest;
use openssl::srtp::SrtpProfileId;
use openssl::ssl::{HandshakeError, MidHandshakeSslStream, Ssl, SslStream};

use crate::crypto::{Fingerprint, KeyingMaterial, SrtpProfile};

use super::CryptoError;

const DTLS_KEY_LABEL: &str = "EXTRACTOR-dtls_srtp";

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

    pub fn complete_handshake_until_block(&mut self) -> Result<bool, CryptoError> {
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

    pub fn is_handshaking(&self) -> bool {
        matches!(self.state, State::Init(_, _) | State::Handshaking(_))
    }

    pub fn is_connected(&self) -> bool {
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

    let mat = KeyingMaterial::new(buf);

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
