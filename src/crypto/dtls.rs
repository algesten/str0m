#![allow(unreachable_patterns, dead_code, unused_variables)]

use std::collections::VecDeque;
use std::fmt;
use std::panic::UnwindSafe;
use std::time::Instant;

use crate::net::DatagramSend;

use super::{
    CryptoError, CryptoProvider, CryptoProviderId, Fingerprint, KeyingMaterial, SrtpProfile,
};

pub(crate) trait DtlsIdentity: fmt::Debug {
    fn fingerprint(&self) -> Fingerprint;
    fn create_context(&self) -> Result<Box<dyn DtlsContext>, CryptoError>;
    fn crypto_provider(&self) -> CryptoProvider;
    fn boxed_clone(&self) -> Box<dyn DtlsIdentity>;
}

pub(crate) trait DtlsContext: UnwindSafe + Send + Sync {
    // Returns the crypto context.
    fn crypto_provider(&self) -> CryptoProvider;

    // Returns the local certificate fingerprint.
    fn local_fingerprint(&self) -> Fingerprint;

    // DTLS session management
    fn set_active(&mut self, active: bool) -> ();
    fn is_active(&self) -> Option<bool>;
    fn is_connected(&self) -> bool;
    fn handle_handshake(
        &mut self,
        out_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<bool, CryptoError>;
    fn handle_receive(
        &mut self,
        datagram: &[u8],
        out_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError>;
    fn poll_datagram(&mut self) -> Option<DatagramSend>;
    fn poll_timeout(&mut self, now: Instant) -> Option<Instant>;
    fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError>;
}

/// Events arising from a [`Dtls`] instance.
pub enum DtlsEvent {
    /// When the DTLS has finished handshaking.
    Connected,

    /// Keying material for SRTP encryption master key and the selected SRTP profile.
    SrtpKeyingMaterial(KeyingMaterial, SrtpProfile),

    /// The fingerprint of the remote peer.
    ///
    /// This should be checked against the fingerprint communicated in the SDP.
    RemoteFingerprint(Fingerprint),

    /// Decrypted data from incoming DTLS traffic.
    Data(Vec<u8>),
}

/// Certificate used for DTLS.
pub struct DtlsCert(Box<dyn DtlsIdentity>);

impl Clone for DtlsCert {
    fn clone(&self) -> Self {
        Self(self.0.boxed_clone())
    }
}

impl DtlsCert {
    /// Create a new DtlsCert using the given provider.
    pub fn new(crypto_provider_id: CryptoProviderId) -> Self {
        let crypto_provider: CryptoProvider = crypto_provider_id.into();
        DtlsCert(crypto_provider.create_dtls_identity())
    }

    #[cfg(feature = "openssl")]
    /// Create a new OpenSSL variant of the certificate.
    pub fn new_openssl() -> Self {
        Self::new(super::CryptoProviderId::default())
    }

    /// Creates a fingerprint for this certificate.
    ///
    /// Fingerprints are used to verify a remote peer's certificate.
    pub fn fingerprint(&self) -> Fingerprint {
        self.0.fingerprint()
    }

    /// Creates a DTLS context using this certificate as the identity.
    ///
    /// Multiple contexts may be created using the same identity.
    pub(crate) fn create_context(&self) -> Result<Box<dyn DtlsContext>, CryptoError> {
        self.0.create_context()
    }

    /// Obtains the CryptoProvider that this Cert was built with.
    pub(crate) fn crypto_provider(&self) -> CryptoProvider {
        self.0.crypto_provider()
    }
}

impl fmt::Debug for DtlsCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
