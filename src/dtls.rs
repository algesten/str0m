use std::collections::VecDeque;
use std::io;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::time::Instant;

use crate::crypto::dtls::{DtlsCert, DtlsOutput};
use crate::crypto::dtls::{DtlsInstance, DtlsProvider, DtlsVersion};
use crate::crypto::Fingerprint;
use crate::crypto::Sha256Provider;
use crate::crypto::{CryptoError, DtlsError};
use crate::io::DatagramSend;
use crate::util::already_happened;

/// Encapsulation of DTLS.
///
/// This is a thin wrapper around `DtlsInstance` that adds fingerprint tracking
/// and active/passive state management. The API follows dimpl's sans-IO pattern.
pub struct Dtls {
    /// The underlying DTLS instance.
    instance: Box<dyn DtlsInstance>,

    /// The fingerprint of the local certificate.
    fingerprint: Fingerprint,

    /// Remote fingerprint (set when received via poll_output).
    remote_fingerprint: Option<Fingerprint>,

    /// Whether set_active has been called.
    active_state: Option<bool>,

    /// Packets to be sent.
    pending_packets: VecDeque<DatagramSend>,
}

pub(crate) fn is_would_block(error: &DtlsError) -> bool {
    match error {
        DtlsError::Io(e) => e.kind() == io::ErrorKind::WouldBlock,
        DtlsError::CryptoError(crypto_err) => match crypto_err {
            CryptoError::Io(e) => e.kind() == io::ErrorKind::WouldBlock,
            #[allow(unreachable_patterns)]
            _ => false,
        },
    }
}

impl UnwindSafe for Dtls {}
impl RefUnwindSafe for Dtls {}

impl Dtls {
    /// Creates a new DTLS instance.
    pub fn new(
        cert: &DtlsCert,
        dtls_provider: &dyn DtlsProvider,
        sha256_provider: &dyn Sha256Provider,
        now: Instant,
        dtls_version: DtlsVersion,
    ) -> Result<Self, DtlsError> {
        let instance = dtls_provider
            .new_dtls(cert, now, dtls_version)
            .map_err(DtlsError::CryptoError)?;

        // Compute fingerprint from the certificate DER bytes
        let fingerprint = Fingerprint {
            hash_func: "sha-256".to_string(),
            bytes: sha256_provider.sha256(&cert.certificate).to_vec(),
        };

        Ok(Self {
            instance,
            fingerprint,
            remote_fingerprint: None,
            active_state: None,
            pending_packets: VecDeque::new(),
        })
    }

    /// Tells if this instance has been inited (set_active called).
    pub fn is_inited(&self) -> bool {
        self.active_state.is_some()
    }

    /// Set whether this instance is active (client) or passive (server).
    pub fn set_active(&mut self, active: bool) {
        self.active_state = Some(active);
        self.instance.set_active(active)
    }

    /// If set_active was called, returns what was set.
    pub fn is_active(&self) -> Option<bool> {
        self.active_state
    }

    /// The local certificate fingerprint.
    pub fn local_fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Remote fingerprint, if received.
    pub fn remote_fingerprint(&self) -> Option<&Fingerprint> {
        self.remote_fingerprint.as_ref()
    }

    /// Set the remote fingerprint (extracted from peer certificate).
    pub fn set_remote_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.remote_fingerprint = Some(fingerprint);
    }

    /// Poll for output from the DTLS instance.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        let next = self.instance.poll_output(buf);

        if let DtlsOutput::Packet(packet) = next {
            self.pending_packets.push_back(packet.to_vec().into());

            // Return timeout indicating we want another poll straight away
            return DtlsOutput::Timeout(already_happened());
        }

        next
    }

    pub fn poll_packet(&mut self) -> Option<DatagramSend> {
        self.pending_packets.pop_front()
    }

    /// Handle an incoming DTLS packet.
    pub fn handle_receive(&mut self, packet: &[u8]) -> Result<(), DtlsError> {
        if self.active_state.is_none() {
            debug!("Ignoring DTLS datagram prior to DTLS start");
            return Ok(());
        }

        self.instance
            .handle_packet(packet)
            .map_err(|e| DtlsError::CryptoError(CryptoError::Other(format!("DTLS error: {}", e))))
    }

    /// Send application data over DTLS.
    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), DtlsError> {
        self.instance
            .send_application_data(data)
            .map_err(|e| DtlsError::CryptoError(CryptoError::Other(format!("DTLS error: {}", e))))
    }

    /// Handle a timeout event.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsError> {
        self.instance
            .handle_timeout(now)
            .map_err(|e| DtlsError::CryptoError(CryptoError::Other(format!("DTLS error: {}", e))))
    }
}
