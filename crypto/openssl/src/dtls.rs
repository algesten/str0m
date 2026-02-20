//! DTLS implementation using OpenSSL.

use std::collections::VecDeque;
use std::panic::UnwindSafe;
use std::time::{Duration, Instant};
use std::{io, mem};

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::srtp::SrtpProfileId;
use openssl::ssl::{HandshakeError, MidHandshakeSslStream, Ssl};
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod};
use openssl::ssl::{SslOptions, SslStream, SslVerifyMode};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder, X509};

use str0m_proto::crypto::dtls::{DtlsCert, KeyingMaterial, SrtpProfile};
use str0m_proto::crypto::dtls::{DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};
use str0m_proto::crypto::{CryptoError, DtlsVersion};
use str0m_proto::{DATAGRAM_MTU, DATAGRAM_MTU_WARN};

// ============================================================================
// IO Buffer
// ============================================================================

#[derive(Default)]
struct IoBuffer {
    incoming: Vec<u8>,
    outgoing: VecDeque<Vec<u8>>,
}

impl IoBuffer {
    fn set_incoming(&mut self, buf: &[u8]) {
        self.incoming.extend_from_slice(buf);

        // Each packet ought to be ~MTU 1400. If openssl is
        // not consuming all incoming data, we got some problem.
        assert!(
            self.incoming.len() < 30_000,
            "Incoming DTLS data is not being consumed"
        );
    }

    fn pop_outgoing(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }
}

impl io::Read for IoBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.incoming.len();

        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock"));
        }

        let max = buf.len().min(n);

        buf[..max].copy_from_slice(&self.incoming[..max]);

        if max == self.incoming.len() {
            self.incoming.truncate(0);
        } else {
            self.incoming.drain(..max);
        }

        Ok(n)
    }
}

impl io::Write for IoBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let dsend = buf.to_vec();
        self.outgoing.push_back(dsend);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ============================================================================
// TLS Stream
// ============================================================================

const DTLS_KEY_LABEL: &str = "EXTRACTOR-dtls_srtp";

struct TlsStream<S> {
    active: Option<bool>,
    state: State<S>,
    keying_mat: Option<(KeyingMaterial, SrtpProfile, Vec<u8>)>,
    exported: bool,
}

enum State<S> {
    Init(Ssl, S),
    Handshaking(MidHandshakeSslStream<S>),
    Established(SslStream<S>),
    Empty,
}

impl<S> UnwindSafe for State<S> {}

impl<S> TlsStream<S>
where
    S: io::Read + io::Write + UnwindSafe,
{
    fn new(ssl: Ssl, stream: S) -> Self {
        TlsStream {
            active: None,
            state: State::Init(ssl, stream),
            keying_mat: None,
            exported: false,
        }
    }

    fn is_active(&self) -> Option<bool> {
        self.active
    }

    fn set_active(&mut self, active: bool) {
        assert!(
            self.active.is_none(),
            "set_active should be called exactly once"
        );
        self.active = Some(active);
    }

    fn complete_handshake_until_block(&mut self) -> Result<bool, io::Error> {
        match self.handshaken() {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn is_handshaking(&self) -> bool {
        matches!(self.state, State::Init(_, _) | State::Handshaking(_))
    }

    fn is_connected(&self) -> bool {
        matches!(self.state, State::Established(_))
    }

    fn handshaken(&mut self) -> Result<&mut SslStream<S>, io::Error> {
        let active = self.is_active().expect("set_active must be called");
        let v = self.state.handshaken(active)?;

        if !self.exported {
            let keying_mat = export_srtp_keying_material(v)?;
            self.exported = true;
            self.keying_mat = Some(keying_mat);
        }

        Ok(v)
    }

    fn take_srtp_keying_material(&mut self) -> Option<(KeyingMaterial, SrtpProfile, Vec<u8>)> {
        self.keying_mat.take()
    }

    fn inner_mut(&mut self) -> &mut S {
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
    stream: &SslStream<S>,
) -> Result<(KeyingMaterial, SrtpProfile, Vec<u8>), io::Error> {
    let ssl = stream.ssl();

    let x509 = ssl
        .peer_certificate()
        .ok_or_else(|| io::Error::other("No remote X509 cert"))?;

    // Get the certificate DER for PeerCert output
    let peer_cert_der = x509.to_der()?;

    let srtp_profile_id = ssl
        .selected_srtp_profile()
        .map(|s| s.id())
        .ok_or_else(|| io::Error::other("Failed to negotiate SRTP profile"))?;
    let srtp_profile = srtp_profile_from_id(srtp_profile_id)?;

    let mut buf = vec![0_u8; srtp_profile.keying_material_len()];
    ssl.export_keying_material(&mut buf, DTLS_KEY_LABEL, None)?;

    let mat = KeyingMaterial::new(&buf);

    Ok((mat, srtp_profile, peer_cert_der))
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

/// Convert OpenSSL SrtpProfileId to dimpl's SrtpProfile.
fn srtp_profile_from_id(value: SrtpProfileId) -> Result<SrtpProfile, io::Error> {
    match value {
        SrtpProfileId::SRTP_AES128_CM_SHA1_80 => Ok(SrtpProfile::AES128_CM_SHA1_80),
        SrtpProfileId::SRTP_AEAD_AES_128_GCM => Ok(SrtpProfile::AEAD_AES_128_GCM),
        SrtpProfileId::SRTP_AEAD_AES_256_GCM => Ok(SrtpProfile::AEAD_AES_256_GCM),
        x => Err(io::Error::other(format!(
            "Unsupported SRTP profile {:x}",
            x.as_raw()
        ))),
    }
}

// ============================================================================
// DTLS Implementation
// ============================================================================

const DTLS_CIPHERS: &str = "ECDHE+AESGCM:DHE+AESGCM:ECDHE+AES256:DHE+AES256";

struct OsslDtlsImpl {
    tls: TlsStream<IoBuffer>,
}

impl OsslDtlsImpl {
    fn new(cert: &DtlsCert) -> Result<Self, CryptoError> {
        let context = dtls_create_ctx(cert)?;
        let ssl = dtls_ssl_create(&context)?;
        Ok(OsslDtlsImpl {
            tls: TlsStream::new(ssl, IoBuffer::default()),
        })
    }

    fn set_active(&mut self, active: bool) {
        self.tls.set_active(active);
    }

    fn is_active(&self) -> Option<bool> {
        self.tls.is_active()
    }

    fn is_connected(&self) -> bool {
        self.tls.is_connected()
    }

    fn handle_receive(&mut self, m: &[u8]) -> Result<Option<Vec<u8>>, CryptoError> {
        self.tls.inner_mut().set_incoming(m);

        // Try to complete handshake
        if self.tls.is_handshaking() {
            match self.tls.complete_handshake_until_block() {
                Ok(true) => {
                    // Handshake just completed
                    return Ok(None);
                }
                Ok(false) => {
                    // Still handshaking
                    return Ok(None);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Read application data
        use io::Read;
        let mut buf = vec![0; 2000];
        match self.tls.read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn poll_datagram(&mut self) -> Option<Vec<u8>> {
        let x = self.tls.inner_mut().pop_outgoing();
        if let Some(x) = &x {
            if x.len() > DATAGRAM_MTU_WARN {
                warn!("DTLS above MTU {}: {}", DATAGRAM_MTU_WARN, x.len());
            }
            trace!("Poll datagram: {}", x.len());
        }
        x
    }

    fn poll_timeout(&self, now: Instant) -> Option<Instant> {
        self.tls
            .is_handshaking()
            .then(|| now + Duration::from_millis(500))
    }

    fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use io::Write;
        Ok(self.tls.write_all(data)?)
    }

    fn take_keying_material(&mut self) -> Option<(KeyingMaterial, SrtpProfile, Vec<u8>)> {
        self.tls.take_srtp_keying_material()
    }
}

fn dtls_create_ctx(cert: &DtlsCert) -> Result<SslContext, CryptoError> {
    let mut ctx = SslContextBuilder::new(SslMethod::dtls())?;

    ctx.set_cipher_list(DTLS_CIPHERS)?;

    let srtp_profiles = {
        let all: Vec<_> = SrtpProfile::ALL
            .iter()
            .map(|&p| srtp_profile_openssl_name(p))
            .collect();
        all.join(":")
    };
    ctx.set_tlsext_use_srtp(&srtp_profiles)?;

    let mut mode = SslVerifyMode::empty();
    mode.insert(SslVerifyMode::PEER);
    mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    ctx.set_verify_callback(mode, |_ok, _ctx| true);

    // Load certificate and private key from DER
    let x509 = X509::from_der(&cert.certificate)?;
    let pkey = PKey::private_key_from_der(&cert.private_key)?;

    ctx.set_private_key(&pkey)?;
    ctx.set_certificate(&x509)?;

    let mut options = SslOptions::empty();
    options.insert(SslOptions::SINGLE_ECDH_USE);
    options.insert(SslOptions::NO_DTLSV1);
    // Use the MTU we set via set_mtu() instead of querying
    options.insert(SslOptions::NO_QUERY_MTU);
    ctx.set_options(options);

    Ok(ctx.build())
}

fn dtls_ssl_create(ctx: &SslContext) -> Result<Ssl, CryptoError> {
    let mut ssl = Ssl::new(ctx)?;
    ssl.set_mtu(DATAGRAM_MTU as u32)?;
    Ok(ssl)
}

/// Get the OpenSSL name for an SRTP profile.
fn srtp_profile_openssl_name(profile: SrtpProfile) -> &'static str {
    match profile {
        SrtpProfile::AES128_CM_SHA1_80 => "SRTP_AES128_CM_SHA1_80",
        SrtpProfile::AEAD_AES_128_GCM => "SRTP_AEAD_AES_128_GCM",
        SrtpProfile::AEAD_AES_256_GCM => "SRTP_AEAD_AES_256_GCM",
    }
}

// ============================================================================
// DTLS Instance Implementation
// ============================================================================

pub(super) struct OsslDtlsInstance {
    inner: OsslDtlsImpl,
    pending_packets: VecDeque<Vec<u8>>,
    pending_keying_material: Option<(Vec<u8>, SrtpProfile)>,
    pending_peer_cert: Option<Vec<u8>>,
    pending_application_data: VecDeque<Vec<u8>>,
    /// Application data queued before handshake completes
    queued_app_data: VecDeque<Vec<u8>>,
    next_timeout: Option<Instant>,
    connected_emitted: bool,
}

impl std::fmt::Debug for OsslDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslDtlsInstance").finish()
    }
}

impl OsslDtlsInstance {
    pub(super) fn new(cert: &DtlsCert) -> Result<Self, CryptoError> {
        let inner = OsslDtlsImpl::new(cert)?;
        Ok(Self {
            inner,
            pending_packets: VecDeque::new(),
            pending_keying_material: None,
            pending_peer_cert: None,
            pending_application_data: VecDeque::new(),
            queued_app_data: VecDeque::new(),
            next_timeout: None,
            connected_emitted: false,
        })
    }

    fn collect_output(&mut self) {
        // Collect outgoing packets
        while let Some(packet) = self.inner.poll_datagram() {
            self.pending_packets.push_back(packet);
        }

        // Check for keying material
        if self.pending_keying_material.is_none() {
            if let Some((km, profile, peer_cert_der)) = self.inner.take_keying_material() {
                self.pending_keying_material = Some((km.as_ref().to_vec(), profile));
                self.pending_peer_cert = Some(peer_cert_der);
            }
        }

        // Update timeout
        if let Some(timeout) = self.inner.poll_timeout(Instant::now()) {
            self.next_timeout = Some(timeout);
        }
    }

    /// Flush any application data that was queued before the handshake completed.
    fn flush_queued_app_data(&mut self) -> Result<(), DtlsImplError> {
        while let Some(queued) = self.queued_app_data.pop_front() {
            if let Err(e) = self.inner.handle_input(&queued) {
                self.queued_app_data.push_front(queued);
                return Err(DtlsImplError::CryptoError(format!("DTLS error: {}", e)));
            }
            self.collect_output();
        }
        Ok(())
    }
}

impl DtlsInstance for OsslDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.inner.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        match self.inner.handle_receive(packet) {
            Ok(Some(data)) => {
                self.pending_application_data.push_back(data);
            }
            Ok(None) => {}
            Err(e) => {
                // Ignore WouldBlock errors
                if let CryptoError::Io(ref io_err) = e {
                    if io_err.kind() == std::io::ErrorKind::WouldBlock {
                        // This is fine
                    } else {
                        return Err(DtlsImplError::CryptoError(format!("DTLS error: {}", e)));
                    }
                } else {
                    return Err(DtlsImplError::CryptoError(format!("DTLS error: {}", e)));
                }
            }
        }

        self.collect_output();

        // If we just became connected, flush any queued application data
        if self.inner.is_connected() {
            self.flush_queued_app_data()?;
        }

        Ok(())
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        // Return pending packets first
        if let Some(packet) = self.pending_packets.pop_front() {
            if packet.len() <= buf.len() {
                buf[..packet.len()].copy_from_slice(&packet);
                return DtlsOutput::Packet(&buf[..packet.len()]);
            } else {
                self.pending_packets.push_front(packet);
            }
        }

        // Return timeout
        if let Some(timeout) = self.next_timeout.take() {
            return DtlsOutput::Timeout(timeout);
        }

        // Return connected event
        if self.inner.is_connected() && !self.connected_emitted {
            self.connected_emitted = true;
            return DtlsOutput::Connected;
        }

        // Return peer certificate DER
        if let Some(cert_der) = self.pending_peer_cert.take() {
            if cert_der.len() <= buf.len() {
                buf[..cert_der.len()].copy_from_slice(&cert_der);
                return DtlsOutput::PeerCert(&buf[..cert_der.len()]);
            } else {
                self.pending_peer_cert = Some(cert_der);
            }
        }

        // Return keying material
        if let Some((km_bytes, profile)) = self.pending_keying_material.take() {
            if km_bytes.len() <= buf.len() {
                buf[..km_bytes.len()].copy_from_slice(&km_bytes);
                let km = KeyingMaterial::new(&buf[..km_bytes.len()]);
                return DtlsOutput::KeyingMaterial(km, profile);
            } else {
                self.pending_keying_material = Some((km_bytes, profile));
            }
        }

        // Return application data
        if let Some(data) = self.pending_application_data.pop_front() {
            if data.len() <= buf.len() {
                buf[..data.len()].copy_from_slice(&data);
                return DtlsOutput::ApplicationData(&buf[..data.len()]);
            } else {
                self.pending_application_data.push_front(data);
            }
        }

        // No output - return far future timeout
        DtlsOutput::Timeout(Instant::now() + Duration::from_secs(3600))
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        if let Some(timeout) = self.inner.poll_timeout(now) {
            self.next_timeout = Some(timeout);
        }
        Ok(())
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        // If handshake not complete, queue for later
        if !self.inner.is_connected() {
            self.queued_app_data.push_back(data.to_vec());
            return Ok(());
        }

        // Flush any queued data first
        self.flush_queued_app_data()?;

        // Now send current data
        if let Err(e) = self.inner.handle_input(data) {
            return Err(DtlsImplError::CryptoError(format!("DTLS error: {}", e)));
        }

        self.collect_output();
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.inner.is_active().unwrap_or(false)
    }
}

// ============================================================================
// DTLS Provider Implementation
// ============================================================================

pub(super) struct OsslDtlsProvider;

impl std::fmt::Debug for OsslDtlsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslDtlsProvider").finish()
    }
}

impl DtlsProvider for OsslDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        generate_certificate_impl().ok()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        _now: Instant,
        dtls_version: DtlsVersion,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        if dtls_version != DtlsVersion::Dtls12 {
            return Err(CryptoError::Other(
                "OpenSSL DTLS provider only supports DTLS 1.2. \
                 Use aws-lc-rs or rust-crypto backend for DTLS 1.3/Auto."
                    .to_string(),
            ));
        }
        Ok(Box::new(OsslDtlsInstance::new(cert)?))
    }
}

fn generate_certificate_impl() -> Result<DtlsCert, CryptoError> {
    // Generate EC key pair using P-256 curve
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // Build the X509 certificate
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?; // X509 v3

    // Generate random serial number
    let mut serial = BigNum::new()?;
    serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    builder.set_serial_number(serial.to_asn1_integer()?.as_ref())?;

    // Set validity period (1 year)
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Set subject name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", "WebRTC")?;
    let name = name_builder.build();
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;

    builder.set_pubkey(&pkey)?;

    // Add extensions
    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;

    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()?;
    builder.append_extension(key_usage)?;

    let ext_key_usage = ExtendedKeyUsage::new()
        .server_auth()
        .client_auth()
        .build()?;
    builder.append_extension(ext_key_usage)?;

    // Sign the certificate
    builder.sign(&pkey, MessageDigest::sha256())?;

    let cert = builder.build();

    // Convert to DER format
    let certificate = cert.to_der()?;
    let private_key = pkey.private_key_to_der()?;

    Ok(DtlsCert {
        certificate,
        private_key,
    })
}
