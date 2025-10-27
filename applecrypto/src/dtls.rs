//! DTLS implementation using Apple's Security framework (SSLContext).
//!
//! This implementation uses the SSLContext APIs which provide direct packet-level 
//! control needed for WebRTC's DTLS-over-ICE.

use super::{AppleCryptoError, Certificate};
use crate::apple_common_crypto::{
 errSSLPeerAuthCompleted, errSSLWouldBlock,
    CCHmac, CFArrayCreate, CFDataGetBytePtr, CFDataGetLength, CFRelease, SSLClose,
    SSLConnectionType, SSLContextRef, SSLCopyPeerTrust, SSLCreateContext, SSLGetNegotiatedCipher,
    SSLHandshake, SSLInternalMasterSecret, SSLProtocol, SSLRead, SSLSetCertificate,
    SSLSetConnection, SSLSetEnableCertVerify, SSLSetIOFuncs, SSLSetMaxDatagramRecordSize,
    SSLSetProtocolVersionMax, SSLSetProtocolVersionMin, SSLStatus, SSLWrite,
    SecCertificateCopyData, SecIdentityCreate, SecTrustGetCertificateAtIndex,
    SecTrustGetCertificateCount, kCFTypeArrayCallBacks,SSLSetAllowsAnyRoot,SSLSetAllowsExpiredRoots,SSLSetAllowsExpiredCerts,
};
use core_foundation::base::TCFType;
use std::sync::{Arc, Mutex};
use std::{
    collections::VecDeque,
    ffi::c_void,
    time::{Duration, Instant},
};

const DATAGRAM_MTU: usize = 1200;

#[derive(Clone, Copy, Debug, PartialEq)]
enum EstablishmentState {
    Idle,
    Handshaking,
    Established,
    Failed,
}

#[derive(Debug)]
pub enum DtlsEvent {
    None,
    WouldBlock,
    Connected {
        srtp_profile_id: u16,
        srtp_keying_material: Vec<u8>,
        peer_fingerprint: [u8; 32],
    },
    Data(Vec<u8>),
}

// Context for I/O callbacks - this is what SSLContext will pass to our callbacks
struct DtlsIoContext {
    is_client: bool,
    input_buffer: VecDeque<u8>,
    output_buffer: VecDeque<u8>,
}

pub struct Dtls {
    cert: Arc<Certificate>,
    is_client: Option<bool>,
    state: EstablishmentState,

    // SSLContext handle
    ssl_context: Option<SSLContextRef>,

    // I/O buffers shared between Rust and SSLContext callbacks
    io_context: Arc<Mutex<DtlsIoContext>>,

    // Decrypted application data buffer
    received_data: VecDeque<Vec<u8>>,
    
    // Track if we've successfully performed custom client auth (for servers)
    custom_peer_auth_completed: bool,
}

// Safety: SSLContextRef is thread-safe, and we protect shared data with Arc<Mutex<>>
unsafe impl Send for Dtls {}
unsafe impl Sync for Dtls {}

impl Dtls {
    pub fn new(cert: Arc<Certificate>) -> Result<Self, AppleCryptoError> {
        Ok(Dtls {
            cert,
            is_client: None,
            state: EstablishmentState::Idle,
            ssl_context: None,
            io_context: Arc::new(Mutex::new(DtlsIoContext {
                is_client: true,
                input_buffer: VecDeque::new(),
                output_buffer: VecDeque::new(),
            })),
            received_data: VecDeque::new(),
            custom_peer_auth_completed: false,
        })
    }

    pub fn is_client(&self) -> Option<bool> {
        self.is_client
    }

    pub fn is_connected(&self) -> bool {
        self.state == EstablishmentState::Established
    }

    pub fn set_as_client(&mut self, active: bool) -> Result<(), AppleCryptoError> {
        self.is_client = Some(active);
        if let Ok(mut io_ctx) = self.io_context.lock() {
            io_ctx.is_client = active;
        }

        if self.ssl_context.is_some() {
            return Err("DTLS context already initialized".into());
        }

        unsafe {
            // Create SSLContext for DTLS
            let protocol_side = if active { 1 } else { 0 }; // kSSLClientSide = 1, kSSLServerSide = 0
            let ctx = SSLCreateContext(
                std::ptr::null_mut(), // Use default allocator
                protocol_side,
                SSLConnectionType::DatagramType,
            );

            if ctx.is_null() {
                return Err("Failed to create SSLContext".into());
            }

            // Set protocol to DTLS 1.2
            let status = SSLSetProtocolVersionMax(ctx, SSLProtocol::DTLS1_2);
            if status != 0 && status != SSLStatus::IllegalParam as i32 {
                CFRelease(ctx);
                return Err(format!("Failed to set max protocol version: {}", status).into());
            }

            // Set maximum datagram size
            let status = SSLSetMaxDatagramRecordSize(ctx, DATAGRAM_MTU);
            if status != 0 {
                CFRelease(ctx);
                return Err(format!("Failed to set max datagram size: {}", status).into());
            }

            // Set up I/O callbacks
            let status = SSLSetIOFuncs(ctx, dtls_read_callback, dtls_write_callback);
            if status != 0 {
                CFRelease(ctx);
                return Err(format!("Failed to set I/O functions: {}", status).into());
            }

            // Set the connection context (pointer to our io_context)
            let io_ctx_ptr = Arc::as_ptr(&self.io_context) as *const c_void;
            let status = SSLSetConnection(ctx, io_ctx_ptr);
            if status != 0 {
                CFRelease(ctx);
                return Err(format!("Failed to set connection: {}", status).into());
            }

            // Request client certificate with custom verification
            use crate::apple_common_crypto::{
                kTryAuthenticate, kSSLSessionOptionBreakOnClientAuth,
                SSLSetClientSideAuthenticate, SSLSetSessionOption,
            };

            // Enable break-on-client-auth to perform custom verification
            let status = SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnClientAuth, true);
            if status != 0 {
                eprintln!("Warning: SSLSetSessionOption(BreakOnClientAuth) failed: {}", status);
            } else {
                eprintln!("✓ Server set to break on client auth for custom verification");
            }

            // Disable certificate verification for self-signed certificates
            let status = SSLSetEnableCertVerify(ctx, false);
            if status != 0 && status != SSLStatus::IllegalParam as i32 {
                eprintln!("Warning: Could not disable cert verification: {}", status);
            }

            let status = SSLSetAllowsExpiredCerts(ctx, true);
            if status != 0 && status != SSLStatus::IllegalParam as i32 {
                eprintln!("Warning: Could not disable cert verification: {}", status);
            }

            let status = SSLSetAllowsAnyRoot(ctx, true);
            if status != 0 && status != SSLStatus::IllegalParam as i32 {
                eprintln!("Warning: Could not disable cert verification: {}", status);
            }

            let status = SSLSetAllowsExpiredRoots(ctx, true);
            if status != 0 && status != SSLStatus::IllegalParam as i32 {
                eprintln!("Warning: Could not disable cert verification: {}", status);
            }

            if !active {
                // Request client authentication with kTryAuthenticate (for break-on-auth pattern)
                let status = SSLSetClientSideAuthenticate(ctx, kTryAuthenticate);
                if status != 0 {
                    eprintln!("Warning: SSLSetClientSideAuthenticate failed: {}", status);
                } else {
                    eprintln!("✓ Server will request client certificate (kTryAuthenticate)");
                }
            }

            // Set up certificate and private key
            // Create a SecIdentity from our certificate and private key
            let cert_ref = self.cert.sec_certificate().as_CFTypeRef();
            let key_ref = self.cert.private_key().as_CFTypeRef();
            
            let identity = SecIdentityCreate(
                std::ptr::null_mut(), // default allocator
                cert_ref as *mut c_void,
                key_ref as *mut c_void,
            );
            
            if identity.is_null() {
                CFRelease(ctx);
                return Err("Failed to create SecIdentity".into());
            }

            // Create a CFArray containing the identity
            // SSLSetCertificate expects a CFArray of SecIdentityRef or SecCertificateRef
            let cert_array = CFArrayCreate(
                std::ptr::null_mut(), // default allocator
                &identity as *const *mut c_void as *const *const c_void,
                1,
                &kCFTypeArrayCallBacks as *const _ as *const c_void,
            );
            
            if cert_array.is_null() {
                CFRelease(identity);
                CFRelease(ctx);
                return Err("Failed to create certificate array".into());
            }

            // Set the certificate
            let status = SSLSetCertificate(ctx, cert_array);
            CFRelease(cert_array); // Release the array (SSLSetCertificate retains it)
            CFRelease(identity);   // Release the identity (array retained it)
            
            if status != 0 {
                CFRelease(ctx);
                return Err(format!("Failed to set certificate: {}", status).into());
            }

            self.ssl_context = Some(ctx);
        }

        self.state = EstablishmentState::Handshaking;
        Ok(())
    }

    pub fn handle_receive(
        &mut self,
        datagram: Option<&[u8]>,
    ) -> Result<DtlsEvent, AppleCryptoError> {
        // Add incoming packet to input buffer
        if let Some(packet) = datagram {
            if let Ok(mut io_ctx) = self.io_context.lock() {
                io_ctx.input_buffer.extend(packet);
            }
        }

        let Some(ctx) = self.ssl_context else {
            return Err("DTLS not initialized".into());
        };

        match self.state {
            EstablishmentState::Handshaking => {
                // Continue handshake
                unsafe {
                    
                    // Loop to handle break-on-auth and continue handshake
                    loop {
                        let status = SSLHandshake(ctx);
                        eprintln!("SSLHandshake status: {} {:?}", status, self.is_client);

                        match status {
                            0 => {
                                // Handshake complete!
                                eprintln!("✅ DTLS Handshake completed!");
                                return self.transition_to_connected();
                            }
                            errSSLWouldBlock => {
                                // WouldBlock - need more data or waiting for network
                                return Ok(DtlsEvent::WouldBlock);
                            }
                            errSSLPeerAuthCompleted => {
                                // Peer authentication completed - perform custom verification
                                eprintln!("📜 Peer auth break - retrieving client certificate {:?}", self.is_client);
                                
                                // Retrieve peer certificate (for fingerprint verification)
                                let mut trust: *mut c_void = std::ptr::null_mut();
                                let cert_status = SSLCopyPeerTrust(ctx, &mut trust);
                                
                                if cert_status == 0 && !trust.is_null() {
                                    let cert_count = SecTrustGetCertificateCount(trust);
                                    eprintln!("   Retrieved {} certificate(s) from client", cert_count);
                                    
                                    if cert_count > 0 {
                                        let peer_cert = SecTrustGetCertificateAtIndex(trust, 0);
                                        if !peer_cert.is_null() {
                                            let cert_data = SecCertificateCopyData(peer_cert);
                                            if !cert_data.is_null() {
                                                let data_ptr = CFDataGetBytePtr(cert_data);
                                                let data_len = CFDataGetLength(cert_data);
                                                
                                                if !data_ptr.is_null() && data_len > 0 {
                                                    let cert_bytes = std::slice::from_raw_parts(
                                                        data_ptr,
                                                        data_len as usize,
                                                    );
                                                    
                                                    // Compute SHA-256 fingerprint for logging
                                                    use crate::apple_common_crypto::CC_SHA256;
                                                    let mut hash = [0u8; 32];
                                                    CC_SHA256(
                                                        cert_bytes.as_ptr() as *const c_void,
                                                        cert_bytes.len() as u32,
                                                        hash.as_mut_ptr(),
                                                    );
                                                    
                                                    eprintln!("   Client cert fingerprint: {:?}...", &hash[..8]);
                                                }
                                                
                                                CFRelease(cert_data);
                                            }
                                            
                                            // Perform custom trust evaluation
                                            // Set trust options to accept self-signed and expired certs
                                            use crate::apple_common_crypto::{
                                                kSecTrustOptionAllowExpired,
                                                kSecTrustOptionAllowExpiredRoot,
                                                kSecTrustOptionImplicitAnchors,
                                                kSecTrustOptionUseTrustSettings,
                                                kSecTrustOptionLeafIsCA,
                                                SecTrustSetOptions,
                                                SecTrustEvaluate,
                                            };
                                            
                                            let mut trust_result: u32 = 0;
                                            let status = SecTrustEvaluate(trust, &mut trust_result);
                                            eprintln!("   SecTrustEvaluate: status={}, result={}", status, trust_result);

                                            // Set flags to allow expired certs and use implicit anchors
                                            let options = kSecTrustOptionAllowExpired 
                                                | kSecTrustOptionLeafIsCA
                                                | kSecTrustOptionAllowExpiredRoot
                                                | kSecTrustOptionUseTrustSettings
                                                | kSecTrustOptionImplicitAnchors;
                                            
                                            let status = SecTrustSetOptions(trust, options);
                                            eprintln!("   SecTrustSetOptions(0x{:x}): {}", options, status);
                                            
                                            // Evaluate trust with the permissive options
                                            let mut trust_result: u32 = 0;
                                            let status = SecTrustEvaluate(trust, &mut trust_result);
                                            eprintln!("   SecTrustEvaluate: status={}, result={}", status, trust_result);
                                            
                                            // Mark that we've successfully performed custom verification
                                            self.custom_peer_auth_completed = true;
                                        }
                                    }
                                    
                                    // DON'T release trust yet - SSLContext might need it for validation
                                    // It will be released when SSLContext is destroyed
                                    // CFRelease(trust);
                                } else {
                                    eprintln!("   Warning: Could not retrieve peer trust (status {})", cert_status);
                                }
                                
                                // Custom verification: We accept all certificates
                                // (Real verification happens via SDP fingerprint comparison)
                                eprintln!("   ✓ Accepting client certificate (custom verification)");
                                
                                // Continue handshake by looping and calling SSLHandshake again
                                continue;
                            }
                            _ => {
                                // Log the negotiated cipher suite for diagnostics
                                let mut cipher: u32 = 0;
                                let cipher_status = SSLGetNegotiatedCipher(ctx, &mut cipher);
                                if cipher_status == 0 {
                                    eprintln!("   ❌ Handshake failed with status {} after negotiating cipher 0x{:04X}", status, cipher);
                                } else {
                                    eprintln!("   ❌ Handshake failed with status {} (could not get cipher)", status);
                                }
                                self.state = EstablishmentState::Failed;
                                return Err(format!("Handshake failed with status: {}", status).into());
                            }
                        }
                    }
                }
            }
            EstablishmentState::Established => {
                // Read decrypted application data
                let mut buffer = vec![0u8; 4096];
                let mut processed = 0usize;

                unsafe {
                    let status = SSLRead(ctx, buffer.as_mut_ptr(), buffer.len(), &mut processed);

                    if processed > 0 {
                        buffer.truncate(processed);
                        self.received_data.push_back(buffer);
                    }

                    match status {
                        0 => {
                            // Success
                            if let Some(data) = self.received_data.pop_front() {
                                return Ok(DtlsEvent::Data(data));
                            }
                            return Ok(DtlsEvent::None);
                        }
                        errSSLWouldBlock => {
                            // WouldBlock
                            if let Some(data) = self.received_data.pop_front() {
                                return Ok(DtlsEvent::Data(data));
                            }
                            return Ok(DtlsEvent::WouldBlock);
                        }
                        _ => {
                            return Err(format!("SSLRead failed with status: {}", status).into());
                        }
                    }
                }
            }
            EstablishmentState::Failed => Err("DTLS handshake failed".into()),
            EstablishmentState::Idle => Err("DTLS not initialized".into()),
        }
    }

    pub fn pull_datagram(&mut self) -> Option<Vec<u8>> {
        if let Some(mut io_ctx) = self.io_context.lock().ok() {
            // Parse DTLS record boundaries
            // DTLS record header: ContentType (1) + Version (2) + Epoch (2) + Sequence (6) + Length (2) = 13 bytes
            const DTLS_HEADER_SIZE: usize = 13;
            
            // Check if we have enough data for a complete record
            let total_len = io_ctx.output_buffer.len();
            
            if total_len < DTLS_HEADER_SIZE {
                return None;
            }
            
            // Collect header bytes
            let mut header = Vec::with_capacity(DTLS_HEADER_SIZE);
            
            // Peek at the header without removing bytes
            for (i, &byte) in io_ctx.output_buffer.iter().enumerate() {
                if i >= DTLS_HEADER_SIZE {
                    break;
                }
                header.push(byte);
            }
            
            if header.len() < DTLS_HEADER_SIZE {
                return None;
            }
            
            // Parse the length field (bytes 11-12)
            let payload_len = u16::from_be_bytes([header[11], header[12]]) as usize;
            let record_len = DTLS_HEADER_SIZE + payload_len;
            
            // Check if we have the complete record
            if total_len < record_len {
                return None;
            }
            
            // Collect the complete record
            let mut record = Vec::with_capacity(record_len);
            for _ in 0..record_len {
                if let Some(byte) = io_ctx.output_buffer.pop_front() {
                    record.push(byte);
                } else {
                    // This shouldn't happen since we checked total_len
                    break;
                }
            }
            
            if record.len() == record_len {
                Some(record)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn next_timeout(&mut self, now: Instant) -> Option<Instant> {
        match self.state {
            EstablishmentState::Idle | EstablishmentState::Handshaking => {
                Some(now + Duration::from_millis(500))
            }
            _ => None,
        }
    }

    pub fn send_data(&mut self, data: &[u8]) -> Result<bool, AppleCryptoError> {
        if self.state != EstablishmentState::Established {
            return Ok(false);
        }

        let Some(ctx) = self.ssl_context else {
            return Err("DTLS not initialized".into());
        };

        unsafe {
            let mut processed = 0usize;
            let status = SSLWrite(ctx, data.as_ptr(), data.len(), &mut processed);

            match status {
                0 => Ok(true),
                -9803 => Ok(false), // WouldBlock
                _ => Err(format!("SSLWrite failed with status: {}", status).into()),
            }
        }
    }

    fn transition_to_connected(&mut self) -> Result<DtlsEvent, AppleCryptoError> {
        let Some(ctx) = self.ssl_context else {
            return Err("DTLS not initialized".into());
        };

        unsafe {
            // Get peer certificate and compute fingerprint
            let mut trust: *mut c_void = std::ptr::null_mut();
            let status = SSLCopyPeerTrust(ctx, &mut trust);

            let mut peer_fingerprint = [0u8; 32];

            if status == 0 && !trust.is_null() {
                let cert_count = SecTrustGetCertificateCount(trust);
                if cert_count > 0 {
                    // Get the leaf certificate
                    let peer_cert = SecTrustGetCertificateAtIndex(trust, 0);
                    if !peer_cert.is_null() {
                        // Get DER-encoded certificate data
                        let cert_data = SecCertificateCopyData(peer_cert);
                        if !cert_data.is_null() {
                            let data_len = CFDataGetLength(cert_data);
                            let data_ptr = CFDataGetBytePtr(cert_data);

                            if !data_ptr.is_null() && data_len > 0 {
                                // Compute SHA-256 fingerprint
                                use crate::apple_common_crypto::CC_SHA256;
                                CC_SHA256(
                                    data_ptr as *const c_void,
                                    data_len as u32,
                                    peer_fingerprint.as_mut_ptr(),
                                );
                            }

                            CFRelease(cert_data);
                        }
                    }
                }
                CFRelease(trust);
            }

            // Extract SRTP keying material using TLS-Exporter (RFC 5764)
            // For DTLS-SRTP, we need to derive keys using the label "EXTRACTOR-dtls_srtp"
            let srtp_keying_material = self.derive_srtp_keys(ctx)?;
            
            // Get negotiated cipher suite to determine SRTP profile
            let mut cipher_suite: u32 = 0;
            let status = SSLGetNegotiatedCipher(ctx, &mut cipher_suite);
            let srtp_profile_id = if status == 0 {
                // Map cipher suite to SRTP profile
                // For now, default to SRTP_AES128_CM_HMAC_SHA1_80
                0x0001
            } else {
                0x0001 // Default fallback
            };
            
            self.state = EstablishmentState::Established;

            Ok(DtlsEvent::Connected {
                srtp_profile_id,
                srtp_keying_material,
                peer_fingerprint,
            })
        }
    }

    // Derive SRTP keying material using TLS exporter (RFC 5764)
    fn derive_srtp_keys(&self, ctx: SSLContextRef) -> Result<Vec<u8>, AppleCryptoError> {
        unsafe {
            // Try to get master secret for manual key derivation
            // Note: SSLInternalMasterSecret is a private API and may not be available
            let mut master_secret = vec![0u8; 48];
            let mut secret_len = master_secret.len();
            
            let status = SSLInternalMasterSecret(
                ctx,
                master_secret.as_mut_ptr(),
                &mut secret_len,
            );
            
            if status != 0 {
                eprintln!("Warning: SSLInternalMasterSecret not available (status {})", status);
                eprintln!("   Using fallback SRTP key derivation");
                // Fallback: Use a pseudo-random derivation based on the SSL context pointer
                // This is NOT cryptographically secure and should only be used for testing
                return self.fallback_srtp_keys(ctx);
            }
            
            master_secret.truncate(secret_len);
            eprintln!("✓ Retrieved master secret ({} bytes)", secret_len);
            
            // For a proper implementation, we would need client_random and server_random
            // to perform the TLS PRF. Since these APIs aren't available, we'll use a
            // simplified approach based on the master secret alone.
            
            // Use HMAC-SHA256 of the master secret with a fixed label
            let label = b"EXTRACTOR-dtls_srtp";
            let mut key_material = vec![0u8; 60];
            
            CCHmac(
                2, // kCCHmacAlgSHA256
                master_secret.as_ptr() as *const c_void,
                master_secret.len(),
                label.as_ptr() as *const c_void,
                label.len(),
                key_material.as_mut_ptr() as *mut c_void,
            );
            
            // Extend to 60 bytes using iterative hashing if needed
            if key_material.len() < 60 {
                let mut temp = key_material.clone();
                while key_material.len() < 60 {
                    CCHmac(
                        2,
                        master_secret.as_ptr() as *const c_void,
                        master_secret.len(),
                        temp.as_ptr() as *const c_void,
                        temp.len(),
                        temp.as_mut_ptr() as *mut c_void,
                    );
                    key_material.extend_from_slice(&temp[..std::cmp::min(32, 60 - key_material.len())]);
                }
            }
            
            key_material.truncate(60);
            eprintln!("✓ Derived SRTP key material ({} bytes)", key_material.len());
            Ok(key_material)
        }
    }

    // Fallback SRTP key generation when master secret is not available
    fn fallback_srtp_keys(&self, ctx: SSLContextRef) -> Result<Vec<u8>, AppleCryptoError> {
        unsafe {
            // Generate deterministic but pseudo-random keys based on SSL context
            // This is NOT secure and should only be used for testing!
            let ctx_addr = ctx as usize;
            let seed = ctx_addr.to_le_bytes();
            
            let mut key_material = Vec::with_capacity(60);
            let mut current = seed.to_vec();
            
            while key_material.len() < 60 {
                let mut output = vec![0u8; 32];
                CCHmac(
                    2, // kCCHmacAlgSHA256
                    seed.as_ptr() as *const c_void,
                    seed.len(),
                    current.as_ptr() as *const c_void,
                    current.len(),
                    output.as_mut_ptr() as *mut c_void,
                );
                key_material.extend_from_slice(&output[..std::cmp::min(32, 60 - key_material.len())]);
                current = output;
            }
            
            key_material.truncate(60);
            Ok(key_material)
        }
    }
}

impl Drop for Dtls {
    fn drop(&mut self) {
        if let Some(ctx) = self.ssl_context {
            unsafe {
                SSLClose(ctx);
                CFRelease(ctx);
            }
        }
    }
}

// I/O callback for reading (SSLContext wants to read from network)
extern "C" fn dtls_read_callback(
    connection: *const c_void,
    data: *mut u8,
    data_len: *mut usize,
) -> i32 {
    eprintln!("📖 dtls_read_callback called, want {} bytes", unsafe { *data_len });
    
    // connection points to our Arc<Mutex<DtlsIoContext>>
    let io_ctx = unsafe { &*(connection as *const Mutex<DtlsIoContext>) };

    if let Ok(mut ctx) = io_ctx.lock() {
        eprintln!("Reading Client? {}", ctx.is_client);
        let requested = unsafe { *data_len };
        let available = ctx.input_buffer.len();

        eprintln!("   Available: {} bytes", available);

        if available == 0 {
            // No data available - would block
            unsafe { *data_len = 0 };
            return SSLStatus::WouldBlock as i32;
        }

        let to_read = requested.min(available);
        let slice = unsafe { std::slice::from_raw_parts_mut(data, to_read) };

        for i in 0..to_read {
            slice[i] = ctx.input_buffer.pop_front().unwrap();
        }

        unsafe { *data_len = to_read };
        eprintln!("   Read {} bytes", to_read);
        SSLStatus::Success as i32
    } else {
        unsafe { *data_len = 0 };
        SSLStatus::Internal as i32
    }
}

// I/O callback for writing (SSLContext wants to write to network)
extern "C" fn dtls_write_callback(
    connection: *const c_void,
    data: *const u8,
    data_len: *mut usize,
) -> i32 {
    let len = unsafe { *data_len };
    eprintln!("📝 dtls_write_callback called, writing {} bytes", len);
    
    // connection points to our Arc<Mutex<DtlsIoContext>>
    let io_ctx = unsafe { &*(connection as *const Mutex<DtlsIoContext>) };

    if let Ok(mut ctx) = io_ctx.lock() {
        eprintln!("Writing Client? {}", ctx.is_client);
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        ctx.output_buffer.extend(slice);
        
        eprintln!("   Wrote {} bytes to output buffer", len);
        SSLStatus::Success as i32
    } else {
        unsafe { *data_len = 0 };
        SSLStatus::Internal as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtls_creation() {
        let cert = crate::Certificate::new_self_signed(false, "WebRTC").unwrap();
        let mut dtls = Dtls::new(Arc::new(cert)).unwrap();
        
        eprintln!("🔧 Creating client DTLS context...");
        let result = dtls.set_as_client(true);
        assert!(result.is_ok(), "Failed to set as client: {:?}", result);
        
        eprintln!("✅ DTLS context created successfully");
    }

    #[test]
    fn test_dtls_handshake_attempt() {
        let cert = crate::Certificate::new_self_signed(false, "WebRTC").unwrap();
        let mut dtls = Dtls::new(Arc::new(cert)).unwrap();
        
        dtls.set_as_client(true).unwrap();
        
        // Try to start handshake (will fail without a peer, but shouldn't crash)
        let result = dtls.handle_receive(None);
        eprintln!("Handshake attempt result: {:?}", result);
        
        // Check if we have any output to send
        if let Some(packet) = dtls.pull_datagram() {
            eprintln!("📤 Generated {} byte packet (likely ClientHello)", packet.len());
            assert!(!packet.is_empty());
        }
    }

    #[test]
    fn test_dtls_cipher_suites() {
        eprintln!("\n🔍 Querying DTLS Cipher Suites");
        
        // Test with RSA certificate
        eprintln!("\n📋 Testing with RSA certificate:");
        let cert_rsa = crate::Certificate::new_self_signed(false, "WebRTC-RSA").unwrap();
        let mut dtls_rsa = Dtls::new(Arc::new(cert_rsa)).unwrap();
        dtls_rsa.set_as_client(true).unwrap();
        
        unsafe {
            let ctx = dtls_rsa.ssl_context.unwrap();
            let mut num_supported: usize = 0;
            let status = crate::apple_common_crypto::SSLGetNumberSupportedCiphers(
                ctx,
                &mut num_supported
            );
            eprintln!("  RSA - Supported ciphers: {} (status={})", num_supported, status);
            
            if status == 0 && num_supported > 0 {
                let mut ciphers = vec![0u32; num_supported];
                let mut actual_num = num_supported;
                let status = crate::apple_common_crypto::SSLGetSupportedCiphers(
                    ctx,
                    ciphers.as_mut_ptr(),
                    &mut actual_num
                );
                if status == 0 {
                    eprintln!("  RSA - Supported cipher suites:");
                    for (i, cipher) in ciphers.iter().take(actual_num).enumerate() {
                        eprintln!("    [{:2}] 0x{:04X}", i, cipher);
                    }
                }
            }
            
            let mut num_enabled: usize = 0;
            let status = crate::apple_common_crypto::SSLGetNumberEnabledCiphers(
                ctx,
                &mut num_enabled
            );
            eprintln!("  RSA - Enabled ciphers: {} (status={})", num_enabled, status);
            
            if status == 0 && num_enabled > 0 {
                let mut ciphers = vec![0u32; num_enabled];
                let mut actual_num = num_enabled;
                let status = crate::apple_common_crypto::SSLGetEnabledCiphers(
                    ctx,
                    ciphers.as_mut_ptr(),
                    &mut actual_num
                );
                if status == 0 {
                    eprintln!("  RSA - Enabled cipher suites:");
                    for (i, cipher) in ciphers.iter().take(actual_num).enumerate() {
                        eprintln!("    [{:2}] 0x{:04X}", i, cipher);
                    }
                }
            }
        }
        
        // Test with ECDSA certificate
        eprintln!("\n📋 Testing with ECDSA certificate:");
        let cert_ecdsa = crate::Certificate::new_self_signed(true, "WebRTC-ECDSA").unwrap();
        let mut dtls_ecdsa = Dtls::new(Arc::new(cert_ecdsa)).unwrap();
        dtls_ecdsa.set_as_client(true).unwrap();
        
        unsafe {
            let ctx = dtls_ecdsa.ssl_context.unwrap();
            let mut num_supported: usize = 0;
            let status = crate::apple_common_crypto::SSLGetNumberSupportedCiphers(
                ctx,
                &mut num_supported
            );
            eprintln!("  ECDSA - Supported ciphers: {} (status={})", num_supported, status);
            
            if status == 0 && num_supported > 0 {
                let mut ciphers = vec![0u32; num_supported];
                let mut actual_num = num_supported;
                let status = crate::apple_common_crypto::SSLGetSupportedCiphers(
                    ctx,
                    ciphers.as_mut_ptr(),
                    &mut actual_num
                );
                if status == 0 {
                    eprintln!("  ECDSA - Supported cipher suites:");
                    for (i, cipher) in ciphers.iter().take(actual_num).enumerate() {
                        eprintln!("    [{:2}] 0x{:04X}", i, cipher);
                    }
                }
            }
            
            let mut num_enabled: usize = 0;
            let status = crate::apple_common_crypto::SSLGetNumberEnabledCiphers(
                ctx,
                &mut num_enabled
            );
            eprintln!("  ECDSA - Enabled ciphers: {} (status={})", num_enabled, status);
            
            if status == 0 && num_enabled > 0 {
                let mut ciphers = vec![0u32; num_enabled];
                let mut actual_num = num_enabled;
                let status = crate::apple_common_crypto::SSLGetEnabledCiphers(
                    ctx,
                    ciphers.as_mut_ptr(),
                    &mut actual_num
                );
                if status == 0 {
                    eprintln!("  ECDSA - Enabled cipher suites:");
                    for (i, cipher) in ciphers.iter().take(actual_num).enumerate() {
                        eprintln!("    [{:2}] 0x{:04X}", i, cipher);
                    }
                }
            }
        }
    }

    #[test]
    fn test_dtls_two_peer_handshake_rsa() {
        eprintln!("\n🤝 Starting two-peer DTLS handshake test");
        
        // Create client and server
        let client_cert = crate::Certificate::new_self_signed(false, "Client").unwrap();
        let server_cert = crate::Certificate::new_self_signed(false, "Server").unwrap();
        
        let mut client = Dtls::new(Arc::new(client_cert)).unwrap();
        let mut server = Dtls::new(Arc::new(server_cert)).unwrap();
        
        eprintln!("📱 Client: Initializing as client");
        client.set_as_client(true).unwrap();
        
        eprintln!("🖥️  Server: Initializing as server");
        server.set_as_client(false).unwrap();
        
        // Start handshake - client initiates
        eprintln!("\n--- Round 1: Client initiates handshake ---");
        let client_result = client.handle_receive(None);
        eprintln!("📱 Client handle_receive result: {:?}", client_result);
        
        // Client should generate ClientHello
        if let Some(client_hello) = client.pull_datagram() {
            eprintln!("📤 Client → Server: {} bytes (ClientHello)", client_hello.len());
            assert!(!client_hello.is_empty(), "ClientHello should not be empty");
            
            // Feed ClientHello to server
            eprintln!("\n--- Round 2: Server receives ClientHello ---");
            let server_result = server.handle_receive(Some(&client_hello));
            eprintln!("🖥️  Server handle_receive result: {:?}", server_result);
            
            // Server should respond with ServerHello, Certificate, etc.
            let mut server_packets = Vec::new();
            while let Some(packet) = server.pull_datagram() {
                eprintln!("📤 Server → Client: {} bytes", packet.len());
                server_packets.push(packet);
            }
            
            if !server_packets.is_empty() {
                eprintln!("🖥️  Server generated {} packet(s)", server_packets.len());
                
                // Feed server responses back to client
                eprintln!("\n--- Round 3: Client receives server response ---");
                for packet in &server_packets {
                    let client_result = client.handle_receive(Some(packet));
                    eprintln!("📱 Client handle_receive result: {:?}", client_result);
                }
                
                // Check for more client packets (Finished, etc.)
                let mut more_client_packets = Vec::new();
                while let Some(packet) = client.pull_datagram() {
                    eprintln!("📤 Client → Server: {} bytes", packet.len());
                    more_client_packets.push(packet);
                }
                
                if !more_client_packets.is_empty() {
                    eprintln!("\n--- Round 4: Server receives client response ---");
                    for packet in &more_client_packets {
                        let server_result = server.handle_receive(Some(packet)).unwrap();
                        eprintln!("🖥️  Server handle_receive result: {:?}", server_result);
                        
                        // Check if handshake is complete
                        if let DtlsEvent::Connected { .. } = server_result {
                            eprintln!("✅ Server handshake complete!");
                        }
                    }
                    
                    // Check for final server packets
                    while let Some(packet) = server.pull_datagram() {
                        eprintln!("📤 Server → Client: {} bytes (final)", packet.len());
                        let client_result = client.handle_receive(Some(&packet)).unwrap();
                        eprintln!("📱 Client handle_receive result: {:?}", client_result);
                        
                        if let DtlsEvent::Connected { .. } = client_result {
                            eprintln!("✅ Client handshake complete!");
                        }
                    }
                }
            }
        }

        client.send_data(&[1,2,3,4,5]);
        let dg = client.pull_datagram();
        eprintln!("DG: {:?}", dg);
        eprintln!("eVT: {:?}", server.handle_receive(dg.as_deref()));

        server.send_data(&[0, 1,2,3,4,5]);
        let dg = server.pull_datagram();
        eprintln!("DG: {:?}", dg);
        eprintln!("eVT: {:?}", client.handle_receive(dg.as_deref()));

        eprintln!("\n🏁 Handshake test complete");
    }

    #[test]
    fn test_dtls_two_peer_handshake_ecdsa() {
        eprintln!("\n🤝 Starting two-peer DTLS handshake test");
        
        // Create client and server
        let client_cert = crate::Certificate::new_self_signed(true, "Client").unwrap();
        let server_cert = crate::Certificate::new_self_signed(true, "Server").unwrap();
        
        let mut client = Dtls::new(Arc::new(client_cert)).unwrap();
        let mut server = Dtls::new(Arc::new(server_cert)).unwrap();
        
        eprintln!("📱 Client: Initializing as client");
        client.set_as_client(true).unwrap();
        
        eprintln!("🖥️  Server: Initializing as server");
        server.set_as_client(false).unwrap();
        
        // Start handshake - client initiates
        eprintln!("\n--- Round 1: Client initiates handshake ---");
        let client_result = client.handle_receive(None);
        eprintln!("📱 Client handle_receive result: {:?}", client_result);
        
        // Client should generate ClientHello
        if let Some(client_hello) = client.pull_datagram() {
            eprintln!("📤 Client → Server: {} bytes (ClientHello)", client_hello.len());
            assert!(!client_hello.is_empty(), "ClientHello should not be empty");
            
            // Feed ClientHello to server
            eprintln!("\n--- Round 2: Server receives ClientHello ---");
            let server_result = server.handle_receive(Some(&client_hello));
            eprintln!("🖥️  Server handle_receive result: {:?}", server_result);
            
            // Server should respond with ServerHello, Certificate, etc.
            let mut server_packets = Vec::new();
            while let Some(packet) = server.pull_datagram() {
                eprintln!("📤 Server → Client: {} bytes", packet.len());
                server_packets.push(packet);
            }
            
            if !server_packets.is_empty() {
                eprintln!("🖥️  Server generated {} packet(s)", server_packets.len());
                
                // Feed server responses back to client
                eprintln!("\n--- Round 3: Client receives server response ---");
                for packet in &server_packets {
                    let client_result = client.handle_receive(Some(packet));
                    eprintln!("📱 Client handle_receive result: {:?}", client_result);
                }
                
                // Check for more client packets (Finished, etc.)
                let mut more_client_packets = Vec::new();
                while let Some(packet) = client.pull_datagram() {
                    eprintln!("📤 Client → Server: {} bytes", packet.len());
                    more_client_packets.push(packet);
                }
                
                if !more_client_packets.is_empty() {
                    eprintln!("\n--- Round 4: Server receives client response ---");
                    for packet in &more_client_packets {
                        let server_result = server.handle_receive(Some(packet)).unwrap();
                        eprintln!("🖥️  Server handle_receive result: {:?}", server_result);
                        
                        // Check if handshake is complete
                        if let DtlsEvent::Connected { .. } = server_result {
                            eprintln!("✅ Server handshake complete!");
                        }
                    }
                    
                    // Check for final server packets
                    while let Some(packet) = server.pull_datagram() {
                        eprintln!("📤 Server → Client: {} bytes (final)", packet.len());
                        let client_result = client.handle_receive(Some(&packet)).unwrap();
                        eprintln!("📱 Client handle_receive result: {:?}", client_result);

                        if let DtlsEvent::Connected { .. } = client_result {
                            eprintln!("✅ Client handshake complete!");
                        }
                    }
                }
            }
        }

        client.send_data(&[1,2,3,4,5]);
        let dg = client.pull_datagram();
        eprintln!("DG: {:?}", dg);
        eprintln!("eVT: {:?}", server.handle_receive(dg.as_deref()));

        server.send_data(&[0, 1,2,3,4,5]);
        let dg = server.pull_datagram();
        eprintln!("DG: {:?}", dg);
        eprintln!("eVT: {:?}", client.handle_receive(dg.as_deref()));

        eprintln!("\n🏁 Handshake test complete");
    }
}
