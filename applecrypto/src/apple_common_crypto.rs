/// Declares constants and function defintions that comes from the System for
/// Apple's CommonCrypto.
use std::ffi::c_void;

// CommonCrypto constants
pub const K_CC_HMAC_ALG_SHA1: u32 = 0;

pub const K_CC_ALGORITHM_AES: u32 = 0;
pub const K_CC_OPTION_ECB_MODE: u32 = 1;
pub const K_CC_MODE_GCM: u32 = 11;
pub const K_CC_ENCRYPT: u32 = 0;
pub const K_CC_DECRYPT: u32 = 1;

// SHA constants
pub const CC_SHA256_DIGEST_LENGTH: usize = 32;

// AES key sizes
pub const K_CC_AES_KEY_SIZE_128: usize = 16;
pub const K_CC_AES_KEY_SIZE_192: usize = 24;
pub const K_CC_AES_KEY_SIZE_256: usize = 32;

// Network framework types and constants
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum nw_connection_state_t {
    Invalid = 0,
    Waiting = 1,
    Preparing = 2,
    Ready = 3,
    Failed = 4,
    Cancelled = 5,
}

// Network framework bindings
#[link(name = "Network", kind = "framework")]
extern "C" {
    pub fn nw_connection_set_state_changed_handler(
        connection: *mut c_void,
        handler: *const c_void, // Block, not function pointer
    );
    pub fn nw_parameters_create_secure_udp(
        configure_tls: *const c_void,
        configure_udp: *const c_void,
    ) -> *mut c_void;
    pub fn nw_parameters_copy_default_protocol_stack(params: *mut c_void) -> *mut c_void;
    pub fn nw_protocol_stack_copy_internet_protocol(stack: *mut c_void) -> *mut c_void;
    pub fn sec_protocol_options_set_min_tls_protocol_version(options: *mut c_void, version: u16);
    pub fn sec_protocol_options_set_max_tls_protocol_version(options: *mut c_void, version: u16);
    pub fn sec_protocol_options_add_tls_application_protocol(
        options: *mut c_void,
        application_protocol: *const u8,
        application_protocol_len: usize,
    );
    pub fn nw_endpoint_create_host(
        hostname: *const std::ffi::c_char,
        port: *const std::ffi::c_char,
    ) -> *mut c_void;
    pub fn nw_connection_create(endpoint: *mut c_void, parameters: *mut c_void) -> *mut c_void;
    pub fn nw_connection_start(connection: *mut c_void);
    pub fn nw_connection_set_queue(connection: *mut c_void, queue: *mut c_void);
    pub fn nw_connection_send(
        connection: *mut c_void,
        content: *const c_void,
        content_len: usize,
        context: *mut c_void,
        is_complete: bool,
        completion: extern "C" fn(*mut c_void),
    );
    pub fn nw_connection_receive(
        connection: *mut c_void,
        minimum_incomplete_length: u32,
        maximum_length: u32,
        completion: *const c_void,
    );
    pub fn nw_connection_cancel(connection: *mut c_void);

    // Custom protocol framer APIs
    pub fn nw_framer_protocol_create_message(framer: *mut c_void) -> *mut c_void;
    pub fn nw_framer_create_definition(
        identifier: *const std::ffi::c_char,
        flags: u32,
        start_handler: *const c_void,
    ) -> *mut c_void;
    pub fn nw_framer_create_options(definition: *mut c_void) -> *mut c_void;
    pub fn nw_protocol_stack_prepend_application_protocol(
        stack: *mut c_void,
        protocol: *mut c_void,
    );
    pub fn nw_tls_create_options() -> *mut c_void;
    pub fn nw_udp_create_options() -> *mut c_void;
    pub fn nw_protocol_stack_set_transport_protocol(stack: *mut c_void, protocol: *mut c_void);
    pub fn nw_framer_set_input_handler(framer: *mut c_void, input_handler: *const c_void);
    pub fn nw_framer_set_output_handler(framer: *mut c_void, output_handler: *const c_void);
    pub fn nw_framer_parse_input(
        framer: *mut c_void,
        minimum_incomplete_length: usize,
        maximum_length: usize,
        temp_buffer: *mut u8,
        parse: *const c_void,
    ) -> usize;
    pub fn nw_framer_deliver_input_no_copy(
        framer: *mut c_void,
        length: usize,
        message: *mut c_void,
        is_complete: bool,
    ) -> bool;
    pub fn nw_framer_write_output(
        framer: *mut c_void,
        output_buffer: *const u8,
        output_length: usize,
    );
    pub fn nw_framer_write_output_data(framer: *mut c_void, output: *const c_void);

    // Content context for messages
    pub fn nw_content_context_create(context_identifier: *const std::ffi::c_char) -> *mut c_void;
    pub fn nw_content_context_get_default_message() -> *mut c_void;

    // Message content access
    pub fn nw_framer_message_copy_object_value(
        message: *mut c_void,
        key: *const std::ffi::c_char,
    ) -> *mut c_void;
    pub fn nw_framer_message_access_value(
        message: *mut c_void,
        key: *const std::ffi::c_char,
        accessor_block: *const c_void,
    ) -> bool;

    // Protocol metadata access
    pub fn nw_protocol_metadata_copy_definition(metadata: *mut c_void) -> *mut c_void;
    pub fn nw_framer_copy_output_message(framer: *mut c_void) -> *mut c_void;
    pub fn nw_framer_schedule_wakeup(framer: *mut c_void, milliseconds: u64);

    // Connection metadata access
    pub fn nw_connection_copy_protocol_metadata(
        connection: *mut c_void,
        protocol_definition: *mut c_void,
    ) -> *mut c_void;
    pub fn nw_protocol_copy_tls_definition() -> *mut c_void;

    // Security protocol metadata access
    pub fn sec_protocol_metadata_get_negotiated_protocol(metadata: *mut c_void) -> *const u8;
    pub fn sec_protocol_metadata_get_negotiated_protocol_version(metadata: *mut c_void) -> u16;
    pub fn sec_protocol_metadata_copy_peer_public_key(metadata: *mut c_void) -> *mut c_void;
    pub fn sec_protocol_metadata_get_peer_certificate_chain(metadata: *mut c_void) -> *mut c_void; // Returns a SecTrustRef

    // SRTP keying material export (using TLS Exporter from RFC 5705)
    pub fn sec_protocol_metadata_copy_exporter(
        metadata: *mut c_void,
        label: *const u8,
        label_len: usize,
        context: *const u8,
        context_len: usize,
        exporter_len: usize,
    ) -> *mut c_void; // Returns dispatch_data_t

    // Parameters and protocol stack manipulation
    pub fn nw_parameters_create() -> *mut c_void;
    pub fn nw_parameters_set_local_endpoint(params: *mut c_void, local_endpoint: *mut c_void);
    pub fn nw_parameters_copy_protocol_stack(params: *mut c_void) -> *mut c_void;
    pub fn nw_protocol_stack_clear_application_protocols(stack: *mut c_void);

    // dispatch_data functions for working with Network framework data
    pub fn dispatch_data_create(
        buffer: *const u8,
        size: usize,
        queue: *mut c_void,
        destructor: *const c_void,
    ) -> *mut c_void;
    pub fn dispatch_data_get_size(data: *mut c_void) -> usize;
    pub fn dispatch_data_create_map(
        data: *mut c_void,
        buffer_ptr: *mut *const u8,
        size_ptr: *mut usize,
    ) -> *mut c_void;
    pub fn dispatch_release(object: *mut c_void);
}

// Dispatch (Grand Central Dispatch) bindings
// These functions are part of libSystem on macOS/iOS
// #[cfg_attr(target_os = "macos", link(name = "System", kind = "dylib"))]
// #[cfg_attr(target_os = "ios", link(name = "System", kind = "dylib"))]
// extern "C" {
//     pub fn dispatch_get_main_queue() -> *mut c_void;
//     pub fn dispatch_queue_create(label: *const std::ffi::c_char, attr: *mut c_void) -> *mut c_void;
//     pub fn dispatch_release(object: *mut c_void);
// }

// CommonCrypto function bindings
#[link(name = "System")]
extern "C" {
    pub fn CCHmac(
        algorithm: u32,
        key: *const c_void,
        key_length: usize,
        data: *const c_void,
        data_length: usize,
        mac_out: *mut c_void,
    );

    pub fn CC_SHA256(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;

    pub fn CCCryptorCreate(
        op: u32,
        alg: u32,
        options: u32,
        key: *const u8,
        key_length: usize,
        iv: *const u8,
        cryptor_ref: *mut *mut c_void,
    ) -> i32;

    pub fn CCCryptorCreateWithMode(
        op: u32,
        mode: u32,
        alg: u32,
        padding: u32,
        iv: *const u8,
        key: *const u8,
        key_length: usize,
        tweak: *const u8,
        tweak_length: usize,
        num_rounds: i32,
        mode_options: u32,
        cryptor_ref: *mut *mut c_void,
    ) -> i32;

    pub fn CCCryptorUpdate(
        cryptor_ref: *mut c_void,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
        data_out_available: usize,
        data_out_moved: *mut usize,
    ) -> i32;

    pub fn CCCryptorFinal(
        cryptor_ref: *mut c_void,
        data_out: *mut u8,
        data_out_available: usize,
        data_out_moved: *mut usize,
    ) -> i32;

    pub fn CCCryptorRelease(cryptor_ref: *mut c_void) -> i32;

    pub fn CCCryptorGCMAddIV(cryptor_ref: *mut c_void, iv: *const u8, iv_len: usize) -> i32;

    pub fn CCCryptorGCMAddAAD(cryptor_ref: *mut c_void, aad: *const u8, aad_len: usize) -> i32;

    pub fn CCCryptorGCMEncrypt(
        cryptor_ref: *mut c_void,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
    ) -> i32;

    pub fn CCCryptorGCMDecrypt(
        cryptor_ref: *mut c_void,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
    ) -> i32;

    pub fn CCCryptorGCMFinal(cryptor_ref: *mut c_void, tag: *mut u8, tag_len: *mut usize) -> i32;
}

// SSLContext error codes
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SSLStatus {
    Success = 0,
    ProtocolError = -9800,
    NegotiationError = -9801,
    FatalAlert = -9802,
    WouldBlock = -9803,
    SessionNotFound = -9804,
    ClosedGraceful = -9805,
    ClosedAbort = -9806,
    XCertChainInvalid = -9807,
    BadCert = -9808,
    Crypto = -9809,
    Internal = -9810,
    ModuleAttach = -9811,
    UnknownRootCert = -9812,
    NoRootCert = -9813,
    CertExpired = -9814,
    CertNotYetValid = -9815,
    ClosedNoNotify = -9816,
    BufferOverflow = -9817,
    BadCipherSuite = -9818,
    PeerUnexpectedMsg = -9819,
    PeerBadRecordMac = -9820,
    PeerDecryptionFail = -9821,
    PeerRecordOverflow = -9822,
    PeerDecompressFail = -9823,
    PeerHandshakeFail = -9824,
    PeerBadCert = -9825,
    PeerUnsupportedCert = -9826,
    PeerCertRevoked = -9827,
    PeerCertExpired = -9828,
    PeerCertUnknown = -9829,
    IllegalParam = -9830,
    PeerUnknownCA = -9831,
    PeerAccessDenied = -9832,
    PeerDecodeError = -9833,
    PeerDecryptError = -9834,
    PeerExportRestriction = -9835,
    PeerProtocolVersion = -9836,
    PeerInsufficientSecurity = -9837,
    PeerInternalError = -9838,
    PeerUserCancelled = -9839,
    PeerNoRenegotiation = -9840,
    HostNameMismatch = -9843,
    ConnectionRefused = -9844,
    DecryptionFail = -9845,
    BadRecordMac = -9846,
    RecordOverflow = -9847,
    BadConfiguration = -9848,
    UnexpectedRecord = -9849,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum SSLProtocol {
    Unknown = 0,
    TLS1 = 4,      // kTLSProtocol1
    TLS1_1 = 7,    // kTLSProtocol11
    TLS1_2 = 8,    // kTLSProtocol12
    TLS1_3 = 10,   // kTLSProtocol13
    DTLS1 = 9,     // kDTLSProtocol1 (DTLS 1.0)
    DTLS1_2 = 11,  // kDTLSProtocol12 (DTLS 1.2)
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum SSLConnectionType {
    StreamType = 0,
    DatagramType = 1,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum SSLSessionState {
    Idle = 0,
    Handshake = 1,
    Connected = 2,
    Closed = 3,
    Aborted = 4,
}

// Session options
pub const kSSLSessionOptionBreakOnServerAuth: u32 = 0;
pub const kSSLSessionOptionBreakOnCertRequested: u32 = 1;
pub const kSSLSessionOptionBreakOnClientAuth: u32 = 2;

// Client authentication modes
pub const kNeverAuthenticate: u32 = 0;
pub const kAlwaysAuthenticate: u32 = 1;
pub const kTryAuthenticate: u32 = 2;

// SSLHandshake return codes for break-on-auth
pub const errSSLPeerAuthCompleted: i32 = -9841;
pub const errSSLWouldBlock: i32 = -9803;

// SecTrustOptionFlags
pub const kSecTrustOptionAllowExpired: u32 = 0x00000001;
pub const kSecTrustOptionLeafIsCA: u32 = 0x00000002;
pub const kSecTrustOptionFetchIssuerFromNet: u32 = 0x00000004;
pub const kSecTrustOptionAllowExpiredRoot: u32 = 0x00000008;
pub const kSecTrustOptionRequireRevPerCert: u32 = 0x00000010;
pub const kSecTrustOptionUseTrustSettings: u32 = 0x00000020;
pub const kSecTrustOptionImplicitAnchors: u32 = 0x00000040;

// Opaque type for SSLContext
pub type SSLContextRef = *mut c_void;

// Security framework bindings for certificate handling and DTLS
#[link(name = "Security", kind = "framework")]
extern "C" {
    // SSLContext creation and management
    pub fn SSLCreateContext(
        alloc: *mut c_void, // CFAllocatorRef, use NULL for default
        protocolSide: u32,  // kSSLServerSide (0) or kSSLClientSide (1)
        connectionType: SSLConnectionType,
    ) -> SSLContextRef;
    
    pub fn SSLSetConnection(ctx: SSLContextRef, connection: *const c_void) -> i32; // OSStatus
    pub fn SSLGetConnection(ctx: SSLContextRef, connection: *mut *const c_void) -> i32;
    
    // Protocol version
    pub fn SSLSetProtocolVersionMin(ctx: SSLContextRef, minVersion: SSLProtocol) -> i32;
    pub fn SSLSetProtocolVersionMax(ctx: SSLContextRef, maxVersion: SSLProtocol) -> i32;
    
    // Certificate configuration
    pub fn SSLSetCertificate(ctx: SSLContextRef, certRefs: *mut c_void) -> i32; // CFArrayRef of SecCertificateRef
    pub fn SSLSetPeerID(ctx: SSLContextRef, peerID: *const u8, peerIDLen: usize) -> i32;
    pub fn SSLSetSessionOption(ctx: SSLContextRef, option: u32, value: bool) -> i32;
    pub fn SSLSetEnableCertVerify(ctx: SSLContextRef, enableVerify: bool) -> i32;
    pub fn SSLSetClientSideAuthenticate(ctx: SSLContextRef, auth: u32) -> i32;

    // Certificate validation options
    pub fn SSLSetAllowsAnyRoot(ctx: SSLContextRef, allowsAnyRoot: bool) -> i32;
    pub fn SSLSetAllowsExpiredRoots(ctx: SSLContextRef, allowsExpiredRoots: bool) -> i32;
    pub fn SSLSetAllowsExpiredCerts(ctx: SSLContextRef, allowsExpiredCerts: bool) -> i32;
    
    // I/O callbacks (for packet-based DTLS)
    pub fn SSLSetIOFuncs(
        ctx: SSLContextRef,
        readFunc: extern "C" fn(*const c_void, *mut u8, *mut usize) -> i32,
        writeFunc: extern "C" fn(*const c_void, *const u8, *mut usize) -> i32,
    ) -> i32;
    
    // Handshake and I/O
    pub fn SSLHandshake(ctx: SSLContextRef) -> i32; // Returns SSLStatus
    pub fn SSLRead(ctx: SSLContextRef, data: *mut u8, dataLength: usize, processed: *mut usize) -> i32;
    pub fn SSLWrite(ctx: SSLContextRef, data: *const u8, dataLength: usize, processed: *mut usize) -> i32;
    
    // Session state
    pub fn SSLGetSessionState(ctx: SSLContextRef, state: *mut SSLSessionState) -> i32;
    pub fn SSLClose(ctx: SSLContextRef) -> i32;
    
    // DTLS-specific
    pub fn SSLSetDatagramHelloCookie(ctx: SSLContextRef, cookie: *const u8, cookieLen: usize) -> i32;
    pub fn SSLGetDatagramWriteSize(ctx: SSLContextRef, bufSize: *mut usize) -> i32;
    pub fn SSLSetMaxDatagramRecordSize(ctx: SSLContextRef, maxSize: usize) -> i32;
    pub fn SSLGetMaxDatagramRecordSize(ctx: SSLContextRef, maxSize: *mut usize) -> i32;
    
    // Get negotiated cipher and protocol
    pub fn SSLGetNegotiatedCipher(ctx: SSLContextRef, cipherSuite: *mut u32) -> i32;
    pub fn SSLGetNegotiatedProtocolVersion(ctx: SSLContextRef, protocol: *mut SSLProtocol) -> i32;
    
    // Cipher suite management
    pub fn SSLGetNumberSupportedCiphers(ctx: SSLContextRef, numCiphers: *mut usize) -> i32;
    pub fn SSLGetSupportedCiphers(ctx: SSLContextRef, ciphers: *mut u32, numCiphers: *mut usize) -> i32;
    pub fn SSLGetNumberEnabledCiphers(ctx: SSLContextRef, numCiphers: *mut usize) -> i32;
    pub fn SSLGetEnabledCiphers(ctx: SSLContextRef, ciphers: *mut u32, numCiphers: *mut usize) -> i32;
    pub fn SSLSetEnabledCiphers(ctx: SSLContextRef, ciphers: *const u32, numCiphers: usize) -> i32;
    
    // Peer certificate chain
    pub fn SSLCopyPeerTrust(ctx: SSLContextRef, trust: *mut *mut c_void) -> i32; // Returns SecTrustRef
    
    // SRTP key material export (DTLS-SRTP RFC 5764)
    // Note: SSLContext doesn't have a direct TLS exporter API, so we'll need to use
    // the internal master secret and derive SRTP keys manually
    pub fn SSLInternalMasterSecret(
        ctx: SSLContextRef,
        secret: *mut u8,
        secretLen: *mut usize,
    ) -> i32;

    // SecTrust functions
    pub fn SecTrustGetCertificateCount(trust: *mut c_void) -> isize;
    pub fn SecTrustGetCertificateAtIndex(trust: *mut c_void, index: isize) -> *mut c_void;
    pub fn SecTrustSetAnchorCertificates(trust: *mut c_void, anchorCertificates: *mut c_void) -> i32;
    pub fn SecTrustSetAnchorCertificatesOnly(trust: *mut c_void, anchorCertificatesOnly: bool) -> i32;
    pub fn SecTrustSetOptions(trust: *mut c_void, options: u32) -> i32;
    pub fn SecTrustEvaluate(trust: *mut c_void, result: *mut u32) -> i32;

    // SecCertificate functions
    pub fn SecCertificateCopyData(certificate: *mut c_void) -> *mut c_void; // Returns CFDataRef

    // SecIdentity functions (certificate + private key)
    pub fn SecIdentityCreate(
        allocator: *mut c_void,
        certificate: *mut c_void,
        privateKey: *mut c_void,
    ) -> *mut c_void; // Returns SecIdentityRef

    // CoreFoundation functions (needed for working with CFDataRef)
    pub fn CFDataGetLength(data: *mut c_void) -> isize;
    pub fn CFDataGetBytePtr(data: *mut c_void) -> *const u8;
    pub fn CFRelease(cf: *mut c_void);
    pub fn CFArrayCreate(
        allocator: *mut c_void,
        values: *const *const c_void,
        numValues: isize,
        callbacks: *const c_void,
    ) -> *mut c_void;
}

// Constant for kCFTypeArrayCallBacks
#[repr(C)]
pub struct CFArrayCallBacks {
    version: isize,
    retain: Option<extern "C" fn(*const c_void, *const c_void) -> *const c_void>,
    release: Option<extern "C" fn(*const c_void, *const c_void)>,
    copy_description: Option<extern "C" fn(*const c_void) -> *const c_void>,
    equal: Option<extern "C" fn(*const c_void, *const c_void) -> bool>,
}

// Make it safe for static
unsafe impl Sync for CFArrayCallBacks {}

// We need this for CFArrayCreate
#[no_mangle]
pub static kCFTypeArrayCallBacks: CFArrayCallBacks = CFArrayCallBacks {
    version: 0,
    retain: None,
    release: None,
    copy_description: None,
    equal: None,
};
