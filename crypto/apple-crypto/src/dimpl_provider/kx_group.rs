//! Key exchange group implementations for Apple platforms using Security framework.

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use dimpl::crypto::Buf;
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};

use dimpl::crypto::{ActiveKeyExchange, NamedGroup, SupportedKxGroup};

// Security framework key exchange algorithm
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecKeyAlgorithmECDHKeyExchangeStandard: *const std::ffi::c_void;

    fn SecKeyCopyKeyExchangeResult(
        private_key: *const std::ffi::c_void,
        algorithm: *const std::ffi::c_void,
        public_key: *const std::ffi::c_void,
        parameters: *const std::ffi::c_void,
        error: *mut *const std::ffi::c_void,
    ) -> *const std::ffi::c_void;

    fn SecKeyCreateWithData(
        key_data: *const std::ffi::c_void,
        attributes: *const std::ffi::c_void,
        error: *mut *const std::ffi::c_void,
    ) -> *mut std::ffi::c_void;

    // Key attribute constants
    static kSecAttrKeyType: core_foundation::string::CFStringRef;
    static kSecAttrKeyTypeECSECPrimeRandom: core_foundation::string::CFStringRef;
    static kSecAttrKeyClass: core_foundation::string::CFStringRef;
    static kSecAttrKeyClassPublic: core_foundation::string::CFStringRef;
    static kSecAttrKeySizeInBits: core_foundation::string::CFStringRef;
}

/// ECDHE key exchange implementation using Security framework.
struct EcdhKeyExchange {
    private_key: SecKey,
    public_key_bytes: Buf,
    group: NamedGroup,
}

impl std::fmt::Debug for EcdhKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.group {
            NamedGroup::Secp256r1 => f
                .debug_struct("EcdhKeyExchange::P256")
                .field("public_key_len", &self.public_key_bytes.len())
                .finish_non_exhaustive(),
            NamedGroup::Secp384r1 => f
                .debug_struct("EcdhKeyExchange::P384")
                .field("public_key_len", &self.public_key_bytes.len())
                .finish_non_exhaustive(),
            _ => f
                .debug_struct("EcdhKeyExchange::Unknown")
                .finish_non_exhaustive(),
        }
    }
}

impl EcdhKeyExchange {
    fn new(group: NamedGroup, mut buf: Buf) -> Result<Self, String> {
        let key_size = match group {
            NamedGroup::Secp256r1 => 256,
            NamedGroup::Secp384r1 => 384,
            _ => return Err("Unsupported group".to_string()),
        };

        // Generate ephemeral EC key pair using Security framework
        let mut options = GenerateKeyOptions::default();
        options.set_key_type(KeyType::ec());
        options.set_size_in_bits(key_size);

        let private_key =
            SecKey::new(&options).map_err(|e| format!("Failed to generate EC key pair: {e}"))?;

        let public_key = private_key
            .public_key()
            .ok_or_else(|| "Failed to get public key".to_string())?;

        // Export public key as SEC1 uncompressed point format
        let public_key_data = public_key
            .external_representation()
            .ok_or_else(|| "Failed to export public key".to_string())?;

        buf.clear();
        buf.extend_from_slice(&public_key_data);

        Ok(Self {
            private_key,
            public_key_bytes: buf,
            group,
        })
    }
}

impl ActiveKeyExchange for EcdhKeyExchange {
    fn pub_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), String> {
        // Import the peer's public key
        let peer_key_data = CFData::from_buffer(peer_pub);

        let key_size = match self.group {
            NamedGroup::Secp256r1 => 256,
            NamedGroup::Secp384r1 => 384,
            _ => return Err("Unsupported group".to_string()),
        };

        // Build attributes dictionary using CFMutableDictionary
        let attributes = unsafe {
            let mut dict: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

            let key_type_key = CFString::wrap_under_get_rule(kSecAttrKeyType);
            let key_type_value = CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom);
            dict.set(key_type_key, key_type_value.as_CFType());

            let key_class_key = CFString::wrap_under_get_rule(kSecAttrKeyClass);
            let key_class_value = CFString::wrap_under_get_rule(kSecAttrKeyClassPublic);
            dict.set(key_class_key, key_class_value.as_CFType());

            let key_size_key = CFString::wrap_under_get_rule(kSecAttrKeySizeInBits);
            let key_size_value = CFNumber::from(key_size);
            dict.set(key_size_key, key_size_value.as_CFType());

            dict
        };

        // Create peer public key from data
        let mut error: core_foundation::error::CFErrorRef = std::ptr::null_mut();
        let peer_public_key = unsafe {
            SecKeyCreateWithData(
                peer_key_data.as_concrete_TypeRef() as *const _,
                attributes.as_concrete_TypeRef() as *const _,
                &mut error as *mut _ as *mut *const std::ffi::c_void,
            )
        };

        if peer_public_key.is_null() {
            let error_msg = if !error.is_null() {
                let cf_error = unsafe { CFError::wrap_under_create_rule(error) };
                format!("{cf_error}")
            } else {
                "Unknown error".to_string()
            };
            return Err(format!("Failed to import peer public key: {error_msg}"));
        }

        let peer_public_key = unsafe { SecKey::wrap_under_create_rule(peer_public_key as *mut _) };

        // Perform ECDH key exchange
        let mut error: core_foundation::error::CFErrorRef = std::ptr::null_mut();

        let shared_secret = unsafe {
            SecKeyCopyKeyExchangeResult(
                self.private_key.as_concrete_TypeRef() as *const _,
                kSecKeyAlgorithmECDHKeyExchangeStandard,
                peer_public_key.as_concrete_TypeRef() as *const _,
                std::ptr::null(),
                &mut error as *mut _ as *mut *const std::ffi::c_void,
            )
        };

        if shared_secret.is_null() {
            let error_msg = if !error.is_null() {
                let cf_error = unsafe { CFError::wrap_under_create_rule(error) };
                format!("{cf_error}")
            } else {
                "Unknown error".to_string()
            };
            return Err(format!("ECDH key exchange failed: {error_msg}"));
        }

        let shared_secret_data =
            unsafe { CFData::wrap_under_create_rule(shared_secret as *const _) };

        out.clear();
        out.extend_from_slice(&shared_secret_data);

        Ok(())
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

/// P-256 (secp256r1) key exchange group.
#[derive(Debug)]
struct P256;

impl SupportedKxGroup for P256 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp256r1
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp256r1, buf)?))
    }
}

/// P-384 (secp384r1) key exchange group.
#[derive(Debug)]
struct P384;

impl SupportedKxGroup for P384 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp384r1
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp384r1, buf)?))
    }
}

/// Static instances of supported key exchange groups.
static KX_GROUP_P256: P256 = P256;
static KX_GROUP_P384: P384 = P384;

/// All supported key exchange groups.
pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&KX_GROUP_P256, &KX_GROUP_P384];
