//! Key exchange group implementations using Windows CNG BCrypt ECDH.

use dimpl::crypto::Buf;
use dimpl::crypto::{ActiveKeyExchange, NamedGroup, SupportedKxGroup};

use windows::Win32::Security::Cryptography::BCRYPT_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_ECCPUBLIC_BLOB;
use windows::Win32::Security::Cryptography::BCRYPT_ECDH_P256_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_ECDH_P384_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_KDF_RAW_SECRET;
use windows::Win32::Security::Cryptography::BCRYPT_KEY_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_SECRET_HANDLE;
use windows::Win32::Security::Cryptography::BCryptDeriveKey;
use windows::Win32::Security::Cryptography::BCryptExportKey;
use windows::Win32::Security::Cryptography::BCryptFinalizeKeyPair;
use windows::Win32::Security::Cryptography::BCryptGenerateKeyPair;
use windows::Win32::Security::Cryptography::BCryptImportKeyPair;
use windows::Win32::Security::Cryptography::BCryptSecretAgreement;
use windows::core::Owned;

use crate::WinCryptoError;

/// ECDHE key exchange implementation using Windows CNG.
struct EcdhKeyExchange {
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    public_key_bytes: Buf,
    group: NamedGroup,
}

// SAFETY: `BCRYPT_KEY_HANDLE` is an opaque CNG handle documented by Microsoft
// Learn for the BCrypt APIs; this wrapper never dereferences it directly and
// only passes it back to those APIs.
// Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/
unsafe impl Send for EcdhKeyExchange {}
unsafe impl Sync for EcdhKeyExchange {}

impl std::fmt::Debug for EcdhKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhKeyExchange")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

impl EcdhKeyExchange {
    fn new(group: NamedGroup, mut buf: Buf) -> Result<Self, String> {
        let (alg_handle, coord_size) = match group {
            NamedGroup::Secp256r1 => (BCRYPT_ECDH_P256_ALG_HANDLE, 32usize),
            NamedGroup::Secp384r1 => (BCRYPT_ECDH_P384_ALG_HANDLE, 48usize),
            _ => return Err(format!("Unsupported group: {group:?}")),
        };

        // SAFETY: Microsoft Learn documents `BCryptGenerateKeyPair` and
        // `BCryptFinalizeKeyPair` as initializing the caller-provided handle
        // for the duration of the call; the output handle outlives this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratekeypair
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinalizekeypair
        let key_handle = unsafe {
            let mut key_handle = Owned::new(BCRYPT_KEY_HANDLE::default());
            WinCryptoError::from_ntstatus(BCryptGenerateKeyPair(
                alg_handle,
                &mut *key_handle,
                (coord_size * 8) as u32,
                0,
            ))
            .map_err(|e| format!("BCryptGenerateKeyPair failed: {e}"))?;

            WinCryptoError::from_ntstatus(BCryptFinalizeKeyPair(*key_handle, 0))
                .map_err(|e| format!("BCryptFinalizeKeyPair failed: {e}"))?;

            key_handle
        };

        // Export public key as SEC1 uncompressed point: 04 || X || Y
        let pub_key_bytes = export_ec_public_key(*key_handle, coord_size)?;

        buf.clear();
        buf.extend_from_slice(&pub_key_bytes);

        Ok(Self {
            key_handle,
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
        let coord_size = match self.group {
            NamedGroup::Secp256r1 => 32usize,
            NamedGroup::Secp384r1 => 48usize,
            _ => return Err("Unsupported group".into()),
        };

        let alg_handle = match self.group {
            NamedGroup::Secp256r1 => BCRYPT_ECDH_P256_ALG_HANDLE,
            NamedGroup::Secp384r1 => BCRYPT_ECDH_P384_ALG_HANDLE,
            _ => return Err("Unsupported group".into()),
        };

        // peer_pub should be uncompressed point: 04 || X || Y
        if peer_pub.len() != 1 + 2 * coord_size || peer_pub[0] != 0x04 {
            return Err(format!(
                "Invalid peer public key length: {} (expected {})",
                peer_pub.len(),
                1 + 2 * coord_size,
            ));
        }

        // Import peer public key as BCRYPT_ECCPUBLIC_BLOB
        let peer_key_handle = import_ec_public_key(alg_handle, peer_pub, coord_size)?;

        // Perform ECDH key exchange
        // SAFETY: Microsoft Learn documents `BCryptSecretAgreement` as
        // borrowing both key handles and the output secret handle for the
        // duration of the call; all handles outlive this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptsecretagreement
        let shared_secret = unsafe {
            let mut secret_handle = Owned::new(BCRYPT_SECRET_HANDLE::default());
            WinCryptoError::from_ntstatus(BCryptSecretAgreement(
                *self.key_handle,
                *peer_key_handle,
                &mut *secret_handle,
                0,
            ))
            .map_err(|e| format!("BCryptSecretAgreement failed: {e}"))?;

            // Derive raw shared secret
            derive_raw_secret(*secret_handle)?
        };

        // Windows returns the raw shared secret in big-endian, which is what we want.
        // However, BCryptDeriveKey with BCRYPT_KDF_RAW_SECRET returns it in LITTLE-endian.
        // We need to reverse it.
        let mut secret_be = shared_secret;
        secret_be.reverse();

        out.clear();
        out.extend_from_slice(&secret_be);

        Ok(())
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

/// Export EC public key as SEC1 uncompressed point format: 04 || X || Y
fn export_ec_public_key(
    key_handle: BCRYPT_KEY_HANDLE,
    coord_size: usize,
) -> Result<Vec<u8>, String> {
    // SAFETY: Microsoft Learn documents `BCryptExportKey` as borrowing the key
    // handle and optional output buffer for the duration of each call; both
    // outlive this block.
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptexportkey
    unsafe {
        // Query size first
        let mut blob_size = 0u32;
        WinCryptoError::from_ntstatus(BCryptExportKey(
            key_handle,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            &mut blob_size,
            0,
        ))
        .map_err(|e| format!("BCryptExportKey size query failed: {e}"))?;

        let mut blob = vec![0u8; blob_size as usize];
        WinCryptoError::from_ntstatus(BCryptExportKey(
            key_handle,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            Some(&mut blob),
            &mut blob_size,
            0,
        ))
        .map_err(|e| format!("BCryptExportKey failed: {e}"))?;

        // BCRYPT_ECCKEY_BLOB header is 8 bytes: dwMagic(4) + cbKey(4)
        // followed by X(cbKey) + Y(cbKey)
        let header_size = 8;
        if blob.len() < header_size + 2 * coord_size {
            return Err("Exported key blob too small".into());
        }

        let x = &blob[header_size..header_size + coord_size];
        let y = &blob[header_size + coord_size..header_size + 2 * coord_size];

        let mut pub_key = Vec::with_capacity(1 + 2 * coord_size);
        pub_key.push(0x04); // Uncompressed point
        pub_key.extend_from_slice(x);
        pub_key.extend_from_slice(y);

        Ok(pub_key)
    }
}

/// Import an EC public key from SEC1 uncompressed point format.
fn import_ec_public_key(
    alg_handle: BCRYPT_ALG_HANDLE,
    pub_key: &[u8],
    coord_size: usize,
) -> Result<Owned<BCRYPT_KEY_HANDLE>, String> {
    // Build BCRYPT_ECCKEY_BLOB
    let magic: u32 = match coord_size {
        32 => 0x314B4345, // BCRYPT_ECDH_PUBLIC_P256_MAGIC
        48 => 0x334B4345, // BCRYPT_ECDH_PUBLIC_P384_MAGIC
        _ => return Err("Unsupported coord size".into()),
    };

    let header_size = 8;
    let mut blob = Vec::with_capacity(header_size + 2 * coord_size);
    blob.extend_from_slice(&magic.to_le_bytes());
    blob.extend_from_slice(&(coord_size as u32).to_le_bytes());
    // pub_key is 04 || X || Y, skip the 04 prefix
    blob.extend_from_slice(&pub_key[1..]);

    // SAFETY: Microsoft Learn documents `BCryptImportKeyPair` as borrowing the
    // key blob and output handle only for the duration of the call; both
    // outlive this block.
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair
    unsafe {
        let mut key_handle = Owned::new(BCRYPT_KEY_HANDLE::default());
        WinCryptoError::from_ntstatus(BCryptImportKeyPair(
            alg_handle,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            &mut *key_handle,
            &blob,
            0,
        ))
        .map_err(|e| format!("BCryptImportKeyPair failed: {e}"))?;

        Ok(key_handle)
    }
}

/// Derive the raw shared secret from an ECDH secret agreement.
pub(super) unsafe fn derive_raw_secret(
    secret_handle: BCRYPT_SECRET_HANDLE,
) -> Result<Vec<u8>, String> {
    let mut derived_size = 0u32;

    unsafe {
        WinCryptoError::from_ntstatus(BCryptDeriveKey(
            secret_handle,
            BCRYPT_KDF_RAW_SECRET,
            None,
            None,
            &mut derived_size,
            0,
        ))
        .map_err(|e| format!("BCryptDeriveKey size query failed: {e}"))?;
    }

    let mut derived = vec![0u8; derived_size as usize];
    unsafe {
        WinCryptoError::from_ntstatus(BCryptDeriveKey(
            secret_handle,
            BCRYPT_KDF_RAW_SECRET,
            None,
            Some(&mut derived),
            &mut derived_size,
            0,
        ))
        .map_err(|e| format!("BCryptDeriveKey failed: {e}"))?;
    }

    derived.truncate(derived_size as usize);
    Ok(derived)
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

#[cfg(not(feature = "fips140"))]
pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &super::x25519::KX_GROUP_X25519,
    &KX_GROUP_P256,
    &KX_GROUP_P384,
];
#[cfg(feature = "fips140")]
pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&KX_GROUP_P256, &KX_GROUP_P384];

static KX_GROUP_P256: P256 = P256;
static KX_GROUP_P384: P384 = P384;
