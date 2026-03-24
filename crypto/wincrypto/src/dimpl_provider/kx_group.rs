//! Key exchange group implementations using Windows CNG BCrypt ECDH.

use std::sync::LazyLock;

use dimpl::crypto::Buf;
use dimpl::crypto::{ActiveKeyExchange, NamedGroup, SupportedKxGroup};

use windows::Win32::Security::Cryptography::BCRYPT_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_ECCPUBLIC_BLOB;
use windows::Win32::Security::Cryptography::BCRYPT_ECDH_ALGORITHM;
use windows::Win32::Security::Cryptography::BCRYPT_ECDH_P256_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_ECDH_P384_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_KDF_RAW_SECRET;
use windows::Win32::Security::Cryptography::BCRYPT_KEY_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS;
use windows::Win32::Security::Cryptography::BCRYPT_SECRET_HANDLE;
use windows::Win32::Security::Cryptography::BCryptDeriveKey;
use windows::Win32::Security::Cryptography::BCryptExportKey;
use windows::Win32::Security::Cryptography::BCryptFinalizeKeyPair;
use windows::Win32::Security::Cryptography::BCryptGenerateKeyPair;
use windows::Win32::Security::Cryptography::BCryptImportKeyPair;
use windows::Win32::Security::Cryptography::BCryptOpenAlgorithmProvider;
use windows::Win32::Security::Cryptography::BCryptSecretAgreement;
use windows::Win32::Security::Cryptography::BCryptSetProperty;
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
unsafe fn derive_raw_secret(secret_handle: BCRYPT_SECRET_HANDLE) -> Result<Vec<u8>, String> {
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

// =============================================================================
// X25519 key exchange using Windows CNG (requires Windows 10 1607+)
// =============================================================================

/// Wrapper to allow BCRYPT_ALG_HANDLE in a LazyLock (Send + Sync).
/// SAFETY: `BCRYPT_ALG_HANDLE` is an opaque CNG algorithm-provider handle
/// documented by Microsoft Learn for the BCrypt APIs; this wrapper never
/// dereferences it directly and only passes it back to those APIs.
/// Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/
struct X25519Alg(BCRYPT_ALG_HANDLE);
unsafe impl Send for X25519Alg {}
unsafe impl Sync for X25519Alg {}

/// Cached algorithm provider for X25519 ECDH.
static X25519_PROVIDER: LazyLock<X25519Alg> = LazyLock::new(|| {
    // SAFETY: Microsoft Learn documents `BCryptOpenAlgorithmProvider` and
    // `BCryptSetProperty` as borrowing the output handle and property buffer
    // for the duration of each call; both outlive this initialization block.
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty
    unsafe {
        let mut handle = BCRYPT_ALG_HANDLE::default();
        WinCryptoError::from_ntstatus(BCryptOpenAlgorithmProvider(
            &mut handle,
            BCRYPT_ECDH_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        ))
        .expect("BCryptOpenAlgorithmProvider ECDH for X25519");

        // Set the curve to Curve25519
        let curve_name: Vec<u16> = "curve25519\0".encode_utf16().collect();
        let curve_bytes =
            std::slice::from_raw_parts(curve_name.as_ptr() as *const u8, curve_name.len() * 2);
        WinCryptoError::from_ntstatus(BCryptSetProperty(
            BCRYPT_HANDLE(handle.0),
            windows::core::w!("ECCCurveName"),
            curve_bytes,
            0,
        ))
        .expect("BCryptSetProperty curve25519");

        X25519Alg(handle)
    }
});

/// X25519 key exchange using Windows CNG Curve25519 support.
struct X25519KeyExchange {
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    public_key_bytes: Buf,
}

// SAFETY: `BCRYPT_KEY_HANDLE` is an opaque CNG handle documented by Microsoft
// Learn for the BCrypt APIs; this wrapper never dereferences it directly and
// only passes it back to those APIs.
// Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/
unsafe impl Send for X25519KeyExchange {}
unsafe impl Sync for X25519KeyExchange {}

impl std::fmt::Debug for X25519KeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyExchange").finish_non_exhaustive()
    }
}

impl X25519KeyExchange {
    fn new(mut buf: Buf) -> Result<Self, String> {
        let alg_handle = X25519_PROVIDER.0;

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
                255,
                0,
            ))
            .map_err(|e| format!("BCryptGenerateKeyPair X25519 failed: {e}"))?;

            WinCryptoError::from_ntstatus(BCryptFinalizeKeyPair(*key_handle, 0))
                .map_err(|e| format!("BCryptFinalizeKeyPair X25519 failed: {e}"))?;

            key_handle
        };

        // Export public key — 32 raw bytes for X25519
        let pub_key = export_x25519_public_key(*key_handle)?;

        buf.clear();
        buf.extend_from_slice(&pub_key);

        Ok(Self {
            key_handle,
            public_key_bytes: buf,
        })
    }
}

impl ActiveKeyExchange for X25519KeyExchange {
    fn pub_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), String> {
        if peer_pub.len() != 32 {
            return Err(format!(
                "Invalid X25519 public key length: {} (expected 32)",
                peer_pub.len(),
            ));
        }

        let alg_handle = X25519_PROVIDER.0;
        let peer_key_handle = import_x25519_public_key(alg_handle, peer_pub)?;

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
            .map_err(|e| format!("BCryptSecretAgreement X25519 failed: {e}"))?;

            derive_raw_secret(*secret_handle)?
        };

        // RFC 7748 §6.1: reject all-zero shared secret (non-contributory / low-order point)
        if shared_secret.iter().all(|&b| b == 0) {
            return Err("X25519 shared secret is zero (non-contributory)".into());
        }

        // BCryptDeriveKey with BCRYPT_KDF_RAW_SECRET returns the raw secret in
        // little-endian (least-significant byte first) for ALL curve types.
        // X25519 is natively little-endian per RFC 7748, but CNG returns it in
        // the opposite order. Reverse to match the RFC 7748 wire format that
        // other implementations (x25519-dalek, BoringSSL, etc.) produce.
        let mut secret = shared_secret;
        secret.reverse();

        out.clear();
        out.extend_from_slice(&secret);

        Ok(())
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// Export X25519 public key as 32 raw bytes.
fn export_x25519_public_key(key_handle: BCRYPT_KEY_HANDLE) -> Result<Vec<u8>, String> {
    // SAFETY: Microsoft Learn documents `BCryptExportKey` as borrowing the key
    // handle and optional output buffer for the duration of each call; both
    // outlive this block.
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptexportkey
    unsafe {
        let mut blob_size = 0u32;
        WinCryptoError::from_ntstatus(BCryptExportKey(
            key_handle,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            &mut blob_size,
            0,
        ))
        .map_err(|e| format!("BCryptExportKey X25519 size query failed: {e}"))?;

        let mut blob = vec![0u8; blob_size as usize];
        WinCryptoError::from_ntstatus(BCryptExportKey(
            key_handle,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            Some(&mut blob),
            &mut blob_size,
            0,
        ))
        .map_err(|e| format!("BCryptExportKey X25519 failed: {e}"))?;

        // BCRYPT_ECCKEY_BLOB: dwMagic(4) + cbKey(4) then X[cbKey] + Y[cbKey]
        // For Curve25519 cbKey=32, so X is the 32-byte u-coordinate.
        let header_size = 8;
        let cb_key = u32::from_le_bytes(blob[4..8].try_into().unwrap()) as usize;
        if blob.len() < header_size + cb_key {
            return Err(format!("X25519 public key blob too small: {}", blob.len()));
        }

        Ok(blob[header_size..header_size + cb_key].to_vec())
    }
}

/// Import an X25519 public key from 32 raw bytes.
fn import_x25519_public_key(
    alg_handle: BCRYPT_ALG_HANDLE,
    pub_key: &[u8],
) -> Result<Owned<BCRYPT_KEY_HANDLE>, String> {
    // BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC
    let magic: u32 = 0x504B4345;
    let cb_key: u32 = 32;

    // BCRYPT_ECCPUBLIC_BLOB: header(8) + X[cbKey] + Y[cbKey]
    // For Curve25519, Y is not meaningful; pad with zeros.
    let mut blob = Vec::with_capacity(8 + 64);
    blob.extend_from_slice(&magic.to_le_bytes());
    blob.extend_from_slice(&cb_key.to_le_bytes());
    blob.extend_from_slice(pub_key); // X (32 bytes)
    blob.extend_from_slice(&[0u8; 32]); // Y (32 zeros)

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
        .map_err(|e| format!("BCryptImportKeyPair X25519 failed: {e}"))?;

        Ok(key_handle)
    }
}

/// X25519 key exchange group.
#[derive(Debug)]
struct X25519Kx;

impl SupportedKxGroup for X25519Kx {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(X25519KeyExchange::new(buf)?))
    }
}

static KX_GROUP_X25519: X25519Kx = X25519Kx;
static KX_GROUP_P256: P256 = P256;
static KX_GROUP_P384: P384 = P384;

pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] =
    &[&KX_GROUP_X25519, &KX_GROUP_P256, &KX_GROUP_P384];

#[cfg(test)]
mod tests {
    use super::*;

    /// Two wincrypto X25519 exchanges must produce identical shared secrets.
    #[test]
    fn x25519_roundtrip_symmetric() {
        let alice = X25519Kx.start_exchange(Buf::new()).unwrap();
        let bob = X25519Kx.start_exchange(Buf::new()).unwrap();

        let alice_pub = alice.pub_key().to_vec();
        let bob_pub = bob.pub_key().to_vec();

        let mut alice_secret = Buf::new();
        let mut bob_secret = Buf::new();
        alice.complete(&bob_pub, &mut alice_secret).unwrap();
        bob.complete(&alice_pub, &mut bob_secret).unwrap();

        assert_eq!(
            &alice_secret[..],
            &bob_secret[..],
            "X25519 shared secrets must be identical regardless of which side completes"
        );
        assert_eq!(alice_secret.len(), 32);
    }

    /// Verify wincrypto X25519 shared secret matches x25519-dalek (reference implementation).
    ///
    /// This catches byte-order bugs: BCryptDeriveKey returns the raw secret in
    /// reversed byte order, and we must reverse it to match RFC 7748.
    #[test]
    fn x25519_interop_with_dalek() {
        use rand_core::OsRng;
        use x25519_dalek::{EphemeralSecret, PublicKey};

        // Generate a key pair with x25519-dalek (reference)
        let dalek_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let dalek_pub = PublicKey::from(&dalek_secret);

        // Generate a key pair with wincrypto CNG
        let win_kx = X25519Kx.start_exchange(Buf::new()).unwrap();
        let win_pub = win_kx.pub_key().to_vec();

        // wincrypto completes with dalek's public key
        let mut win_shared = Buf::new();
        win_kx
            .complete(dalek_pub.as_bytes(), &mut win_shared)
            .unwrap();

        // dalek completes with wincrypto's public key
        let win_pub_bytes: [u8; 32] = win_pub.try_into().unwrap();
        let dalek_peer = PublicKey::from(win_pub_bytes);
        let dalek_shared = dalek_secret.diffie_hellman(&dalek_peer);

        assert_eq!(
            &win_shared[..],
            dalek_shared.as_bytes(),
            "wincrypto and x25519-dalek must produce the same shared secret"
        );
    }
}
