//! Cipher suite implementations using Windows CNG AES-GCM.

use std::cell::RefCell;
use std::ptr::{addr_of, write_volatile};

use dimpl::crypto::SupportedDtls12CipherSuite;
use dimpl::crypto::SupportedDtls13CipherSuite;
use dimpl::crypto::{Aad, Cipher, Dtls12CipherSuite, HashAlgorithm, Nonce};
use dimpl::crypto::{Buf, Dtls13CipherSuite, TmpBuf};

use windows::Win32::Security::Cryptography::BCRYPT_AES_ECB_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_AES_GCM_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
use windows::Win32::Security::Cryptography::BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
use windows::Win32::Security::Cryptography::BCRYPT_FLAGS;
use windows::Win32::Security::Cryptography::BCRYPT_KEY_HANDLE;
use windows::Win32::Security::Cryptography::BCryptDecrypt;
use windows::Win32::Security::Cryptography::BCryptEncrypt;
use windows::Win32::Security::Cryptography::BCryptGenerateSymmetricKey;
use windows::core::Owned;

use crate::WinCryptoError;

const AES_GCM_TAG_LEN: usize = 16;

/// AES-GCM cipher implementation using Windows CNG.
struct AesGcm {
    key: Owned<BCRYPT_KEY_HANDLE>,
}

// SAFETY: `BCRYPT_KEY_HANDLE` is an opaque CNG handle documented by Microsoft
// Learn for the BCrypt APIs; this wrapper never dereferences it directly and
// only passes it back to those APIs.
// Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/
unsafe impl Send for AesGcm {}
unsafe impl Sync for AesGcm {}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcm").finish_non_exhaustive()
    }
}

impl AesGcm {
    fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 16 && key.len() != 32 {
            return Err(format!("Invalid key size for AES-GCM: {}", key.len()));
        }
        // SAFETY: Microsoft Learn documents `BCryptGenerateSymmetricKey` as
        // borrowing the caller-provided key bytes and output handle only for
        // the duration of the call; both outlive this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey
        let key_handle = unsafe {
            let mut key_handle = Owned::new(BCRYPT_KEY_HANDLE::default());
            WinCryptoError::from_ntstatus(BCryptGenerateSymmetricKey(
                BCRYPT_AES_GCM_ALG_HANDLE,
                &mut *key_handle,
                None,
                key,
                0,
            ))
            .map_err(|e| format!("AES-GCM key creation failed: {e}"))?;
            key_handle
        };
        Ok(Self { key: key_handle })
    }
}

impl Cipher for AesGcm {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        let plain_len = plaintext.len();
        let mut ciphertext = vec![0u8; plain_len];
        let mut tag = [0u8; AES_GCM_TAG_LEN];

        let auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            pbNonce: nonce.0.as_ptr() as *mut u8,
            cbNonce: nonce.0.len() as u32,
            pbAuthData: aad.0.as_ptr() as *mut u8,
            cbAuthData: aad.0.len() as u32,
            pbTag: tag.as_mut_ptr(),
            cbTag: AES_GCM_TAG_LEN as u32,
            ..Default::default()
        };

        let mut count = 0u32;
        // SAFETY: Microsoft Learn documents `BCryptEncrypt` as borrowing the
        // input, output, and authenticated-cipher-mode-info buffers for the
        // duration of the call; `auth_info` only points at data that outlives
        // this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt
        unsafe {
            WinCryptoError::from_ntstatus(BCryptEncrypt(
                *self.key,
                Some(plaintext.as_ref()),
                Some(addr_of!(auth_info) as *const std::ffi::c_void),
                None,
                Some(&mut ciphertext),
                &mut count,
                BCRYPT_FLAGS(0),
            ))
            .map_err(|e| format!("AES-GCM encrypt failed: {e}"))?;
        }

        plaintext.clear();
        plaintext.extend_from_slice(&ciphertext[..count as usize]);
        plaintext.extend_from_slice(&tag);
        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if ciphertext.len() < AES_GCM_TAG_LEN {
            return Err("Ciphertext too short for AES-GCM".into());
        }

        let ct_len = ciphertext.len() - AES_GCM_TAG_LEN;
        // Split ciphertext and tag - we need to copy because we can't borrow twice.
        let ct_data: Vec<u8> = ciphertext.as_ref()[..ct_len].to_vec();
        let mut tag = [0u8; AES_GCM_TAG_LEN];
        tag.copy_from_slice(&ciphertext.as_ref()[ct_len..]);

        let mut plaintext = vec![0u8; ct_len];

        let auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            pbNonce: nonce.0.as_ptr() as *mut u8,
            cbNonce: nonce.0.len() as u32,
            pbAuthData: aad.0.as_ptr() as *mut u8,
            cbAuthData: aad.0.len() as u32,
            pbTag: tag.as_mut_ptr(),
            cbTag: AES_GCM_TAG_LEN as u32,
            ..Default::default()
        };

        let mut count = 0u32;
        // SAFETY: Microsoft Learn documents `BCryptDecrypt` as borrowing the
        // input, output, and authenticated-cipher-mode-info buffers for the
        // duration of the call; all referenced data outlives this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt
        unsafe {
            WinCryptoError::from_ntstatus(BCryptDecrypt(
                *self.key,
                Some(&ct_data),
                Some(addr_of!(auth_info) as *const std::ffi::c_void),
                None,
                Some(&mut plaintext),
                &mut count,
                BCRYPT_FLAGS(0),
            ))
            .map_err(|e| format!("AES-GCM decrypt failed: {e}"))?;
        }

        ciphertext.truncate(count as usize);
        ciphertext.as_mut()[..count as usize].copy_from_slice(&plaintext[..count as usize]);
        Ok(())
    }
}

// DTLS 1.2 cipher suites

/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#[derive(Debug)]
struct Aes128GcmSha256;

impl SupportedDtls12CipherSuite for Aes128GcmSha256 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 16, 4)
    }

    fn explicit_nonce_len(&self) -> usize {
        8
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
#[derive(Debug)]
struct Aes256GcmSha384;

impl SupportedDtls12CipherSuite for Aes256GcmSha384 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 32, 4)
    }

    fn explicit_nonce_len(&self) -> usize {
        8
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

static AES_128_GCM_SHA256: Aes128GcmSha256 = Aes128GcmSha256;
static AES_256_GCM_SHA384: Aes256GcmSha384 = Aes256GcmSha384;

pub(super) static ALL_CIPHER_SUITES: &[&dyn SupportedDtls12CipherSuite] =
    &[&AES_128_GCM_SHA256, &AES_256_GCM_SHA384];

// DTLS 1.3 cipher suites

/// TLS_AES_128_GCM_SHA256 (DTLS 1.3)
#[derive(Debug)]
struct Tls13Aes128GcmSha256;

impl SupportedDtls13CipherSuite for Tls13Aes128GcmSha256 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_128_GCM_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_len(&self) -> usize {
        16
    }

    fn iv_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        aes_ecb_encrypt(sn_key, sample)
    }
}

/// TLS_AES_256_GCM_SHA384 (DTLS 1.3)
#[derive(Debug)]
struct Tls13Aes256GcmSha384;

impl SupportedDtls13CipherSuite for Tls13Aes256GcmSha384 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_256_GCM_SHA384
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn key_len(&self) -> usize {
        32
    }

    fn iv_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        aes_ecb_encrypt(sn_key, sample)
    }
}

static TLS13_AES_128_GCM_SHA256: Tls13Aes128GcmSha256 = Tls13Aes128GcmSha256;
static TLS13_AES_256_GCM_SHA384: Tls13Aes256GcmSha384 = Tls13Aes256GcmSha384;

pub(super) static ALL_DTLS13_CIPHER_SUITES: &[&dyn SupportedDtls13CipherSuite] =
    &[&TLS13_AES_128_GCM_SHA256, &TLS13_AES_256_GCM_SHA384];

/// Key bytes wrapper that volatile-zeroes its contents on drop.
struct ZeroizingKey(Vec<u8>);

impl Drop for ZeroizingKey {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            // SAFETY: `byte` is a valid, aligned, dereferenceable pointer into
            // our own Vec's heap buffer. `write_volatile` prevents the compiler
            // from eliding this zero-write.
            unsafe { write_volatile(byte, 0) };
        }
    }
}

impl ZeroizingKey {
    fn new(key: &[u8]) -> Self {
        Self(key.to_vec())
    }
}

impl PartialEq<[u8]> for ZeroizingKey {
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

// DTLS 1.3 record number protection (`encrypt_sn`) requires a single AES-ECB
// block encryption per packet. On other platforms this is cheap: Apple's
// `CCCrypt` and pure-Rust `aes` both accept raw key bytes and do the AES key
// expansion inline (~100 ns). Windows CNG, however, forces a two-step model:
//
//   1. `BCryptGenerateSymmetricKey` — allocate a kernel object, expand the key
//      schedule, return a `BCRYPT_KEY_HANDLE`.  (~5–20 µs)
//   2. `BCryptEncrypt` — encrypt using that handle.
//
// Creating and destroying a handle per packet is 100–400× slower than the
// inline approach. We want to cache the handle, but the dimpl trait that calls
// us is:
//
//   fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16];
//
// The implementor (`Tls13Aes128GcmSha256`) is a unit struct stored as a global
// `static`, shared across all connections. `&self` is immutable and the trait
// requires `Send + Sync`, so we cannot stash a `BCRYPT_KEY_HANDLE` inside
// `self` without a `Mutex` — which would serialize all DTLS traffic in the
// process through a single lock.
//
// `thread_local!` sidesteps both problems:
//   • No lock — each OS thread has its own small LRU cache (capacity 4).
//   • No mutation of `self` — the cache lives outside the trait object.
//   • Handles are cleaned up automatically when the thread exits.
//   • Key bytes are volatile-zeroed on eviction via `ZeroizingKey`.
//
// The `sn_key` is constant for a given DTLS epoch (usually the entire
// session), so the cache hit rate is effectively 100 % during steady state.
thread_local! {
    /// Cache for AES-ECB keys for DTLS 1.3 record number protection.
    static AES_ECB_KEY_CACHE: RefCell<
        Vec<(ZeroizingKey, Owned<BCRYPT_KEY_HANDLE>)>,
    > = RefCell::new(Vec::with_capacity(4));
}

fn aes_ecb_encrypt(key: &[u8], input: &[u8; 16]) -> [u8; 16] {
    AES_ECB_KEY_CACHE.with(|cache_cell| {
        let mut cache = cache_cell.borrow_mut();

        // 1. Try to find in cache
        let cached_handle = if let Some(pos) = cache.iter().position(|(k, _)| k == key) {
            // Move to front (LRU)
            if pos > 0 {
                let item = cache.remove(pos);
                cache.insert(0, item);
            }
            Some(*cache[0].1)
        } else {
            None
        };

        if let Some(handle) = cached_handle {
            return do_aes_ecb_encrypt(handle, input);
        }

        // 2. Not found, generate new
        // SAFETY: Microsoft Learn documents `BCryptGenerateSymmetricKey`...
        let new_handle_owned = unsafe {
            let mut key_handle = Owned::new(BCRYPT_KEY_HANDLE::default());
            WinCryptoError::from_ntstatus(BCryptGenerateSymmetricKey(
                BCRYPT_AES_ECB_ALG_HANDLE,
                &mut *key_handle,
                None,
                key,
                0,
            ))
            .expect("AES-ECB key creation");
            key_handle
        };

        let raw_handle = *new_handle_owned;

        // 3. Store in cache
        if cache.len() >= 4 {
            cache.pop();
        }
        cache.insert(0, (ZeroizingKey::new(key), new_handle_owned));

        do_aes_ecb_encrypt(raw_handle, input)
    })
}

fn do_aes_ecb_encrypt(key_handle: BCRYPT_KEY_HANDLE, input: &[u8; 16]) -> [u8; 16] {
    let mut output = [0u8; 16];
    unsafe {
        let mut count = 0u32;
        WinCryptoError::from_ntstatus(BCryptEncrypt(
            key_handle,
            Some(input),
            None,
            None,
            Some(&mut output),
            &mut count,
            BCRYPT_FLAGS(0),
        ))
        .expect("AES-ECB encrypt");
    }
    let mut result = [0u8; 16];
    result.copy_from_slice(&output);
    result
}
