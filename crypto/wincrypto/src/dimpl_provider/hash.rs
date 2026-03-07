//! Hash implementations using Windows CNG.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, HashContext, HashProvider};

use windows::Win32::Security::Cryptography::BCRYPT_HASH_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_SHA256_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_SHA384_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCryptCreateHash;
use windows::Win32::Security::Cryptography::BCryptFinishHash;
use windows::Win32::Security::Cryptography::BCryptHashData;
use windows::core::Owned;

use crate::WinCryptoError;

#[derive(Debug)]
pub(super) struct WinCngHashProvider;

impl HashProvider for WinCngHashProvider {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn HashContext> {
        match algorithm {
            HashAlgorithm::SHA256 => Box::new(WinCngHashContext::new(HashKind::Sha256)),
            HashAlgorithm::SHA384 => Box::new(WinCngHashContext::new(HashKind::Sha384)),
            _ => panic!("Unsupported hash algorithm: {algorithm:?}"),
        }
    }
}

pub(super) static HASH_PROVIDER: WinCngHashProvider = WinCngHashProvider;

#[derive(Clone, Copy)]
enum HashKind {
    Sha256,
    Sha384,
}

/// Incremental hash context using Windows CNG.
///
/// CNG hash handles are NOT clonable, so to implement `clone_and_finalize`
/// we buffer all input and re-hash from scratch each time.
struct WinCngHashContext {
    kind: HashKind,
    data: Vec<u8>,
}

// SAFETY: This type stores only owned Rust data; it does not retain any live
// CNG handle between calls, so `Send`/`Sync` rely only on ordinary Rust
// ownership invariants rather than undocumented FFI aliasing.
// Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
unsafe impl Send for WinCngHashContext {}
unsafe impl Sync for WinCngHashContext {}

impl WinCngHashContext {
    fn new(kind: HashKind) -> Self {
        Self {
            kind,
            data: Vec::new(),
        }
    }

    fn hash_len(&self) -> usize {
        match self.kind {
            HashKind::Sha256 => 32,
            HashKind::Sha384 => 48,
        }
    }

    fn finalize_snapshot(&self) -> Vec<u8> {
        let mut hash = vec![0u8; self.hash_len()];
        let alg_handle = match self.kind {
            HashKind::Sha256 => BCRYPT_SHA256_ALG_HANDLE,
            HashKind::Sha384 => BCRYPT_SHA384_ALG_HANDLE,
        };
        // SAFETY: Microsoft Learn documents `BCryptCreateHash`,
        // `BCryptHashData`, and `BCryptFinishHash` as borrowing the handle and
        // buffer arguments only for the duration of each call; all of them
        // outlive this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash
        unsafe {
            let mut hash_handle = Owned::new(BCRYPT_HASH_HANDLE::default());
            WinCryptoError::from_ntstatus(BCryptCreateHash(
                alg_handle,
                &mut *hash_handle,
                None,
                None,
                0,
            ))
            .expect("hash creation");

            WinCryptoError::from_ntstatus(BCryptHashData(*hash_handle, &self.data, 0))
                .expect("hash data");

            WinCryptoError::from_ntstatus(BCryptFinishHash(*hash_handle, &mut hash, 0))
                .expect("hash finish");
        }
        hash
    }
}

impl std::fmt::Debug for WinCngHashContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinCngHashContext").finish_non_exhaustive()
    }
}

impl HashContext for WinCngHashContext {
    fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        let digest = self.finalize_snapshot();
        out.clear();
        out.extend_from_slice(&digest);
    }
}
