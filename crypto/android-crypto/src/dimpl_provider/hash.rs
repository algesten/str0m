//! Hash implementations using Android JNI crypto.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, HashContext, HashProvider};

use crate::jni_crypto;

#[derive(Debug)]
pub(super) struct AndroidHashProvider;

impl HashProvider for AndroidHashProvider {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn HashContext> {
        match algorithm {
            HashAlgorithm::SHA256 => Box::new(Sha256Context::new()),
            HashAlgorithm::SHA384 => Box::new(Sha384Context::new()),
            _ => panic!("Unsupported hash algorithm: {algorithm:?}"),
        }
    }
}

pub(super) static HASH_PROVIDER: AndroidHashProvider = AndroidHashProvider;

struct Sha256Context(jni_crypto::Sha256Context);

// SAFETY: The context only holds a Vec<u8> which is Send + Sync.
unsafe impl Send for Sha256Context {}
unsafe impl Sync for Sha256Context {}

impl Sha256Context {
    fn new() -> Self {
        Self(jni_crypto::Sha256Context::new())
    }
}

impl std::fmt::Debug for Sha256Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256Context").finish_non_exhaustive()
    }
}

impl HashContext for Sha256Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        let digest = self.0.snapshot().expect("SHA-256 finalize failed");
        out.clear();
        out.extend_from_slice(&digest);
    }
}

struct Sha384Context(jni_crypto::Sha384Context);

// SAFETY: The context only holds a Vec<u8> which is Send + Sync.
unsafe impl Send for Sha384Context {}
unsafe impl Sync for Sha384Context {}

impl Sha384Context {
    fn new() -> Self {
        Self(jni_crypto::Sha384Context::new())
    }
}

impl std::fmt::Debug for Sha384Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha384Context").finish_non_exhaustive()
    }
}

impl HashContext for Sha384Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        let digest = self.0.snapshot().expect("SHA-384 finalize failed");
        out.clear();
        out.extend_from_slice(&digest);
    }
}
