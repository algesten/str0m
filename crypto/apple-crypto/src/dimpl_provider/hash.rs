//! Hash implementations using Apple CommonCrypto.

use dimpl::buffer::Buf;
use dimpl::crypto::{HashAlgorithm, HashContext, HashProvider};

#[derive(Debug)]
pub(super) struct AppleHashProvider;

impl HashProvider for AppleHashProvider {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn HashContext> {
        match algorithm {
            HashAlgorithm::SHA256 => Box::new(Sha256Context::new()),
            HashAlgorithm::SHA384 => Box::new(Sha384Context::new()),
            _ => panic!("Unsupported hash algorithm: {algorithm:?}"),
        }
    }
}

pub(super) static HASH_PROVIDER: AppleHashProvider = AppleHashProvider;

struct Sha256Context(apple_cryptokit::hashing::Sha256);

impl Sha256Context {
    fn new() -> Self {
        Self(apple_cryptokit::hashing::Sha256::new())
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
        let digest = self.0.snapshot();
        out.clear();
        out.extend_from_slice(&digest);
    }
}

struct Sha384Context(apple_cryptokit::hashing::Sha384);

impl Sha384Context {
    fn new() -> Self {
        Self(apple_cryptokit::hashing::Sha384::new())
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
        let digest = self.0.snapshot();
        out.clear();
        out.extend_from_slice(&digest);
    }
}

/// Compute SHA-256 hash of data and return as fixed-size array.
pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    apple_cryptokit::sha256_hash(data)
}

/// Compute SHA-384 hash of data and return as fixed-size array.
pub(super) fn sha384(data: &[u8]) -> [u8; 48] {
    apple_cryptokit::sha384_hash(data)
}
