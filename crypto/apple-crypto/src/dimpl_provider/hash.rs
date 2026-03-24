//! Hash implementations using Apple CommonCrypto.

use dimpl::crypto::Buf;
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

// SAFETY: The inner `apple_cryptokit::hashing::Sha256` holds a `*mut c_void` pointing to a
// Swift `Sha256Box` class instance (managed via `Unmanaged.passRetained()`). The Swift class
// wraps Apple CryptoKit's `SHA256` struct — a pure value type containing only hash state bytes
// (no references, pointers, or heap allocations inside the value type itself).
//
// The Swift side has NO internal synchronization (no locks, actors, or atomics). Thread safety
// relies entirely on Rust's borrow checker enforcing access discipline:
//
// - `update(&mut self)` requires exclusive access, so concurrent mutation is impossible.
// - `clone_and_finalize(&self)` is the only `&self` method. On the Swift side this reads the
//   stored `SHA256` value (a byte-level copy) into a local and finalizes the copy. When multiple
//   threads call this concurrently, they are performing concurrent reads of the same bytes with
//   no writer present — Rust's borrow rules guarantee no `&mut self` can coexist with `&self`.
//   Concurrent reads of plain bytes with no concurrent writer is safe on all architectures.
// - `Drop` calls `swift_sha256_free` which does `Unmanaged<Sha256Box>.release()`. Swift ARC
//   retain/release is atomic, so dropping on a different thread than creation is safe.
//
// Summary: Send is safe because ownership transfer is clean (atomic ARC, no thread-local state).
// Sync is safe because the only shared operation (`&self`) is a pure read with no concurrent writer.
unsafe impl Send for Sha256Context {}
unsafe impl Sync for Sha256Context {}

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

// SAFETY: Same reasoning as Sha256Context above. The inner `Sha384` holds a `*mut c_void`
// pointing to a Swift `Sha384Box` class wrapping Apple CryptoKit's `SHA384` value type (plain
// hash state bytes). Rust's borrow checker ensures `update(&mut self)` has exclusive access and
// `clone_and_finalize(&self)` only performs concurrent reads with no writer. Swift ARC
// retain/release is atomic, making cross-thread Drop safe.
unsafe impl Send for Sha384Context {}
unsafe impl Sync for Sha384Context {}

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
