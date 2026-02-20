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

#[cfg(test)]
mod test {
    use super::*;

    // Test vectors from NIST CAVP
    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
    fn slice_to_hex(data: &[u8]) -> String {
        let mut s = String::new();
        for byte in data.iter() {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    // SHA-256 Test Vectors

    #[test]
    fn test_sha256_context_single_update() {
        let mut ctx = Sha256Context::new();
        ctx.update(b"abc");
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        assert_eq!(
            slice_to_hex(&out),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_context_multiple_updates() {
        let mut ctx = Sha256Context::new();
        ctx.update(b"abcdbcde");
        ctx.update(b"cdefdefg");
        ctx.update(b"efghfghighijhijkijkljklmklmnlmnomnopnopq");
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        assert_eq!(
            slice_to_hex(&out),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_sha256_context_snapshot() {
        let mut ctx = Sha256Context::new();
        ctx.update(b"abc");
        let mut out1 = Buf::new();
        ctx.clone_and_finalize(&mut out1);

        // Update again and verify first snapshot is unchanged
        ctx.update(b"def");
        let mut out2 = Buf::new();
        ctx.clone_and_finalize(&mut out2);

        assert_eq!(
            slice_to_hex(&out1),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            slice_to_hex(&out2),
            "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
        );
    }

    // SHA-384 Test Vectors

    #[test]
    fn test_sha384_context_single_update() {
        let mut ctx = Sha384Context::new();
        ctx.update(b"abc");
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        assert_eq!(
            slice_to_hex(&out),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn test_sha384_context_multiple_updates() {
        let mut ctx = Sha384Context::new();
        ctx.update(b"abcdefghbcdefghicdefghijdefghijk");
        ctx.update(b"efghijklfghijklmghijklmnhijklmno");
        ctx.update(b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        assert_eq!(
            slice_to_hex(&out),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        );
    }

    #[test]
    fn test_hash_provider_sha256() {
        let provider = AppleHashProvider;
        let mut ctx = provider.create_hash(HashAlgorithm::SHA256);
        ctx.update(b"abc");
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        assert_eq!(
            slice_to_hex(&out),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_hash_provider_sha384() {
        let provider = AppleHashProvider;
        let mut ctx = provider.create_hash(HashAlgorithm::SHA384);
        ctx.update(b"abc");
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        assert_eq!(
            slice_to_hex(&out),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }
}
