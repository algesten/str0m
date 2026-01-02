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
    fn test_sha256_empty() {
        let result = sha256(b"");
        assert_eq!(
            slice_to_hex(&result),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let result = sha256(b"abc");
        assert_eq!(
            slice_to_hex(&result),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_longer() {
        let result = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            slice_to_hex(&result),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

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
    fn test_sha384_empty() {
        let result = sha384(b"");
        assert_eq!(
            slice_to_hex(&result),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn test_sha384_abc() {
        let result = sha384(b"abc");
        assert_eq!(
            slice_to_hex(&result),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn test_sha384_longer() {
        let result = sha384(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(
            slice_to_hex(&result),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        );
    }

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
