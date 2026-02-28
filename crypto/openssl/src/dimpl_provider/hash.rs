//! Hash implementations using OpenSSL.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, HashContext, HashProvider};

use openssl::hash::{Hasher, MessageDigest};

#[derive(Debug)]
pub(super) struct OsslHashProvider;

impl HashProvider for OsslHashProvider {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn HashContext> {
        match algorithm {
            HashAlgorithm::SHA256 => Box::new(OsslHashContext::new(MessageDigest::sha256())),
            HashAlgorithm::SHA384 => Box::new(OsslHashContext::new(MessageDigest::sha384())),
            _ => panic!("Unsupported hash algorithm: {algorithm:?}"),
        }
    }
}

pub(super) static HASH_PROVIDER: OsslHashProvider = OsslHashProvider;

struct OsslHashContext {
    digest: MessageDigest,
    /// Accumulated data for `clone_and_finalize` support.
    ///
    /// OpenSSL's `Hasher` doesn't expose `EVP_MD_CTX_copy_ex` for cloning,
    /// so we replay all data into a fresh hasher on each `clone_and_finalize` call.
    /// This is O(n) in accumulated data size, but acceptable since DTLS handshake
    /// transcripts are bounded (typically a few KB).
    data: Vec<u8>,
}

impl std::fmt::Debug for OsslHashContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslHashContext").finish_non_exhaustive()
    }
}

impl OsslHashContext {
    fn new(digest: MessageDigest) -> Self {
        Self {
            digest,
            data: Vec::new(),
        }
    }
}

impl HashContext for OsslHashContext {
    fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        // Create a new hasher, replay all data, and finalize
        let mut hasher = Hasher::new(self.digest).expect("Hasher::new");
        hasher.update(&self.data).expect("hasher update");
        let digest = hasher.finish().expect("hasher finish");
        out.clear();
        out.extend_from_slice(&digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dimpl_provider::test_utils::to_hex;

    #[test]
    fn sha256_single_update() {
        let mut ctx = OsslHashContext::new(MessageDigest::sha256());
        ctx.update(b"abc");
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        assert_eq!(
            to_hex(&out),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_multiple_updates() {
        let mut ctx = OsslHashContext::new(MessageDigest::sha256());
        ctx.update(b"abcdbcde");
        ctx.update(b"cdefdefg");
        ctx.update(b"efghfghighijhijkijkljklmklmnlmnomnopnopq");
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        assert_eq!(
            to_hex(&out),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_clone_and_finalize_does_not_consume_state() {
        let mut ctx = OsslHashContext::new(MessageDigest::sha256());
        ctx.update(b"abc");
        let mut out1 = Buf::new();
        ctx.clone_and_finalize(&mut out1);

        // Continue updating after first finalize
        ctx.update(b"def");
        let mut out2 = Buf::new();
        ctx.clone_and_finalize(&mut out2);

        // First snapshot should be SHA-256("abc")
        assert_eq!(
            to_hex(&out1),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Second snapshot should be SHA-256("abcdef")
        assert_eq!(
            to_hex(&out2),
            "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
        );
    }

    #[test]
    fn sha384_single_update() {
        let mut ctx = OsslHashContext::new(MessageDigest::sha384());
        ctx.update(b"abc");
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        assert_eq!(
            to_hex(&out),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }
}
