//! Hash implementations using Apple CommonCrypto.

use dimpl::buffer::Buf;
use dimpl::crypto::{HashAlgorithm, HashContext, HashProvider};

use crate::ffi::CC_LONG;
use crate::ffi::CC_SHA256_CTX;
use crate::ffi::CC_SHA256_Final;
use crate::ffi::CC_SHA256_Init;
use crate::ffi::CC_SHA256_Update;
use crate::ffi::CC_SHA384_Final;
use crate::ffi::CC_SHA384_Init;
use crate::ffi::CC_SHA384_Update;
use crate::ffi::CC_SHA512_CTX;

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

struct Sha256Context {
    ctx: CC_SHA256_CTX,
}

impl Sha256Context {
    fn new() -> Self {
        // SAFETY: zeroed memory is valid for CC_SHA256_CTX
        let mut ctx = unsafe { std::mem::zeroed() };
        // SAFETY: ctx is properly initialized zeroed memory
        unsafe { CC_SHA256_Init(&mut ctx) };
        Self { ctx }
    }
}

impl std::fmt::Debug for Sha256Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256Context").finish_non_exhaustive()
    }
}

impl HashContext for Sha256Context {
    fn update(&mut self, data: &[u8]) {
        // SAFETY: ctx is valid, data pointer and length are from valid slice
        unsafe { CC_SHA256_Update(&mut self.ctx, data.as_ptr(), data.len() as CC_LONG) };
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        let mut ctx_copy = self.ctx;
        let mut digest = [0u8; 32];
        // SAFETY: ctx_copy is valid copy, digest is properly sized buffer
        unsafe { CC_SHA256_Final(digest.as_mut_ptr(), &mut ctx_copy) };
        out.clear();
        out.extend_from_slice(&digest);
    }
}

struct Sha384Context {
    ctx: CC_SHA512_CTX,
}

impl Sha384Context {
    fn new() -> Self {
        // SAFETY: zeroed memory is valid for CC_SHA512_CTX
        let mut ctx = unsafe { std::mem::zeroed() };
        // SAFETY: ctx is properly initialized zeroed memory
        unsafe { CC_SHA384_Init(&mut ctx) };
        Self { ctx }
    }
}

impl std::fmt::Debug for Sha384Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha384Context").finish_non_exhaustive()
    }
}

impl HashContext for Sha384Context {
    fn update(&mut self, data: &[u8]) {
        // SAFETY: ctx is valid, data pointer and length are from valid slice
        unsafe { CC_SHA384_Update(&mut self.ctx, data.as_ptr(), data.len() as CC_LONG) };
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        let mut ctx_copy = self.ctx;
        let mut digest = [0u8; 48];
        // SAFETY: ctx_copy is valid copy, digest is properly sized buffer
        unsafe { CC_SHA384_Final(digest.as_mut_ptr(), &mut ctx_copy) };
        out.clear();
        out.extend_from_slice(&digest);
    }
}

/// Compute SHA-256 hash of data and return as fixed-size array.
pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut ctx = Sha256Context::new();
    ctx.update(data);
    let mut digest = [0u8; 32];
    // SAFETY: ctx is valid, digest is properly sized buffer
    unsafe { CC_SHA256_Final(digest.as_mut_ptr(), &mut ctx.ctx) };
    digest
}

/// Compute SHA-384 hash of data and return as fixed-size array.
pub(super) fn sha384(data: &[u8]) -> [u8; 48] {
    let mut ctx = Sha384Context::new();
    ctx.update(data);
    let mut digest = [0u8; 48];
    // SAFETY: ctx is valid, digest is properly sized buffer
    unsafe { CC_SHA384_Final(digest.as_mut_ptr(), &mut ctx.ctx) };
    digest
}
