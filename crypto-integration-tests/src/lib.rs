//! Crypto Integration Tests
//!
//! This crate contains integration tests that verify the full WebRTC stack
//! works correctly with platform-specific crypto providers.
//!
//! The tests automatically select the appropriate crypto provider based on
//! the target platform:
//! - macOS/iOS: str0m-apple-crypto
//! - Windows: str0m-wincrypto (TODO)
//! - Linux/other: OpenSSL (TODO)
//!
//! This crate is never published - it exists only for testing.

// This crate has no library code, only tests
