//! The random source behind sctp-proto's verification tags, initial TSNs and state cookies.
//!
//! sctp-proto holds a single random fill for the whole process (`sctp_proto::set_fill`). str0m
//! installs it from the [`SecureRandom`] of the first crypto provider that has one. Without one,
//! sctp-proto falls back to its own RNG when the `sctp-rand` feature is on, and panics on a draw
//! when it is off.

use std::sync::OnceLock;

use crate::crypto::{CryptoError, CryptoProvider, SecureRandom};

/// The random source sctp-proto draws from, once installed.
static SECURE_RANDOM: OnceLock<&'static dyn SecureRandom> = OnceLock::new();

/// Point sctp-proto at `random`. Does nothing if `random` is `None` or a source is already installed.
pub(crate) fn install(random: Option<&'static dyn SecureRandom>) {
    let Some(random) = random else {
        return;
    };
    if SECURE_RANDOM.set(random).is_ok() {
        // Returns false if the application installed its own fill first, which then stays.
        let _ = sctp_proto::set_fill(fill);
    }
}

/// Point sctp-proto at the random source of the process default crypto provider, or of the one
/// selected by feature flags, unless a source is already installed.
pub(crate) fn install_default() {
    if SECURE_RANDOM.get().is_some() {
        return;
    }

    if let Some(provider) = CryptoProvider::get_default() {
        install(provider.secure_random);
    } else {
        install_from_feature_flags();
    }
}

#[cfg(any(
    feature = "aws-lc-rs",
    feature = "rust-crypto",
    feature = "openssl",
    feature = "openssl-dimpl",
    all(feature = "apple-crypto", target_vendor = "apple"),
    all(feature = "wincrypto", target_os = "windows")
))]
fn install_from_feature_flags() {
    install(crate::crypto::from_feature_flags().secure_random);
}

/// No crypto backend is compiled in: leave sctp-proto on its own fallback.
#[cfg(not(any(
    feature = "aws-lc-rs",
    feature = "rust-crypto",
    feature = "openssl",
    feature = "openssl-dimpl",
    all(feature = "apple-crypto", target_vendor = "apple"),
    all(feature = "wincrypto", target_os = "windows")
)))]
fn install_from_feature_flags() {}

/// Check that `random` produces bytes, so a failing source refuses SCTP setup up front
/// instead of failing inside an sctp-proto draw.
pub(crate) fn check(random: Option<&'static dyn SecureRandom>) -> Result<(), CryptoError> {
    if let Some(random) = random {
        random.fill(&mut [0; 4])?;
    }
    Ok(())
}

/// The fill installed into sctp-proto. sctp-proto has no way to report an error from a draw,
/// so a failure here panics.
fn fill(buf: &mut [u8]) {
    let random = SECURE_RANDOM
        .get()
        .expect("SCTP random source installed before the fill");
    if let Err(e) = random.fill(buf) {
        panic!("SCTP random fill failed: {e}");
    }
}
