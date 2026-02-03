//! Utility types shared across str0m crates.

use std::fmt;

/// A wrapper type for personally identifiable information (PII) that redacts
/// the inner value when formatting in debug/display mode (unless the "pii" feature is enabled).
pub struct Pii<T>(pub T);

impl<T: fmt::Debug> fmt::Debug for Pii<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "pii")]
        {
            self.0.fmt(f)
        }
        #[cfg(not(feature = "pii"))]
        {
            write!(f, "[REDACTED]")
        }
    }
}

impl<T: fmt::Display> fmt::Display for Pii<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "pii")]
        {
            self.0.fmt(f)
        }
        #[cfg(not(feature = "pii"))]
        {
            write!(f, "[REDACTED]")
        }
    }
}

/// Non-cryptographic random number generator using fastrand.
pub struct NonCryptographicRng;

impl NonCryptographicRng {
    #[inline(always)]
    pub fn u8() -> u8 {
        fastrand::u8(..)
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub fn u16() -> u16 {
        fastrand::u16(..)
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub fn u32() -> u32 {
        fastrand::u32(..)
    }

    #[inline(always)]
    pub fn u64() -> u64 {
        fastrand::u64(..)
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub fn f32() -> f32 {
        fastrand::f32()
    }
}
