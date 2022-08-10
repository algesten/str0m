use std::fmt;
use std::ops::Deref;
use std::str::from_utf8_unchecked;

use net::Id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mid([u8; 3]);

impl Mid {
    pub fn new() -> Mid {
        Mid(Id::random().into_array())
    }
}

impl fmt::Display for Mid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &str = self;
        write!(f, "{}", s)
    }
}

impl Deref for Mid {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        // SAFETY: We know the mid is ascii alphanumeric
        unsafe { from_utf8_unchecked(&self.0) }.trim()
    }
}

impl<'a> From<&'a str> for Mid {
    fn from(v: &'a str) -> Self {
        assert!(v.chars().all(|c| c.is_ascii_alphanumeric()));
        let bytes = v.as_bytes();
        assert!(bytes.len() <= 3);

        // pad with space.
        let mut array = [b' '; 3];

        let max = bytes.len().min(array.len());
        (&mut array[0..max]).copy_from_slice(bytes);

        Mid(array)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ssrc(u32);

impl Deref for Ssrc {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u32> for Ssrc {
    fn from(v: u32) -> Self {
        Ssrc(v)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CName([u8; 64]);

impl CName {
    pub fn new() -> Self {
        CName(Id::random().into_array())
    }
}

impl fmt::Display for CName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &str = self;
        write!(f, "{}", s)
    }
}

impl Deref for CName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        // SAFETY: We know the mid is ascii alphanumeric
        unsafe { from_utf8_unchecked(&self.0) }.trim()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pt(u8);

impl Deref for Pt {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u8> for Pt {
    fn from(v: u8) -> Self {
        Pt(v)
    }
}

impl fmt::Display for Pt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
