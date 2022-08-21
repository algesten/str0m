use std::fmt;
use std::ops::Deref;
use std::str::from_utf8_unchecked;

use rand::random;

use net::Id;

macro_rules! str_id {
    ($id:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $id([u8; 3]);

        impl $id {
            pub fn new() -> $id {
                $id(Id::random().into_array())
            }
        }

        impl fmt::Display for $id {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let s: &str = self;
                write!(f, "{}", s)
            }
        }

        impl Deref for $id {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                // SAFETY: We know the mid is ascii alphanumeric
                unsafe { from_utf8_unchecked(&self.0) }.trim()
            }
        }

        impl<'a> From<&'a str> for $id {
            fn from(v: &'a str) -> Self {
                assert!(v.chars().all(|c| c.is_ascii_alphanumeric()));
                let bytes = v.as_bytes();
                assert!(bytes.len() <= 3);

                // pad with space.
                let mut array = [b' '; 3];

                let max = bytes.len().min(array.len());
                (&mut array[0..max]).copy_from_slice(bytes);

                $id(array)
            }
        }

        impl Default for $id {
            fn default() -> Self {
                $id::new()
            }
        }
    };
}

macro_rules! num_id {
    ($id:ident, $t:ty) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $id($t);

        impl $id {
            pub fn new() -> Self {
                $id(random())
            }
        }

        impl Deref for $id {
            type Target = $t;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl From<$t> for $id {
            fn from(v: $t) -> Self {
                $id(v)
            }
        }

        impl fmt::Display for $id {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

str_id!(Mid);
str_id!(StreamId);
num_id!(Ssrc, u32);
num_id!(Pt, u8);
num_id!(MLineIdx, usize);
num_id!(SessionId, u64);
num_id!(SeqNo, u64);
