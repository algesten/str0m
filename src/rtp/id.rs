#![allow(missing_docs)]

use std::fmt;
use std::ops::Deref;
use std::str::from_utf8;

use serde::{Deserialize, Serialize};

use rand::random;

use crate::io::Id;

macro_rules! str_id {
    ($id:ident, $name:literal, $num:tt) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $id([u8; $num]);

        impl $id {
            pub fn new() -> $id {
                $id(Id::random().into_array())
            }

            pub const fn from_array(a: [u8; $num]) -> $id {
                $id(a)
            }
        }

        impl fmt::Display for $id {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let s: &str = self;
                write!(f, "{}", s)
            }
        }

        impl fmt::Debug for $id {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let s: &str = self;
                write!(f, "{}({})", $name, s)
            }
        }

        impl Deref for $id {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                from_utf8(&self.0).expect("ascii id").trim()
            }
        }

        impl<'a> From<&'a str> for $id {
            fn from(v: &'a str) -> Self {
                let v = v
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                    .collect::<String>();

                let bytes = v.as_bytes();
                let bytes = &bytes[0..$num.min(bytes.len())];

                // pad with space.
                let mut array = [b' '; $num];

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
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

str_id!(Mid, "Mid", 3);
str_id!(Rid, "Rid", 8);
num_id!(Ssrc, u32);
num_id!(Pt, u8);
num_id!(SessionId, u64);
num_id!(SeqNo, u64);

impl SeqNo {
    pub fn is_next(&self, other: SeqNo) -> bool {
        if **self >= *other {
            return false;
        }
        *other - **self == 1
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}
