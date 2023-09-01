use std::fmt;
use std::ops::Deref;
use std::str::from_utf8;

use serde::{Deserialize, Serialize};

use rand::random;

use crate::io::Id;

macro_rules! str_id {
    ($id:ident, $name:literal, $num:tt, $new_len:tt) => {
        impl $id {
            /// Creates a new random id.
            pub fn new() -> $id {
                let mut arr = Id::<$num>::random().into_array();
                for i in $new_len..$num {
                    arr[i] = b' ';
                }
                $id(arr)
            }

            /// Converts an array of bytes to an id.
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
        impl $id {
            /// Creates a new random id.
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

/// Media identifier.
///
/// In SDP this is found per m-line with the attribute `a=mid:<mid>`.
///
/// When using Direct API we still need `Mid`, since they group individual
/// encoded streams. For example a simulcast of 3 layers would have
/// 3 incoming StreamRx, but since they belong to the same media,
/// the have the same `Mid`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Mid([u8; 16]);
str_id!(Mid, "Mid", 16, 3);

/// Identifier of a simulcast layer for an encoded stream.
///
/// The abbreviation means "RTP Stream Id", which is a very confusing name, because
/// everything in RTP is a stream. People tend to just call it "rid".
///
/// In SDP this is an optional value that will be seen in [`MediaData`][crate::media::MediaData]
/// if the remote peer is configured for simulcast.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rid([u8; 8]);
str_id!(Rid, "Rid", 8, 3);

/// Synchronization source.
///
/// Uniquely identifies a sending source of data. Each video/audio stream would be associated
/// with at least one synchronization source. Multiple sources for the same stream happens
/// for RTX (resend) and simulcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ssrc(u32);
num_id!(Ssrc, u32);

/// Paylad type.
///
/// The payload type identifies which codec and format parameters a stream is sent with.
/// The mappings of Pt-Codec + parameters is negotiated in SDP OFFER/ANSWER.
///
/// PTs in RTP headers are 7 bits. Values >=128 are not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Pt(u8);
num_id!(Pt, u8);

/// Identifier of an SDP session.
///
/// This value is rarely interesting, but is part of the SDP OFFER and ANSWER.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SessionId(u64);
num_id!(SessionId, u64);

/// Sequence number of an RTP packet.
///
/// An RTP packet is identified by: SSRC + SeqNo. However in the RTP header the sequence number
/// is a `u16`, meaning the value quite quickly "rolls over". To uniquely identify a packet,
/// str0m keeps track of the roll overs and converts the `u16` to `u64` in this `SeqNo`.
///
/// To get the RTP u16 value from a `SeqNo`, use `as_u16()` or cast it to u16.
///
/// ```
/// # use str0m::rtp::SeqNo;
/// let seq_no: SeqNo = 65_537.into();
///
/// // Use `as_u16()`.
/// let a = seq_no.as_u16();
/// // Discard upper 48 bits to get RTP u16.
/// let b = *seq_no as u16;
///
/// assert_eq!(a, 1);
/// assert_eq!(b, 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SeqNo(u64);
num_id!(SeqNo, u64);

impl SeqNo {
    pub(crate) const MAX: SeqNo = SeqNo(u64::MAX);

    /// Check if the `other` sequence number is directly following this.
    #[inline(always)]
    pub fn is_next(&self, other: SeqNo) -> bool {
        if **self >= *other {
            return false;
        }
        *other - **self == 1
    }

    /// Increase (mutate) this sequence number and return the previous value.
    #[inline(always)]
    pub fn inc(&mut self) -> SeqNo {
        let n = SeqNo(self.0);
        self.0 += 1;
        n
    }

    #[inline(always)]
    pub(crate) fn is_max(&self) -> bool {
        self.0 == Self::MAX.0
    }

    /// The RTP header value (discarding the ROC).
    ///
    /// This is the same as discarding the top 48 bits by casting to a u16.
    ///
    /// ```
    /// # use str0m::rtp::SeqNo;
    /// let seq_no: SeqNo = 65_537.into();
    ///
    /// // Use `as_u16()`.
    /// let a = seq_no.as_u16();
    ///
    /// assert_eq!(a, 1);
    /// ```
    #[inline(always)]
    pub fn as_u16(&self) -> u16 {
        self.0 as u16
    }

    /// Get the rollover counter (ROC) value.
    ///
    /// ```
    /// # use str0m::rtp::SeqNo;
    /// // More than 2^16, thus rolled over.
    /// let seq_no: SeqNo = 95_000.into();
    ///
    /// assert_eq!(seq_no.roc(), 1);
    ///
    /// // Is the same as shifting 16 bits.
    /// assert_eq!(seq_no.roc(), 95_000 >> 16);
    /// ```
    #[inline(always)]
    pub fn roc(&self) -> u64 {
        self.0 >> 16
    }
}

impl Pt {
    /// Create a PT with a specific value.
    ///
    /// PTs are 7 bit. Values with 8 bits are not valid in RTP headers.
    pub const fn new_with_value(v: u8) -> Pt {
        Pt(v)
    }
}
