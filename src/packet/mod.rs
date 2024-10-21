#![allow(clippy::type_complexity)]

use std::fmt;
use std::panic::UnwindSafe;
use thiserror::Error;

use crate::format::Codec;
use crate::sdp::MediaType;

mod g7xx;
use g7xx::{G711Packetizer, G722Packetizer};

mod h264;
pub use h264::H264CodecExtra;
use h264::{H264Depacketizer, H264Packetizer};

mod h264_profile;
pub(crate) use h264_profile::H264ProfileLevel;

mod h265;
use h265::H265Depacketizer;

mod opus;
use opus::{OpusDepacketizer, OpusPacketizer};

mod vp8;
pub use vp8::Vp8CodecExtra;
use vp8::{Vp8Depacketizer, Vp8Packetizer};

mod vp9;
pub use vp9::Vp9CodecExtra;
use vp9::{Vp9Depacketizer, Vp9Packetizer};

mod null;
use null::{NullDepacketizer, NullPacketizer};

mod buffer_rx;
pub(crate) use buffer_rx::{DepacketizingBuffer, RtpMeta};
mod contiguity;
mod contiguity_vp8;
mod contiguity_vp9;

mod payload;
pub(crate) use payload::Payloader;

mod bwe;
pub(crate) use bwe::SendSideBandwithEstimator;

mod pacer;
pub(crate) use pacer::{LeakyBucketPacer, NullPacer, Pacer, PacerImpl};
pub(crate) use pacer::{QueuePriority, QueueSnapshot, QueueState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Types of media.
pub enum MediaKind {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
}

impl MediaKind {
    /// Tests if this is `MediaKind::Audio`
    pub fn is_audio(&self) -> bool {
        *self == MediaKind::Audio
    }

    /// Tests if this is `MediaKind::Video`
    pub fn is_video(&self) -> bool {
        *self == MediaKind::Video
    }
}

/// Packetizes some bytes for use as RTP packet.
pub(crate) trait Packetizer: fmt::Debug {
    /// Chunk the data up into RTP packets.
    fn packetize(&mut self, mtu: usize, b: &[u8]) -> Result<Vec<Vec<u8>>, PacketError>;

    fn is_marker(&mut self, data: &[u8], previous: Option<&[u8]>, last: bool) -> bool;
}

/// Codec specific information
///
/// Contains additional codec specific information which are deemed useful for
/// managing and repackaging the sample
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecExtra {
    /// No extra information available
    None,
    /// Codec extra parameters for VP8.
    Vp8(Vp8CodecExtra),
    /// Codec extra parameters for VP9.
    Vp9(Vp9CodecExtra),
    /// Codec extra parameters for H264.
    H264(H264CodecExtra),
}

/// Depacketizes an RTP payload.
///
/// Removes any RTP specific data from the payload.
pub(crate) trait Depacketizer: fmt::Debug {
    /// Unpack the RTP packet into a provided `Vec<u8>`.
    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
        codec_extra: &mut CodecExtra,
    ) -> Result<(), PacketError>;

    /// Checks if the packet is at the beginning of a partition.
    ///
    /// Returns false if the result could not be determined.
    fn is_partition_head(&self, packet: &[u8]) -> bool;

    /// Checks if the packet is at the end of a partition.
    ///
    /// Returns false if the result could not be determined.
    fn is_partition_tail(&self, marker: bool, packet: &[u8]) -> bool;
}

/// Errors arising in packet- and depacketization.
#[derive(Debug, Error, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PacketError {
    #[error("Packet is too short")]
    ErrShortPacket,
    #[error("Too many spatial layers")]
    ErrTooManySpatialLayers,
    #[error("Too many P-Diff")]
    ErrTooManyPDiff,
    #[error("H265 corrupted packet")]
    ErrH265CorruptedPacket,
    #[error("H265 invalid packet type")]
    ErrInvalidH265PacketType,
    #[error("H264 StapA size larger than buffer: {0} > {1}")]
    StapASizeLargerThanBuffer(usize, usize),
    #[error("H264 NALU type is not handled: {0}")]
    NaluTypeIsNotHandled(u8),
    #[error("VP9 corrupted packet")]
    ErrVP9CorruptedPacket,
}

/// Helper to replace Bytes. Provides get_u8 and get_u16 over some buffer of bytes.
pub(crate) trait BitRead {
    fn remaining(&self) -> usize;
    fn get_u8(&mut self) -> Option<u8>;
    fn get_u16(&mut self) -> Option<u16>;
}

impl BitRead for (&[u8], usize) {
    #[inline(always)]
    fn remaining(&self) -> usize {
        (self.0.len() * 8).saturating_sub(self.1)
    }

    #[inline(always)]
    fn get_u8(&mut self) -> Option<u8> {
        if self.remaining() < 8 {
            return None;
        }

        let offs = self.1 / 8;
        let shift = (self.1 % 8) as u32;
        self.1 += 8;

        let mut n = self.0[offs];

        if shift > 0 {
            n <<= shift;
            n |= self.0[offs + 1] >> (8 - shift)
        }

        Some(n)
    }

    fn get_u16(&mut self) -> Option<u16> {
        if self.remaining() < 16 {
            return None;
        }
        Some(u16::from_be_bytes([self.get_u8()?, self.get_u8()?]))
    }
}

#[derive(Debug)]
pub(crate) enum CodecPacketizer {
    #[allow(unused)]
    G711(G711Packetizer),
    #[allow(unused)]
    G722(G722Packetizer),
    H264(H264Packetizer),
    // H265() TODO
    Opus(OpusPacketizer),
    Vp8(Vp8Packetizer),
    Vp9(Vp9Packetizer),
    Null(NullPacketizer),
    #[allow(unused)]
    Boxed(Box<dyn Packetizer + Send + Sync + UnwindSafe>),
}

#[derive(Debug)]
pub(crate) enum CodecDepacketizer {
    H264(H264Depacketizer),
    H265(H265Depacketizer),
    Opus(OpusDepacketizer),
    Vp8(Vp8Depacketizer),
    Vp9(Vp9Depacketizer),
    Null(NullDepacketizer),
    #[allow(unused)]
    Boxed(Box<dyn Depacketizer + Send + Sync + UnwindSafe>),
}

impl From<Codec> for CodecPacketizer {
    fn from(c: Codec) -> Self {
        match c {
            Codec::Opus => CodecPacketizer::Opus(OpusPacketizer),
            Codec::H264 => CodecPacketizer::H264(H264Packetizer::default()),
            Codec::H265 => unimplemented!("Missing packetizer for H265"),
            Codec::Vp8 => CodecPacketizer::Vp8(Vp8Packetizer::default()),
            Codec::Vp9 => CodecPacketizer::Vp9(Vp9Packetizer::default()),
            Codec::Av1 => unimplemented!("Missing packetizer for AV1"),
            Codec::Null => CodecPacketizer::Null(NullPacketizer),
            Codec::Rtx => panic!("Cant instantiate packetizer for RTX codec"),
            Codec::Unknown => panic!("Cant instantiate packetizer for unknown codec"),
        }
    }
}

impl From<Codec> for CodecDepacketizer {
    fn from(c: Codec) -> Self {
        match c {
            Codec::Opus => CodecDepacketizer::Opus(OpusDepacketizer),
            Codec::H264 => CodecDepacketizer::H264(H264Depacketizer::default()),
            Codec::H265 => CodecDepacketizer::H265(H265Depacketizer::default()),
            Codec::Vp8 => CodecDepacketizer::Vp8(Vp8Depacketizer::default()),
            Codec::Vp9 => CodecDepacketizer::Vp9(Vp9Depacketizer::default()),
            Codec::Av1 => unimplemented!("Missing depacketizer for AV1"),
            Codec::Null => CodecDepacketizer::Null(NullDepacketizer),
            Codec::Rtx => panic!("Cant instantiate depacketizer for RTX codec"),
            Codec::Unknown => panic!("Cant instantiate depacketizer for unknown codec"),
        }
    }
}

impl Packetizer for CodecPacketizer {
    fn packetize(&mut self, mtu: usize, b: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        use CodecPacketizer::*;
        match self {
            G711(v) => v.packetize(mtu, b),
            G722(v) => v.packetize(mtu, b),
            H264(v) => v.packetize(mtu, b),
            Opus(v) => v.packetize(mtu, b),
            Vp8(v) => v.packetize(mtu, b),
            Vp9(v) => v.packetize(mtu, b),
            Null(v) => v.packetize(mtu, b),
            Boxed(v) => v.packetize(mtu, b),
        }
    }

    fn is_marker(&mut self, data: &[u8], previous: Option<&[u8]>, last: bool) -> bool {
        match self {
            CodecPacketizer::G711(v) => v.is_marker(data, previous, last),
            CodecPacketizer::G722(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Opus(v) => v.is_marker(data, previous, last),
            CodecPacketizer::H264(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Vp8(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Vp9(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Null(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Boxed(v) => v.is_marker(data, previous, last),
        }
    }
}

impl Depacketizer for CodecDepacketizer {
    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
        extra: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        use CodecDepacketizer::*;
        match self {
            H264(v) => v.depacketize(packet, out, extra),
            H265(v) => v.depacketize(packet, out, extra),
            Opus(v) => v.depacketize(packet, out, extra),
            Vp8(v) => v.depacketize(packet, out, extra),
            Vp9(v) => v.depacketize(packet, out, extra),
            Null(v) => v.depacketize(packet, out, extra),
            Boxed(v) => v.depacketize(packet, out, extra),
        }
    }

    fn is_partition_head(&self, packet: &[u8]) -> bool {
        use CodecDepacketizer::*;
        match self {
            H264(v) => v.is_partition_head(packet),
            H265(v) => v.is_partition_head(packet),
            Opus(v) => v.is_partition_head(packet),
            Vp8(v) => v.is_partition_head(packet),
            Vp9(v) => v.is_partition_head(packet),
            Null(v) => v.is_partition_head(packet),
            Boxed(v) => v.is_partition_head(packet),
        }
    }

    fn is_partition_tail(&self, marker: bool, packet: &[u8]) -> bool {
        use CodecDepacketizer::*;
        match self {
            H264(v) => v.is_partition_tail(marker, packet),
            H265(v) => v.is_partition_tail(marker, packet),
            Opus(v) => v.is_partition_tail(marker, packet),
            Vp8(v) => v.is_partition_tail(marker, packet),
            Vp9(v) => v.is_partition_tail(marker, packet),
            Null(v) => v.is_partition_tail(marker, packet),
            Boxed(v) => v.is_partition_tail(marker, packet),
        }
    }
}

impl From<MediaType> for MediaKind {
    fn from(v: MediaType) -> Self {
        match v {
            MediaType::Audio => MediaKind::Audio,
            MediaType::Video => MediaKind::Video,
            _ => panic!("Not MediaType::Audio or Video"),
        }
    }
}

impl fmt::Display for MediaKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaKind::Audio => write!(f, "audio"),
            MediaKind::Video => write!(f, "video"),
        }
    }
}
