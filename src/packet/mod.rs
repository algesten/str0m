#![allow(clippy::type_complexity)]

use std::fmt;
use std::panic::UnwindSafe;

use crate::format::Codec;
use crate::sdp::MediaType;

use crate::rtp::vla::encode_leb_u63;

mod av1;
pub use av1::Av1CodecExtra;
use av1::{Av1Depacketizer, Av1Packetizer};

mod g7xx;
use g7xx::{G711Depacketizer, G711Packetizer, G722Packetizer};

mod h264;
pub use h264::H264CodecExtra;
pub use h264::{H264Depacketizer, H264Packetizer};

mod h264_profile;
pub(crate) use h264_profile::H264ProfileLevel;

mod h265;
pub use h265::H265CodecExtra;
use h265::H265Depacketizer;
pub use h265::H265Packetizer;

mod h265_profile;
pub(crate) use h265_profile::H265ProfileTierLevel;

mod opus;
pub use opus::{OpusDepacketizer, OpusPacketizer};

mod vp8;
pub use vp8::Vp8CodecExtra;
pub use vp8::{Vp8Depacketizer, Vp8Packetizer};

mod vp9;
pub use vp9::Vp9CodecExtra;
pub use vp9::Vp9PacketizerMode;
use vp9::{Vp9Depacketizer, Vp9Packetizer};

mod null;
use null::{NullDepacketizer, NullPacketizer};

mod buffer_rx;
pub(crate) use buffer_rx::{DepacketizingBuffer, RtpMeta};

mod contiguity;
mod contiguity_vp8;
mod contiguity_vp9;
mod error;

mod payload;
pub(crate) use payload::Payloader;

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
///
/// ## Unversioned API surface
///
/// This trait is not currently versioned according to semver rules.
/// Breaking changes may be made in minor or patch releases.
pub trait Packetizer: fmt::Debug {
    /// Chunk the data up into RTP packets.
    fn packetize(&mut self, mtu: usize, b: &[u8]) -> Result<Vec<Vec<u8>>, PacketError>;

    /// Tell if this is the last packet of a frame.
    fn is_marker(&mut self, data: &[u8], previous: Option<&[u8]>, last: bool) -> bool;
}

/// Codec specific information
///
/// Contains additional codec specific information which are deemed useful for
/// managing and repackaging the frame
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecExtra {
    /// No extra information available
    None,
    /// Codec extra parameters for VP8.
    Vp8(Vp8CodecExtra),
    /// Codec extra parameters for VP9.
    Vp9(Vp9CodecExtra),
    /// Codec extra parameters for H264.
    H264(H264CodecExtra),
    /// Codec extra parameters for AV1,
    Av1(Av1CodecExtra),
    /// Codec extra parameters for H265.
    H265(H265CodecExtra),
}

/// Depacketizes an RTP payload.
///
/// Removes any RTP specific data from the payload.
///
/// ## Unversioned API surface
///
/// This trait is not currently versioned according to semver rules.
/// Breaking changes may be made in minor or patch releases.
pub trait Depacketizer: fmt::Debug {
    /// Provide a size hint for the `out: &mut Vec<u8>` parameter in [`Depacketizer::depacketize`].
    /// The [`packets_size`] parameter is the sum of the size of all packets that will be processed in
    /// subsequent calls to [`Depacketizer::depacketize`].
    /// This is used to allocate the vector with upfront capacity.
    /// Return [`None`] if it cannot be determined.
    fn out_size_hint(&self, packets_size: usize) -> Option<usize>;

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

pub use error::PacketError;

/// Helper to replace Bytes. Provides get_u8 and get_u16 over some buffer of bytes.
pub(crate) trait BitRead {
    fn remaining(&self) -> usize;
    fn remaining_bytes(&self) -> usize;
    fn get_offset(&self) -> usize;
    fn get_u8(&mut self) -> Option<u8>;
    fn get_u16(&mut self) -> Option<u16>;
    fn get_remaining(&mut self) -> Vec<u8>;
    fn get_bytes(&mut self, size: usize) -> Option<Vec<u8>>;
    fn get_variant(&mut self) -> Option<usize>;
    fn consume(&mut self, bytes: usize);
}

impl BitRead for (&[u8], usize) {
    #[inline(always)]
    fn remaining(&self) -> usize {
        (self.0.len() * 8).saturating_sub(self.1)
    }

    #[inline(always)]
    fn remaining_bytes(&self) -> usize {
        self.remaining() / 8
    }

    #[inline(always)]
    fn get_offset(&self) -> usize {
        self.1 / 8
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

    fn get_remaining(&mut self) -> Vec<u8> {
        let mut remaining = Vec::new();
        while self.remaining() > 7 {
            remaining.push(self.get_u8().unwrap());
        }

        remaining
    }

    fn get_bytes(&mut self, size: usize) -> Option<Vec<u8>> {
        if self.remaining() < (size * 8) {
            return None;
        }

        let mut bytes = Vec::new();
        while bytes.len() < size {
            bytes.push(self.get_u8().unwrap());
        }

        Some(bytes)
    }

    fn get_variant(&mut self) -> Option<usize> {
        let mut temp_value: usize = 0;

        for i in (0..64).step_by(7) {
            if self.remaining() < 8 {
                return None;
            }
            let byte = self.get_u8().unwrap();
            temp_value |= ((byte & 0x7f) as usize) << i;

            if byte < 0x80 {
                return Some(temp_value);
            }
        }

        None
    }

    fn consume(&mut self, bytes: usize) {
        if self.remaining() < bytes * 8 {
            return;
        }

        self.1 += bytes * 8;
    }
}

#[derive(Debug)]
pub(crate) enum CodecPacketizer {
    #[allow(unused)]
    G711(G711Packetizer),
    #[allow(unused)]
    G722(G722Packetizer),
    H264(H264Packetizer),
    H265(H265Packetizer),
    Opus(OpusPacketizer),
    Vp8(Vp8Packetizer),
    Vp9(Vp9Packetizer),
    Av1(Av1Packetizer),
    Null(NullPacketizer),
    #[allow(unused)]
    Boxed(Box<dyn Packetizer + Send + Sync + UnwindSafe>),
}

#[derive(Debug)]
pub(crate) enum CodecDepacketizer {
    G711(G711Depacketizer),
    H264(H264Depacketizer),
    H265(H265Depacketizer),
    Opus(OpusDepacketizer),
    Vp8(Vp8Depacketizer),
    Vp9(Vp9Depacketizer),
    Av1(Av1Depacketizer),
    Null(NullDepacketizer),
    #[allow(unused)]
    Boxed(Box<dyn Depacketizer + Send + Sync + UnwindSafe>),
}

impl CodecPacketizer {
    pub(crate) fn new(codec: Codec, vp9_mode: Vp9PacketizerMode) -> Self {
        match codec {
            Codec::Opus => CodecPacketizer::Opus(OpusPacketizer),
            Codec::PCMU => CodecPacketizer::G711(G711Packetizer::default()),
            Codec::PCMA => CodecPacketizer::G711(G711Packetizer::default()),
            Codec::H264 => CodecPacketizer::H264(H264Packetizer::default()),
            Codec::H265 => CodecPacketizer::H265(H265Packetizer::default()),
            Codec::Vp8 => CodecPacketizer::Vp8(Vp8Packetizer::default()),
            Codec::Vp9 => CodecPacketizer::Vp9(Vp9Packetizer::with_mode(vp9_mode)),
            Codec::Av1 => CodecPacketizer::Av1(Av1Packetizer::default()),
            Codec::Null => CodecPacketizer::Null(NullPacketizer),
            Codec::Rtx => panic!("Cant instantiate packetizer for RTX codec"),
            Codec::Unknown => panic!("Cant instantiate packetizer for unknown codec"),
        }
    }
}

impl From<Codec> for CodecPacketizer {
    fn from(c: Codec) -> Self {
        CodecPacketizer::new(c, Vp9PacketizerMode::default())
    }
}

impl From<Codec> for CodecDepacketizer {
    fn from(c: Codec) -> Self {
        match c {
            Codec::Opus => CodecDepacketizer::Opus(OpusDepacketizer),
            Codec::PCMU => CodecDepacketizer::G711(G711Depacketizer),
            Codec::PCMA => CodecDepacketizer::G711(G711Depacketizer),
            Codec::H264 => CodecDepacketizer::H264(H264Depacketizer::default()),
            Codec::H265 => CodecDepacketizer::H265(H265Depacketizer::default()),
            Codec::Vp8 => CodecDepacketizer::Vp8(Vp8Depacketizer::default()),
            Codec::Vp9 => CodecDepacketizer::Vp9(Vp9Depacketizer::default()),
            Codec::Av1 => CodecDepacketizer::Av1(Av1Depacketizer::default()),
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
            H265(v) => v.packetize(mtu, b),
            Opus(v) => v.packetize(mtu, b),
            Vp8(v) => v.packetize(mtu, b),
            Vp9(v) => v.packetize(mtu, b),
            Av1(v) => v.packetize(mtu, b),
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
            CodecPacketizer::H265(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Vp8(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Vp9(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Av1(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Null(v) => v.is_marker(data, previous, last),
            CodecPacketizer::Boxed(v) => v.is_marker(data, previous, last),
        }
    }
}

impl Depacketizer for CodecDepacketizer {
    fn out_size_hint(&self, packets_size: usize) -> Option<usize> {
        use CodecDepacketizer::*;
        match self {
            H264(v) => v.out_size_hint(packets_size),
            H265(v) => v.out_size_hint(packets_size),
            Opus(v) => v.out_size_hint(packets_size),
            G711(v) => v.out_size_hint(packets_size),
            Vp8(v) => v.out_size_hint(packets_size),
            Vp9(v) => v.out_size_hint(packets_size),
            Av1(v) => v.out_size_hint(packets_size),
            Null(v) => v.out_size_hint(packets_size),
            Boxed(v) => v.out_size_hint(packets_size),
        }
    }

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
            G711(v) => v.depacketize(packet, out, extra),
            Vp8(v) => v.depacketize(packet, out, extra),
            Vp9(v) => v.depacketize(packet, out, extra),
            Av1(v) => v.depacketize(packet, out, extra),
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
            G711(v) => v.is_partition_head(packet),
            Vp8(v) => v.is_partition_head(packet),
            Vp9(v) => v.is_partition_head(packet),
            Av1(v) => v.is_partition_head(packet),
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
            G711(v) => v.is_partition_tail(marker, packet),
            Vp8(v) => v.is_partition_tail(marker, packet),
            Vp9(v) => v.is_partition_tail(marker, packet),
            Av1(v) => v.is_partition_tail(marker, packet),
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
