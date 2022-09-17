use std::fmt;
use thiserror::Error;

pub mod g7xx;
pub mod h264;
pub mod h265;
pub mod opus;
pub mod vp8;
pub mod vp9;

/// Chunks up some bytes for use as RTP packet
pub trait Packetizer: fmt::Debug {
    /// Chunk the data up into RTP packets.
    fn packetize(&mut self, mtu: usize, b: &[u8]) -> Result<Vec<Vec<u8>>, PacketError>;
}

/// Depacketizer depacketizes a RTP payload, removing any RTP specific data from the payload
pub trait Depacketizer {
    /// Unpack the RTP packet into a provided Vec<u8>.
    fn depacketize(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), PacketError>;

    /// Checks if the packet is at the beginning of a partition.
    ///
    /// Returns false if the result could not be determined.
    fn is_partition_head(&self, packet: &[u8]) -> bool;

    /// Checks if the packet is at the end of a partition.
    ///
    /// Returns false if the result could not be determined.
    fn is_partition_tail(&self, marker: bool, packet: &[u8]) -> bool;
}

#[derive(Debug, Error, PartialEq, Eq)]
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
}

/// Helper to replace Bytes. Provides get_u8 and get_u16 over some buffer of bytes.
pub(crate) trait BitRead {
    fn remaining(&self) -> usize;
    fn get_u8(&mut self) -> u8;
    fn get_u16(&mut self) -> u16;
}

impl BitRead for (&[u8], usize) {
    #[inline(always)]
    fn remaining(&self) -> usize {
        (self.0.len() * 8).checked_sub(self.1).unwrap_or(0)
    }

    #[inline(always)]
    fn get_u8(&mut self) -> u8 {
        if self.remaining() == 0 {
            panic!("Too few bits left");
        }

        let offs = self.1 / 8;
        let shift = (self.1 % 8) as u32;
        self.1 += 8;

        let mut n = self.0[offs];

        if shift > 0 {
            n <<= shift;
            n |= self.0[offs + 1] >> (8 - shift)
        }

        n
    }

    fn get_u16(&mut self) -> u16 {
        u16::from_be_bytes([self.get_u8(), self.get_u8()])
    }
}
