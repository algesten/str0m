use std::error::Error;
use std::fmt;

/// Errors arising in packet- and depacketization.
#[derive(Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PacketError {
    ErrShortPacket,
    ErrTooManySpatialLayers,
    ErrTooManyPDiff,
    ErrH265CorruptedPacket,
    ErrInvalidH265PacketType,
    StapASizeLargerThanBuffer(usize, usize),
    NaluTypeIsNotHandled(u8),
    ErrVP9CorruptedPacket,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::ErrShortPacket => write!(f, "Packet is too short"),
            PacketError::ErrTooManySpatialLayers => write!(f, "Too many spatial layers"),
            PacketError::ErrTooManyPDiff => write!(f, "Too many P-Diff"),
            PacketError::ErrH265CorruptedPacket => write!(f, "H265 corrupted packet"),
            PacketError::ErrInvalidH265PacketType => write!(f, "H265 invalid packet type"),
            PacketError::StapASizeLargerThanBuffer(size, buffer) => write!(
                f,
                "H264 StapA size larger than buffer: {} > {}",
                size, buffer
            ),
            PacketError::NaluTypeIsNotHandled(nalu_type) => {
                write!(f, "H264 NALU type is not handled: {}", nalu_type)
            }
            PacketError::ErrVP9CorruptedPacket => write!(f, "VP9 corrupted packet"),
        }
    }
}

impl Error for PacketError {}
