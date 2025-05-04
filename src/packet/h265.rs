#![allow(clippy::all)]
#![allow(unused)]

use super::{CodecExtra, Depacketizer, PacketError};

///
/// Network Abstraction Unit Header implementation
///

const H265NALU_HEADER_SIZE: usize = 2;
/// https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
const H265NALU_AGGREGATION_PACKET_TYPE: u8 = 48;
/// https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.3
const H265NALU_FRAGMENTATION_UNIT_TYPE: u8 = 49;
/// https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.4
const H265NALU_PACI_PACKET_TYPE: u8 = 50;

/// H265NALUHeader is a H265 NAL Unit Header
/// https://datatracker.ietf.org/doc/html/rfc7798#section-1.1.4
///
/// ```text
/// +---------------+---------------+
///  |0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |F|   Type    |  layer_id  | tid |
///  +-------------+-----------------+
/// ```
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct H265NALUHeader(pub u16);

impl H265NALUHeader {
    fn new(high_byte: u8, low_byte: u8) -> Self {
        H265NALUHeader(((high_byte as u16) << 8) | low_byte as u16)
    }

    /// f is the forbidden bit, should always be 0.
    pub fn f(&self) -> bool {
        (self.0 >> 15) != 0
    }

    /// nalu_type of NAL Unit.
    pub fn nalu_type(&self) -> u8 {
        // 01111110 00000000
        const MASK: u16 = 0b01111110 << 8;
        ((self.0 & MASK) >> (8 + 1)) as u8
    }

    /// is_type_vcl_unit returns whether or not the NAL Unit type is a VCL NAL unit.
    pub fn is_type_vcl_unit(&self) -> bool {
        // Type is coded on 6 bits
        const MSB_MASK: u8 = 0b00100000;
        (self.nalu_type() & MSB_MASK) == 0
    }

    /// layer_id should always be 0 in non-3D HEVC context.
    pub fn layer_id(&self) -> u8 {
        // 00000001 11111000
        const MASK: u16 = (0b00000001 << 8) | 0b11111000;
        ((self.0 & MASK) >> 3) as u8
    }

    /// tid is the temporal identifier of the NAL unit +1.
    pub fn tid(&self) -> u8 {
        const MASK: u16 = 0b00000111;
        (self.0 & MASK) as u8
    }

    /// is_aggregation_packet returns whether or not the packet is an Aggregation packet.
    pub fn is_aggregation_packet(&self) -> bool {
        self.nalu_type() == H265NALU_AGGREGATION_PACKET_TYPE
    }

    /// is_fragmentation_unit returns whether or not the packet is a Fragmentation Unit packet.
    pub fn is_fragmentation_unit(&self) -> bool {
        self.nalu_type() == H265NALU_FRAGMENTATION_UNIT_TYPE
    }

    /// is_paci_packet returns whether or not the packet is a PACI packet.
    pub fn is_paci_packet(&self) -> bool {
        self.nalu_type() == H265NALU_PACI_PACKET_TYPE
    }
}

///
/// Single NAL Unit Packet implementation
///
/// H265SingleNALUnitPacket represents a NALU packet, containing exactly one NAL unit.
///
/// ```text
///     0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |           PayloadHdr          |      DONL (conditional)       |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   |                  NAL unit payload data                        |
///   |                                                               |
///   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                               :...OPTIONAL RTP padding        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.1
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265SingleNALUnitPacket {
    /// payload_header is the header of the H265 packet.
    payload_header: H265NALUHeader,
    /// donl is a 16-bit field, that may or may not be present.
    donl: Option<u16>,
    /// payload of the fragmentation unit.
    payload: Vec<u8>,

    might_need_donl: bool,
}

impl H265SingleNALUnitPacket {
    /// with_donl can be called to specify whether or not DONL might be parsed.
    /// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
    pub fn with_donl(&mut self, value: bool) {
        self.might_need_donl = value;
    }

    /// depacketize parses the passed byte slice and stores the result in the
    /// H265SingleNALUnitPacket this method is called upon.
    fn depacketize(&mut self, payload: &[u8]) -> Result<(), PacketError> {
        if payload.len() <= H265NALU_HEADER_SIZE {
            return Err(PacketError::ErrShortPacket);
        }

        let payload_header = H265NALUHeader::new(payload[0], payload[1]);
        if payload_header.f() {
            return Err(PacketError::ErrH265CorruptedPacket);
        }
        if payload_header.is_fragmentation_unit()
            || payload_header.is_paci_packet()
            || payload_header.is_aggregation_packet()
        {
            return Err(PacketError::ErrInvalidH265PacketType);
        }

        let mut payload = &payload[2..];

        if self.might_need_donl {
            // sizeof(uint16)
            if payload.len() <= 2 {
                return Err(PacketError::ErrShortPacket);
            }

            let donl = ((payload[0] as u16) << 8) | (payload[1] as u16);
            self.donl = Some(donl);
            payload = &payload[2..];
        }

        self.payload_header = payload_header;
        self.payload = payload.to_vec();

        Ok(())
    }

    /// payload_header returns the NALU header of the packet.
    pub fn payload_header(&self) -> H265NALUHeader {
        self.payload_header
    }

    /// donl returns the DONL of the packet.
    pub fn donl(&self) -> Option<u16> {
        self.donl
    }

    /// payload returns the Fragmentation Unit packet payload.
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
}

///
/// Aggregation Packets implementation
///
/// H265AggregationUnitFirst represent the First Aggregation Unit in an AP.
///
/// ```text
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///                   :       DONL (conditional)      |   NALU size   |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |   NALU size   |                                               |
///   +-+-+-+-+-+-+-+-+         NAL unit                              |
///   |                                                               |
///   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                               :
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265AggregationUnitFirst {
    donl: Option<u16>,
    nal_unit_size: u16,
    nal_unit: Vec<u8>,
}

impl H265AggregationUnitFirst {
    /// donl field, when present, specifies the value of the 16 least
    /// significant bits of the decoding order number of the aggregated NAL
    /// unit.
    pub fn donl(&self) -> Option<u16> {
        self.donl
    }

    /// nalu_size represents the size, in bytes, of the nal_unit.
    pub fn nalu_size(&self) -> u16 {
        self.nal_unit_size
    }

    /// nal_unit payload.
    pub fn nal_unit(&self) -> Vec<u8> {
        self.nal_unit.clone()
    }
}

/// H265AggregationUnit represent the an Aggregation Unit in an AP, which is not the first one.
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///                   : DOND (cond)   |          NALU size            |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   |                       NAL unit                                |
///   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                               :
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265AggregationUnit {
    dond: Option<u8>,
    nal_unit_size: u16,
    nal_unit: Vec<u8>,
}

impl H265AggregationUnit {
    /// dond field plus 1 specifies the difference between
    /// the decoding order number values of the current aggregated NAL unit
    /// and the preceding aggregated NAL unit in the same AP.
    pub fn dond(&self) -> Option<u8> {
        self.dond
    }

    /// nalu_size represents the size, in bytes, of the nal_unit.
    pub fn nalu_size(&self) -> u16 {
        self.nal_unit_size
    }

    /// nal_unit payload.
    pub fn nal_unit(&self) -> Vec<u8> {
        self.nal_unit.clone()
    }
}

/// H265AggregationPacket represents an Aggregation packet.
///
/// ```text
///   0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |    PayloadHdr (Type=48)       |                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
///   |                                                               |
///   |             two or more aggregation units                     |
///   |                                                               |
///   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                               :...OPTIONAL RTP padding        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265AggregationPacket {
    first_unit: Option<H265AggregationUnitFirst>,
    other_units: Vec<H265AggregationUnit>,

    might_need_donl: bool,
}

impl H265AggregationPacket {
    /// with_donl can be called to specify whether or not DONL might be parsed.
    /// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
    pub fn with_donl(&mut self, value: bool) {
        self.might_need_donl = value;
    }

    /// depacketize parses the passed byte slice and stores the result in the
    /// H265AggregationPacket this method is called upon.
    fn depacketize(&mut self, payload: &[u8]) -> Result<(), PacketError> {
        if payload.len() <= H265NALU_HEADER_SIZE {
            return Err(PacketError::ErrShortPacket);
        }

        let payload_header = H265NALUHeader::new(payload[0], payload[1]);
        if payload_header.f() {
            return Err(PacketError::ErrH265CorruptedPacket);
        }
        if !payload_header.is_aggregation_packet() {
            return Err(PacketError::ErrInvalidH265PacketType);
        }

        // First parse the first aggregation unit
        let mut payload = &payload[2..];
        let mut first_unit = H265AggregationUnitFirst::default();

        if self.might_need_donl {
            if payload.len() < 2 {
                return Err(PacketError::ErrShortPacket);
            }

            let donl = ((payload[0] as u16) << 8) | (payload[1] as u16);
            first_unit.donl = Some(donl);

            payload = &payload[2..];
        }
        if payload.len() < 2 {
            return Err(PacketError::ErrShortPacket);
        }
        first_unit.nal_unit_size = ((payload[0] as u16) << 8) | (payload[1] as u16);
        payload = &payload[2..];

        if payload.len() < first_unit.nal_unit_size as usize {
            return Err(PacketError::ErrShortPacket);
        }

        first_unit.nal_unit = payload[..first_unit.nal_unit_size as usize].to_vec();
        payload = &payload[first_unit.nal_unit_size as usize..];

        // Parse remaining Aggregation Units
        let mut units = vec![]; //H265AggregationUnit
        loop {
            let mut unit = H265AggregationUnit::default();

            if self.might_need_donl {
                if payload.is_empty() {
                    break;
                }

                let dond = payload[0];
                unit.dond = Some(dond);

                payload = &payload[1..];
            }

            if payload.len() < 2 {
                break;
            }
            unit.nal_unit_size = ((payload[0] as u16) << 8) | (payload[1] as u16);
            payload = &payload[2..];

            if payload.len() < unit.nal_unit_size as usize {
                break;
            }

            unit.nal_unit = payload[..unit.nal_unit_size as usize].to_vec();
            payload = &payload[unit.nal_unit_size as usize..];

            units.push(unit);
        }

        // There need to be **at least** two Aggregation Units (first + another one)
        if units.is_empty() {
            return Err(PacketError::ErrShortPacket);
        }

        self.first_unit = Some(first_unit);
        self.other_units = units;

        Ok(())
    }

    /// first_unit returns the first Aggregated Unit of the packet.
    pub fn first_unit(&self) -> Option<&H265AggregationUnitFirst> {
        self.first_unit.as_ref()
    }

    /// other_units returns the all the other Aggregated Unit of the packet (excluding the first one).
    pub fn other_units(&self) -> &[H265AggregationUnit] {
        self.other_units.as_slice()
    }
}

///
/// Fragmentation Unit implementation
///

const H265FRAGMENTATION_UNIT_HEADER_SIZE: usize = 1;

/// H265FragmentationUnitHeader is a H265 FU Header
///
/// ```text
/// +---------------+
/// |0|1|2|3|4|5|6|7|
/// +-+-+-+-+-+-+-+-+
/// |S|E|  fu_type   |
/// +---------------+
/// ```
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct H265FragmentationUnitHeader(pub u8);

impl H265FragmentationUnitHeader {
    /// s represents the start of a fragmented NAL unit.
    pub fn s(&self) -> bool {
        const MASK: u8 = 0b10000000;
        ((self.0 & MASK) >> 7) != 0
    }

    /// e represents the end of a fragmented NAL unit.
    pub fn e(&self) -> bool {
        const MASK: u8 = 0b01000000;
        ((self.0 & MASK) >> 6) != 0
    }

    /// fu_type MUST be equal to the field Type of the fragmented NAL unit.
    pub fn fu_type(&self) -> u8 {
        const MASK: u8 = 0b00111111;
        self.0 & MASK
    }
}

/// H265FragmentationUnitPacket represents a single Fragmentation Unit packet.
///
///  0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    PayloadHdr (Type=49)       |   FU header   | DONL (cond)   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
/// | DONL (cond)   |                                               |
/// |-+-+-+-+-+-+-+-+                                               |
/// |                         FU payload                            |
/// |                                                               |
/// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               :...OPTIONAL RTP padding        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.3
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265FragmentationUnitPacket {
    /// payload_header is the header of the H265 packet.
    payload_header: H265NALUHeader,
    /// fu_header is the header of the fragmentation unit
    fu_header: H265FragmentationUnitHeader,
    /// donl is a 16-bit field, that may or may not be present.
    donl: Option<u16>,
    /// payload of the fragmentation unit.
    payload: Vec<u8>,

    might_need_donl: bool,
}

impl H265FragmentationUnitPacket {
    /// with_donl can be called to specify whether or not DONL might be parsed.
    /// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
    pub fn with_donl(&mut self, value: bool) {
        self.might_need_donl = value;
    }

    /// depacketize parses the passed byte slice and stores the result in the
    /// H265FragmentationUnitPacket this method is called upon.
    fn depacketize(&mut self, payload: &[u8]) -> Result<(), PacketError> {
        const TOTAL_HEADER_SIZE: usize = H265NALU_HEADER_SIZE + H265FRAGMENTATION_UNIT_HEADER_SIZE;
        if payload.len() <= TOTAL_HEADER_SIZE {
            return Err(PacketError::ErrShortPacket);
        }

        let payload_header = H265NALUHeader::new(payload[0], payload[1]);
        if payload_header.f() {
            return Err(PacketError::ErrH265CorruptedPacket);
        }
        if !payload_header.is_fragmentation_unit() {
            return Err(PacketError::ErrInvalidH265PacketType);
        }

        let fu_header = H265FragmentationUnitHeader(payload[2]);
        let mut payload = &payload[3..];

        if fu_header.s() && self.might_need_donl {
            if payload.len() <= 2 {
                return Err(PacketError::ErrShortPacket);
            }

            let donl = ((payload[0] as u16) << 8) | (payload[1] as u16);
            self.donl = Some(donl);
            payload = &payload[2..];
        }

        self.payload_header = payload_header;
        self.fu_header = fu_header;
        self.payload = payload.to_vec();

        Ok(())
    }

    /// payload_header returns the NALU header of the packet.
    pub fn payload_header(&self) -> H265NALUHeader {
        self.payload_header
    }

    /// fu_header returns the Fragmentation Unit Header of the packet.
    pub fn fu_header(&self) -> H265FragmentationUnitHeader {
        self.fu_header
    }

    /// donl returns the DONL of the packet.
    pub fn donl(&self) -> Option<u16> {
        self.donl
    }

    /// payload returns the Fragmentation Unit packet payload.
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
}

///
/// PACI implementation
///

/// H265PACIPacket represents a single H265 PACI packet.
///
/// ```text
///  0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    PayloadHdr (Type=50)       |A|   cType   | phssize |F0..2|Y|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        payload Header Extension Structure (phes)              |
/// |=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=|
/// |                                                               |
/// |                  PACI payload: NAL unit                       |
/// |                   . . .                                       |
/// |                                                               |
/// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               :...OPTIONAL RTP padding        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.4
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265PACIPacket {
    /// payload_header is the header of the H265 packet.
    payload_header: H265NALUHeader,

    /// Field which holds value for `A`, `cType`, `phssize`, `F0`, `F1`, `F2` and `Y` fields.
    paci_header_fields: u16,

    /// phes is a header extension, of byte length `phssize`
    phes: Vec<u8>,

    /// payload contains NAL units & optional padding
    payload: Vec<u8>,
}

impl H265PACIPacket {
    /// payload_header returns the NAL Unit Header.
    pub fn payload_header(&self) -> H265NALUHeader {
        self.payload_header
    }

    /// a copies the F bit of the PACI payload NALU.
    pub fn a(&self) -> bool {
        const MASK: u16 = 0b10000000 << 8;
        (self.paci_header_fields & MASK) != 0
    }

    /// ctype copies the Type field of the PACI payload NALU.
    pub fn ctype(&self) -> u8 {
        const MASK: u16 = 0b01111110 << 8;
        ((self.paci_header_fields & MASK) >> (8 + 1)) as u8
    }

    /// phs_size indicates the size of the phes field.
    pub fn phs_size(&self) -> u8 {
        const MASK: u16 = (0b00000001 << 8) | 0b11110000;
        ((self.paci_header_fields & MASK) >> 4) as u8
    }

    /// f0 indicates the presence of a Temporal Scalability support extension in the phes.
    pub fn f0(&self) -> bool {
        const MASK: u16 = 0b00001000;
        (self.paci_header_fields & MASK) != 0
    }

    /// f1 must be zero, reserved for future extensions.
    pub fn f1(&self) -> bool {
        const MASK: u16 = 0b00000100;
        (self.paci_header_fields & MASK) != 0
    }

    /// f2 must be zero, reserved for future extensions.
    pub fn f2(&self) -> bool {
        const MASK: u16 = 0b00000010;
        (self.paci_header_fields & MASK) != 0
    }

    /// y must be zero, reserved for future extensions.
    pub fn y(&self) -> bool {
        const MASK: u16 = 0b00000001;
        (self.paci_header_fields & MASK) != 0
    }

    /// phes contains header extensions. Its size is indicated by phssize.
    pub fn phes(&self) -> Vec<u8> {
        self.phes.clone()
    }

    /// payload is a single NALU or NALU-like struct, not including the first two octets (header).
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// tsci returns the Temporal Scalability Control Information extension, if present.
    pub fn tsci(&self) -> Option<H265TSCI> {
        if !self.f0() || self.phs_size() < 3 {
            return None;
        }

        Some(H265TSCI(
            ((self.phes[0] as u32) << 16) | ((self.phes[1] as u32) << 8) | self.phes[0] as u32,
        ))
    }

    /// depacketize parses the passed byte slice and stores the result in the
    /// H265PACIPacket this method is called upon.
    fn depacketize(&mut self, payload: &[u8]) -> Result<(), PacketError> {
        const TOTAL_HEADER_SIZE: usize = H265NALU_HEADER_SIZE + 2;
        if payload.len() <= TOTAL_HEADER_SIZE {
            return Err(PacketError::ErrShortPacket);
        }

        let payload_header = H265NALUHeader::new(payload[0], payload[1]);
        if payload_header.f() {
            return Err(PacketError::ErrH265CorruptedPacket);
        }
        if !payload_header.is_paci_packet() {
            return Err(PacketError::ErrInvalidH265PacketType);
        }

        let paci_header_fields = ((payload[2] as u16) << 8) | (payload[3] as u16);
        let mut payload = &payload[4..];

        self.paci_header_fields = paci_header_fields;
        let header_extension_size = self.phs_size();

        if payload.len() < header_extension_size as usize + 1 {
            self.paci_header_fields = 0;
            return Err(PacketError::ErrShortPacket);
        }

        self.payload_header = payload_header;

        if header_extension_size > 0 {
            self.phes = payload[..header_extension_size as usize].to_vec();
        }

        payload = &payload[header_extension_size as usize..];
        self.payload = payload.to_vec();

        Ok(())
    }
}

///
/// Temporal Scalability Control Information
///

/// H265TSCI is a Temporal Scalability Control Information header extension.
/// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.5
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct H265TSCI(pub u32);

impl H265TSCI {
    /// tl0picidx see RFC7798 for more details.
    pub fn tl0picidx(&self) -> u8 {
        const M1: u32 = 0xFFFF0000;
        const M2: u32 = 0xFF00;
        ((((self.0 & M1) >> 16) & M2) >> 8) as u8
    }

    /// irap_pic_id see RFC7798 for more details.
    pub fn irap_pic_id(&self) -> u8 {
        const M1: u32 = 0xFFFF0000;
        const M2: u32 = 0x00FF;
        (((self.0 & M1) >> 16) & M2) as u8
    }

    /// s see RFC7798 for more details.
    pub fn s(&self) -> bool {
        const M1: u32 = 0xFF00;
        const M2: u32 = 0b10000000;
        (((self.0 & M1) >> 8) & M2) != 0
    }

    /// e see RFC7798 for more details.
    pub fn e(&self) -> bool {
        const M1: u32 = 0xFF00;
        const M2: u32 = 0b01000000;
        (((self.0 & M1) >> 8) & M2) != 0
    }

    /// res see RFC7798 for more details.
    pub fn res(&self) -> u8 {
        const M1: u32 = 0xFF00;
        const M2: u32 = 0b00111111;
        (((self.0 & M1) >> 8) & M2) as u8
    }
}

///
/// H265 Payload Enum
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H265Payload {
    H265SingleNALUnitPacket(H265SingleNALUnitPacket),
    H265FragmentationUnitPacket(H265FragmentationUnitPacket),
    H265AggregationPacket(H265AggregationPacket),
    H265PACIPacket(H265PACIPacket),
}

impl Default for H265Payload {
    fn default() -> Self {
        H265Payload::H265SingleNALUnitPacket(H265SingleNALUnitPacket::default())
    }
}

/// Depacketizes H265 RTP packets.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265Depacketizer {
    payload: H265Payload,
    might_need_donl: bool,
}

impl H265Depacketizer {
    /// with_donl can be called to specify whether or not DONL might be parsed.
    /// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
    pub fn with_donl(&mut self, value: bool) {
        self.might_need_donl = value;
    }

    /// payload returns the populated payload.
    /// Must be casted to one of:
    /// - H265SingleNALUnitPacket
    /// - H265FragmentationUnitPacket
    /// - H265AggregationPacket
    /// - H265PACIPacket
    pub fn payload(&self) -> &H265Payload {
        &self.payload
    }
}

impl Depacketizer for H265Depacketizer {
    /// depacketize parses the passed byte slice and stores the result
    /// in the H265Packet this method is called upon
    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
        _: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        if packet.len() <= H265NALU_HEADER_SIZE {
            return Err(PacketError::ErrShortPacket);
        }

        let header = H265NALUHeader::new(packet[0], packet[1]);
        if header.f() {
            return Err(PacketError::ErrH265CorruptedPacket);
        }

        if header.is_paci_packet() {
            let mut decoded = H265PACIPacket::default();
            decoded.depacketize(packet)?;

            self.payload = H265Payload::H265PACIPacket(decoded);
        } else if header.is_fragmentation_unit() {
            let mut decoded = H265FragmentationUnitPacket::default();
            decoded.with_donl(self.might_need_donl);

            decoded.depacketize(packet)?;

            self.payload = H265Payload::H265FragmentationUnitPacket(decoded);
        } else if header.is_aggregation_packet() {
            let mut decoded = H265AggregationPacket::default();
            decoded.with_donl(self.might_need_donl);

            decoded.depacketize(packet)?;

            self.payload = H265Payload::H265AggregationPacket(decoded);
        } else {
            let mut decoded = H265SingleNALUnitPacket::default();
            decoded.with_donl(self.might_need_donl);

            decoded.depacketize(packet)?;

            self.payload = H265Payload::H265SingleNALUnitPacket(decoded);
        }

        out.extend_from_slice(packet);

        Ok(())
    }

    /// is_partition_head checks if this is the head of a packetized nalu stream.
    fn is_partition_head(&self, _payload: &[u8]) -> bool {
        //TODO:
        true
    }

    fn is_partition_tail(&self, marker: bool, _payload: &[u8]) -> bool {
        marker
    }
}

#[cfg(test)]
mod test {
    use super::*;

    type Result<T> = std::result::Result<T, PacketError>;

    #[test]
    fn test_h265_nalu_header() -> Result<()> {
        #[derive(Default)]
        struct TestType {
            raw_header: &'static [u8],

            fbit: bool,
            typ: u8,
            layer_id: u8,
            tid: u8,

            is_ap: bool,
            is_fu: bool,
            is_paci: bool,
        }

        let tests = vec![
            // fbit
            TestType {
                raw_header: &[0x80, 0x00],
                typ: 0,
                layer_id: 0,
                tid: 0,
                fbit: true,
                ..Default::default()
            },
            // VPS_NUT
            TestType {
                raw_header: &[0x40, 0x01],
                typ: 32,
                layer_id: 0,
                tid: 1,
                ..Default::default()
            },
            // SPS_NUT
            TestType {
                raw_header: &[0x42, 0x01],
                typ: 33,
                layer_id: 0,
                tid: 1,
                ..Default::default()
            },
            // PPS_NUT
            TestType {
                raw_header: &[0x44, 0x01],
                typ: 34,
                layer_id: 0,
                tid: 1,
                ..Default::default()
            },
            // PREFIX_SEI_NUT
            TestType {
                raw_header: &[0x4e, 0x01],
                typ: 39,
                layer_id: 0,
                tid: 1,
                ..Default::default()
            },
            // Fragmentation Unit
            TestType {
                raw_header: &[0x62, 0x01],
                typ: H265NALU_FRAGMENTATION_UNIT_TYPE,
                layer_id: 0,
                tid: 1,
                is_fu: true,
                ..Default::default()
            },
        ];

        for cur in tests {
            let header = H265NALUHeader::new(cur.raw_header[0], cur.raw_header[1]);

            assert_eq!(header.f(), cur.fbit, "invalid F bit");
            assert_eq!(header.nalu_type(), cur.typ, "invalid type");

            // For any type < 32, NAL is a VLC NAL unit.
            assert_eq!(
                header.is_type_vcl_unit(),
                (header.nalu_type() < 32),
                "invalid IsTypeVCLUnit"
            );
            assert_eq!(
                header.is_aggregation_packet(),
                cur.is_ap,
                "invalid type (aggregation packet)"
            );
            assert_eq!(
                header.is_fragmentation_unit(),
                cur.is_fu,
                "invalid type (fragmentation unit)"
            );
            assert_eq!(header.is_paci_packet(), cur.is_paci, "invalid type (PACI)");
            assert_eq!(header.layer_id(), cur.layer_id, "invalid layer_id");
            assert_eq!(header.tid(), cur.tid, "invalid tid");
        }

        Ok(())
    }

    #[test]
    fn test_h265_fu_header() -> Result<()> {
        #[derive(Default)]
        struct TestType {
            header: H265FragmentationUnitHeader,

            s: bool,
            e: bool,
            typ: u8,
        }

        let tests = vec![
            // Start | IDR_W_RADL
            TestType {
                header: H265FragmentationUnitHeader(0x93),
                s: true,
                e: false,
                typ: 19,
            },
            // Continuation | IDR_W_RADL
            TestType {
                header: H265FragmentationUnitHeader(0x13),
                s: false,
                e: false,
                typ: 19,
            },
            // End | IDR_W_RADL
            TestType {
                header: H265FragmentationUnitHeader(0x53),
                s: false,
                e: true,
                typ: 19,
            },
            // Start | TRAIL_R
            TestType {
                header: H265FragmentationUnitHeader(0x81),
                s: true,
                e: false,
                typ: 1,
            },
            // Continuation | TRAIL_R
            TestType {
                header: H265FragmentationUnitHeader(0x01),
                s: false,
                e: false,
                typ: 1,
            },
            // End | TRAIL_R
            TestType {
                header: H265FragmentationUnitHeader(0x41),
                s: false,
                e: true,
                typ: 1,
            },
        ];

        for cur in tests {
            assert_eq!(cur.header.s(), cur.s, "invalid s field");
            assert_eq!(cur.header.e(), cur.e, "invalid e field");
            assert_eq!(cur.header.fu_type(), cur.typ, "invalid FuType field");
        }

        Ok(())
    }

    #[test]
    fn test_h265_single_nalunit_packet() -> Result<()> {
        #[derive(Default)]
        struct TestType {
            raw: &'static [u8],
            with_donl: bool,
            expected_packet: Option<H265SingleNALUnitPacket>,
            expected_err: Option<PacketError>,
        }

        let tests = vec![
            TestType {
                raw: &[],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62, 0x01, 0x93],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            // FBit enabled in H265NALUHeader
            TestType {
                raw: &[0x80, 0x01, 0x93, 0xaf, 0xaf, 0xaf, 0xaf],
                expected_err: Some(PacketError::ErrH265CorruptedPacket),
                ..Default::default()
            },
            // Type '49' in H265NALUHeader
            TestType {
                raw: &[0x62, 0x01, 0x93, 0xaf, 0xaf, 0xaf, 0xaf],
                expected_err: Some(PacketError::ErrInvalidH265PacketType),
                ..Default::default()
            },
            // Type '50' in H265NALUHeader
            TestType {
                raw: &[0x64, 0x01, 0x93, 0xaf, 0xaf, 0xaf, 0xaf],
                expected_err: Some(PacketError::ErrInvalidH265PacketType),
                ..Default::default()
            },
            TestType {
                raw: &[0x01, 0x01, 0xab, 0xcd, 0xef],
                expected_packet: Some(H265SingleNALUnitPacket {
                    payload_header: H265NALUHeader::new(0x01, 0x01),
                    payload: vec![0xab, 0xcd, 0xef],
                    ..Default::default()
                }),
                ..Default::default()
            },
            // DONL, payload too small
            TestType {
                raw: &[0x01, 0x01, 0x93, 0xaf],
                expected_err: Some(PacketError::ErrShortPacket),
                with_donl: true,
                ..Default::default()
            },
            TestType {
                raw: &[0x01, 0x01, 0xaa, 0xbb, 0xcc],
                expected_packet: Some(H265SingleNALUnitPacket {
                    payload_header: H265NALUHeader::new(0x01, 0x01),
                    donl: Some((0xaa << 8) | 0xbb),
                    payload: vec![0xcc],
                    ..Default::default()
                }),
                with_donl: true,
                ..Default::default()
            },
        ];

        for cur in tests {
            let mut parsed = H265SingleNALUnitPacket::default();
            if cur.with_donl {
                parsed.with_donl(cur.with_donl);
            }

            let result = parsed.depacketize(&cur.raw);

            if cur.expected_err.is_some() && result.is_ok() {
                assert!(false, "should error");
            } else if cur.expected_err.is_none() && result.is_err() {
                assert!(false, "should not error");
            }

            if let Some(expected_packet) = cur.expected_packet {
                assert_eq!(
                    expected_packet.payload_header(),
                    parsed.payload_header(),
                    "invalid payload header"
                );
                assert_eq!(expected_packet.donl(), parsed.donl(), "invalid DONL");

                assert_eq!(
                    expected_packet.payload(),
                    parsed.payload(),
                    "invalid payload"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_h265_aggregation_packet() -> Result<()> {
        #[derive(Default)]
        struct TestType {
            raw: &'static [u8],
            with_donl: bool,
            expected_packet: Option<H265AggregationPacket>,
            expected_err: Option<PacketError>,
        }

        let tests = vec![
            TestType {
                raw: &[],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62, 0x01, 0x93],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            // FBit enabled in H265NALUHeader
            TestType {
                raw: &[0x80, 0x01, 0x93, 0xaf, 0xaf, 0xaf, 0xaf],
                expected_err: Some(PacketError::ErrH265CorruptedPacket),
                ..Default::default()
            },
            // Type '48' in H265NALUHeader
            TestType {
                raw: &[0xE0, 0x01, 0x93, 0xaf, 0xaf, 0xaf, 0xaf],
                expected_err: Some(PacketError::ErrInvalidH265PacketType),
                ..Default::default()
            },
            // Small payload
            TestType {
                raw: &[0x60, 0x01, 0x00, 0x1],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            // Small payload
            TestType {
                raw: &[0x60, 0x01, 0x00],
                expected_err: Some(PacketError::ErrShortPacket),
                with_donl: true,
                ..Default::default()
            },
            // Small payload
            TestType {
                raw: &[0x60, 0x01, 0x00, 0x1],
                expected_err: Some(PacketError::ErrShortPacket),
                with_donl: true,
                ..Default::default()
            },
            // Small payload
            TestType {
                raw: &[0x60, 0x01, 0x00, 0x01, 0x02],
                expected_err: Some(PacketError::ErrShortPacket),
                with_donl: true,
                ..Default::default()
            },
            // Single Aggregation Unit
            TestType {
                raw: &[0x60, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00],
                expected_err: Some(PacketError::ErrShortPacket),
                with_donl: true,
                ..Default::default()
            },
            // Incomplete second Aggregation Unit
            TestType {
                raw: &[
                    0x60, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, // DONL
                    0x00,
                ],
                expected_err: Some(PacketError::ErrShortPacket),
                with_donl: true,
                ..Default::default()
            },
            // Incomplete second Aggregation Unit
            TestType {
                raw: &[
                    0x60, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00,
                    // DONL, NAL Unit size (2 bytes)
                    0x00, 0x55, 0x55,
                ],
                expected_err: Some(PacketError::ErrShortPacket),
                with_donl: true,
                ..Default::default()
            },
            // Valid Second Aggregation Unit
            TestType {
                raw: &[
                    0x60, 0x01, 0xcc, 0xdd, 0x00, 0x02, 0xff, 0xee,
                    // DONL, NAL Unit size (2 bytes), Payload
                    0x77, 0x00, 0x01, 0xaa,
                ],
                with_donl: true,
                expected_packet: Some(H265AggregationPacket {
                    first_unit: Some(H265AggregationUnitFirst {
                        donl: Some(0xccdd),
                        nal_unit_size: 2,
                        nal_unit: vec![0xff, 0xee],
                    }),
                    other_units: vec![H265AggregationUnit {
                        dond: Some(0x77),
                        nal_unit_size: 1,
                        nal_unit: vec![0xaa],
                    }],
                    might_need_donl: false,
                }),
                ..Default::default()
            },
        ];

        for cur in tests {
            let mut parsed = H265AggregationPacket::default();
            if cur.with_donl {
                parsed.with_donl(cur.with_donl);
            }

            let result = parsed.depacketize(&cur.raw);

            if cur.expected_err.is_some() && result.is_ok() {
                assert!(false, "should error");
            } else if cur.expected_err.is_none() && result.is_err() {
                assert!(false, "should not error");
            }

            if let Some(expected_packet) = cur.expected_packet {
                if let (Some(first_unit), Some(parsed_first_unit)) =
                    (expected_packet.first_unit(), parsed.first_unit())
                {
                    assert_eq!(
                        parsed_first_unit.nal_unit_size, first_unit.nal_unit_size,
                        "invalid first unit NALUSize"
                    );
                    assert_eq!(
                        first_unit.donl(),
                        parsed_first_unit.donl(),
                        "invalid first unit DONL"
                    );
                    assert_eq!(
                        first_unit.nal_unit(),
                        parsed_first_unit.nal_unit(),
                        "invalid first unit NalUnit"
                    );
                }

                assert_eq!(
                    expected_packet.other_units().len(),
                    parsed.other_units().len(),
                    "number of other units mismatch"
                );

                for ndx in 0..expected_packet.other_units().len() {
                    assert_eq!(
                        parsed.other_units()[ndx].nalu_size(),
                        expected_packet.other_units()[ndx].nalu_size(),
                        "invalid unit NALUSize"
                    );

                    assert_eq!(
                        expected_packet.other_units()[ndx].dond(),
                        parsed.other_units()[ndx].dond(),
                        "invalid unit DOND"
                    );

                    assert_eq!(
                        expected_packet.other_units()[ndx].nal_unit(),
                        parsed.other_units()[ndx].nal_unit(),
                        "invalid first unit NalUnit"
                    );
                }

                assert_eq!(
                    expected_packet.other_units(),
                    parsed.other_units(),
                    "invalid payload"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_h265_fragmentation_unit_packet() -> Result<()> {
        #[derive(Default)]
        struct TestType {
            raw: &'static [u8],
            with_donl: bool,
            expected_fu: Option<H265FragmentationUnitPacket>,
            expected_err: Option<PacketError>,
        }
        let tests = vec![
            TestType {
                raw: &[],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62, 0x01],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62, 0x01, 0x93],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            // FBit enabled in H265NALUHeader
            TestType {
                raw: &[0x80, 0x01, 0x93, 0xaf],
                expected_err: Some(PacketError::ErrH265CorruptedPacket),
                ..Default::default()
            },
            // Type not '49' in H265NALUHeader
            TestType {
                raw: &[0x40, 0x01, 0x93, 0xaf],
                expected_err: Some(PacketError::ErrInvalidH265PacketType),
                ..Default::default()
            },
            TestType {
                raw: &[0x62, 0x01, 0x93, 0xaf],
                expected_fu: Some(H265FragmentationUnitPacket {
                    payload_header: H265NALUHeader::new(0x62, 0x01),
                    fu_header: H265FragmentationUnitHeader(0x93),
                    donl: None,
                    payload: vec![0xaf],
                    might_need_donl: false,
                }),
                ..Default::default()
            },
            TestType {
                raw: &[0x62, 0x01, 0x93, 0xcc],
                with_donl: true,
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62, 0x01, 0x93, 0xcc, 0xdd, 0xaf, 0x0d, 0x5a],
                with_donl: true,
                expected_fu: Some(H265FragmentationUnitPacket {
                    payload_header: H265NALUHeader::new(0x62, 0x01),
                    fu_header: H265FragmentationUnitHeader(0x93),
                    donl: Some((0xcc << 8) | 0xdd),
                    payload: vec![0xaf, 0x0d, 0x5a],
                    might_need_donl: false,
                }),
                ..Default::default()
            },
        ];

        for cur in tests {
            let mut parsed = H265FragmentationUnitPacket::default();
            if cur.with_donl {
                parsed.with_donl(cur.with_donl);
            }

            let result = parsed.depacketize(&cur.raw);

            if cur.expected_err.is_some() && result.is_ok() {
                assert!(false, "should error");
            } else if cur.expected_err.is_none() && result.is_err() {
                assert!(false, "should not error");
            }

            if let Some(expected_fu) = &cur.expected_fu {
                assert_eq!(
                    parsed.payload_header(),
                    expected_fu.payload_header(),
                    "invalid payload header"
                );
                assert_eq!(
                    parsed.fu_header(),
                    expected_fu.fu_header(),
                    "invalid FU header"
                );
                assert_eq!(parsed.donl(), expected_fu.donl(), "invalid DONL");
                assert_eq!(parsed.payload(), expected_fu.payload(), "invalid Payload");
            }
        }

        Ok(())
    }

    #[test]
    fn test_h265_temporal_scalability_control_information() -> Result<()> {
        #[derive(Default)]
        struct TestType {
            value: H265TSCI,
            expected_tl0picidx: u8,
            expected_irap_pic_id: u8,
            expected_s: bool,
            expected_e: bool,
            expected_res: u8,
        }

        let tests = vec![
            TestType {
                value: H265TSCI(((0xCA) << 24) | ((0xFE) << 16)),
                expected_tl0picidx: 0xCA,
                expected_irap_pic_id: 0xFE,
                ..Default::default()
            },
            TestType {
                value: H265TSCI((1) << 15),
                expected_s: true,
                ..Default::default()
            },
            TestType {
                value: H265TSCI((1) << 14),
                expected_e: true,
                ..Default::default()
            },
            TestType {
                value: H265TSCI((0x0A) << 8),
                expected_res: 0x0A,
                ..Default::default()
            },
            // Sets RES, and force sets S and E to 0.
            TestType {
                value: H265TSCI(
                    ((0xAA) << 8) & (u32::MAX ^ ((1) << 15)) & (u32::MAX ^ ((1) << 14)),
                ),
                expected_res: 0xAA & 0b00111111,
                ..Default::default()
            },
        ];

        for cur in tests {
            assert_eq!(
                cur.value.tl0picidx(),
                cur.expected_tl0picidx,
                "invalid TL0PICIDX"
            );
            assert_eq!(
                cur.value.irap_pic_id(),
                cur.expected_irap_pic_id,
                "invalid IrapPicID"
            );
            assert_eq!(cur.value.s(), cur.expected_s, "invalid S");
            assert_eq!(cur.value.e(), cur.expected_e, "invalid E");
            assert_eq!(cur.value.res(), cur.expected_res, "invalid RES");
        }

        Ok(())
    }

    #[test]
    fn test_h265_paci_packet() -> Result<()> {
        #[derive(Default)]
        struct TestType {
            raw: &'static [u8],
            expected_fu: Option<H265PACIPacket>,
            expected_err: Option<PacketError>,
        }

        let tests = vec![
            TestType {
                raw: &[],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62, 0x01, 0x93],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            // FBit enabled in H265NALUHeader
            TestType {
                raw: &[0x80, 0x01, 0x93, 0xaf, 0xaf, 0xaf, 0xaf],
                expected_err: Some(PacketError::ErrH265CorruptedPacket),
                ..Default::default()
            },
            // Type not '50' in H265NALUHeader
            TestType {
                raw: &[0x40, 0x01, 0x93, 0xaf, 0xaf, 0xaf, 0xaf],
                expected_err: Some(PacketError::ErrInvalidH265PacketType),
                ..Default::default()
            },
            // Invalid header extension size
            TestType {
                raw: &[0x64, 0x01, 0x93, 0xaf, 0xaf, 0xaf, 0xaf],
                expected_err: Some(PacketError::ErrInvalidH265PacketType),
                ..Default::default()
            },
            // No Header Extension
            TestType {
                raw: &[0x64, 0x01, 0x64, 0x00, 0xab, 0xcd, 0xef],
                expected_fu: Some(H265PACIPacket {
                    payload_header: H265NALUHeader::new(0x64, 0x01),
                    paci_header_fields: ((0x64) << 8),
                    phes: vec![],
                    payload: vec![0xab, 0xcd, 0xef],
                }),
                ..Default::default()
            },
            // Header Extension 1 byte
            TestType {
                raw: &[0x64, 0x01, 0x64, 0x10, 0xff, 0xab, 0xcd, 0xef],
                expected_fu: Some(H265PACIPacket {
                    payload_header: H265NALUHeader::new(0x64, 0x01),
                    paci_header_fields: ((0x64) << 8) | (0x10),
                    phes: vec![0xff],
                    payload: vec![0xab, 0xcd, 0xef],
                }),
                ..Default::default()
            },
            // Header Extension TSCI
            TestType {
                raw: &[
                    0x64, 0x01, 0x64, 0b00111000, 0xaa, 0xbb, 0x80, 0xab, 0xcd, 0xef,
                ],
                expected_fu: Some(H265PACIPacket {
                    payload_header: H265NALUHeader::new(0x64, 0x01),
                    paci_header_fields: ((0x64) << 8) | (0b00111000),
                    phes: vec![0xaa, 0xbb, 0x80],
                    payload: vec![0xab, 0xcd, 0xef],
                }),
                ..Default::default()
            },
        ];

        for cur in tests {
            let mut parsed = H265PACIPacket::default();

            let result = parsed.depacketize(&cur.raw);

            if cur.expected_err.is_some() && result.is_ok() {
                assert!(false, "should error");
            } else if cur.expected_err.is_none() && result.is_err() {
                assert!(false, "should not error");
            }

            if let Some(expected_fu) = &cur.expected_fu {
                assert_eq!(
                    expected_fu.payload_header(),
                    parsed.payload_header(),
                    "invalid PayloadHeader"
                );
                assert_eq!(expected_fu.a(), parsed.a(), "invalid A");
                assert_eq!(expected_fu.ctype(), parsed.ctype(), "invalid CType");
                assert_eq!(expected_fu.phs_size(), parsed.phs_size(), "invalid PHSsize");
                assert_eq!(expected_fu.f0(), parsed.f0(), "invalid F0");
                assert_eq!(expected_fu.f1(), parsed.f1(), "invalid F1");
                assert_eq!(expected_fu.f2(), parsed.f2(), "invalid F2");
                assert_eq!(expected_fu.y(), parsed.y(), "invalid Y");
                assert_eq!(expected_fu.phes(), parsed.phes(), "invalid PHES");
                assert_eq!(expected_fu.payload(), parsed.payload(), "invalid Payload");
                assert_eq!(expected_fu.tsci(), parsed.tsci(), "invalid TSCI");
            }
        }

        Ok(())
    }

    #[test]
    fn test_h265_packet() -> Result<()> {
        #[derive(Default)]
        struct TestType {
            raw: &'static [u8],
            with_donl: bool,
            expected_packet_type: Option<H265Payload>,
            expected_err: Option<PacketError>,
        }
        let tests = vec![
            TestType {
                raw: &[],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x62, 0x01, 0x93],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x64, 0x01, 0x93, 0xaf],
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            TestType {
                raw: &[0x01, 0x01],
                with_donl: true,
                expected_err: Some(PacketError::ErrShortPacket),
                ..Default::default()
            },
            // FBit enabled in H265NALUHeader
            TestType {
                raw: &[0x80, 0x01, 0x93, 0xaf, 0xaf, 0xaf, 0xaf],
                expected_err: Some(PacketError::ErrH265CorruptedPacket),
                ..Default::default()
            },
            // Valid H265SingleNALUnitPacket
            TestType {
                raw: &[0x01, 0x01, 0xab, 0xcd, 0xef],
                expected_packet_type: Some(H265Payload::H265SingleNALUnitPacket(
                    H265SingleNALUnitPacket::default(),
                )),
                ..Default::default()
            },
            // Invalid H265SingleNALUnitPacket
            TestType {
                raw: &[0x01, 0x01, 0x93, 0xaf],
                expected_err: Some(PacketError::ErrShortPacket),
                with_donl: true,
                ..Default::default()
            },
            // Valid H265PACIPacket
            TestType {
                raw: &[
                    0x64, 0x01, 0x64, 0b00111000, 0xaa, 0xbb, 0x80, 0xab, 0xcd, 0xef,
                ],
                expected_packet_type: Some(H265Payload::H265PACIPacket(H265PACIPacket::default())),
                ..Default::default()
            },
            // Valid H265FragmentationUnitPacket
            TestType {
                raw: &[0x62, 0x01, 0x93, 0xcc, 0xdd, 0xaf, 0x0d, 0x5a],
                expected_packet_type: Some(H265Payload::H265FragmentationUnitPacket(
                    H265FragmentationUnitPacket::default(),
                )),
                with_donl: true,
                ..Default::default()
            },
            // Valid H265AggregationPacket
            TestType {
                raw: &[
                    0x60, 0x01, 0xcc, 0xdd, 0x00, 0x02, 0xff, 0xee, 0x77, 0x00, 0x01, 0xaa,
                ],
                expected_packet_type: Some(H265Payload::H265AggregationPacket(
                    H265AggregationPacket::default(),
                )),
                with_donl: true,
                ..Default::default()
            },
            // Invalid H265AggregationPacket
            TestType {
                raw: &[0x60, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00],
                expected_err: Some(PacketError::ErrShortPacket),
                with_donl: true,
                ..Default::default()
            },
        ];

        for cur in tests {
            let mut pck = H265Depacketizer::default();
            if cur.with_donl {
                pck.with_donl(true);
            }

            let mut out = Vec::new();
            let mut extra = CodecExtra::None;
            let result = pck.depacketize(&cur.raw, &mut out, &mut extra);

            if cur.expected_err.is_some() && result.is_ok() {
                assert!(false, "should error");
            } else if cur.expected_err.is_none() && result.is_err() {
                assert!(false, "should not error");
            }

            if cur.expected_err.is_some() {
                continue;
            }

            if let Some(expected_packet_type) = &cur.expected_packet_type {
                //TODO: assert_eq!(pck.packet(), expected_packet_type, "invalid packet type");
                let pck_packet = pck.payload();
                match (pck_packet, expected_packet_type) {
                    (
                        &H265Payload::H265SingleNALUnitPacket(_),
                        &H265Payload::H265SingleNALUnitPacket(_),
                    ) => assert!(true),
                    (
                        &H265Payload::H265FragmentationUnitPacket(_),
                        &H265Payload::H265FragmentationUnitPacket(_),
                    ) => assert!(true),
                    (
                        &H265Payload::H265AggregationPacket(_),
                        &H265Payload::H265AggregationPacket(_),
                    ) => assert!(true),
                    (&H265Payload::H265PACIPacket(_), &H265Payload::H265PACIPacket(_)) => {
                        assert!(true)
                    }
                    _ => assert!(false),
                };
            }
        }

        Ok(())
    }

    #[test]
    fn test_h265_packet_real() -> Result<()> {
        // Tests decoding of real H265 payloads extracted from a Wireshark dump.
        let tests = vec![
        b"\x40\x01\x0c\x01\xff\xff\x01\x60\x00\x00\x03\x00\xb0\x00\x00\x03\x00\x00\x03\x00\x7b\xac\x09".to_vec(),
        b"\x42\x01\x01\x01\x60\x00\x00\x03\x00\xb0\x00\x00\x03\x00\x00\x03\x00\x7b\xa0\x03\xc0\x80\x10\xe5\x8d\xae\x49\x32\xf4\xdc\x04\x04\x04\x02".to_vec(),
        b"\x44\x01\xc0\xf2\xf0\x3c\x90".to_vec(),
        b"\x4e\x01\xe5\x04\x61\x0c\x00\x00\x80".to_vec(),
        b"\x62\x01\x93\xaf\x0d\x5a\xfe\x67\x77\x29\xc0\x74\xf3\x57\x4c\x16\x94\xaa\x7c\x2a\x64\x5f\xe9\xa5\xb7\x2a\xa3\x95\x9d\x94\xa7\xb4\xd3\xc4\x4a\xb1\xb7\x69\xca\xbe\x75\xc5\x64\xa8\x97\x4b\x8a\xbf\x7e\xf0\x0f\xc3\x22\x60\x67\xab\xae\x96\xd6\x99\xca\x7a\x8d\x35\x93\x1a\x67\x60\xe7\xbe\x7e\x13\x95\x3c\xe0\x11\xc1\xc1\xa7\x48\xef\xf7\x7b\xb0\xeb\x35\x49\x81\x4e\x4e\x54\xf7\x31\x6a\x38\xa1\xa7\x0c\xd6\xbe\x3b\x25\xba\x08\x19\x0b\x49\xfd\x90\xbb\x73\x7a\x45\x8c\xb9\x73\x43\x04\xc5\x5f\xda\x0f\xd5\x70\x4c\x11\xee\x72\xb8\x6a\xb4\x95\x62\x64\xb6\x23\x14\x7e\xdb\x0e\xa5\x0f\x86\x31\xe4\xd1\x64\x56\x43\xf6\xb7\xe7\x1b\x93\x4a\xeb\xd0\xa6\xe3\x1f\xce\xda\x15\x67\x05\xb6\x77\x36\x8b\x27\x5b\xc6\xf2\x95\xb8\x2b\xcc\x9b\x0a\x03\x05\xbe\xc3\xd3\x85\xf5\x69\xb6\x19\x1f\x63\x2d\x8b\x65\x9e\xc3\x9d\xd2\x44\xb3\x7c\x86\x3b\xea\xa8\x5d\x02\xe5\x40\x03\x20\x76\x48\xff\xf6\x2b\x0d\x18\xd6\x4d\x49\x70\x1a\x5e\xb2\x89\xca\xec\x71\x41\x79\x4e\x94\x17\x0c\x57\x51\x55\x14\x61\x40\x46\x4b\x3e\x17\xb2\xc8\xbd\x1c\x06\x13\x91\x72\xf8\xc8\xfc\x6f\xb0\x30\x9a\xec\x3b\xa6\xc9\x33\x0b\xa5\xe5\xf4\x65\x7a\x29\x8b\x76\x62\x81\x12\xaf\x20\x4c\xd9\x21\x23\x9e\xeb\xc9\x0e\x5b\x29\x35\x7f\x41\xcd\xce\xa1\xc4\xbe\x01\x30\xb9\x11\xc3\xb1\xe4\xce\x45\xd2\x5c\xb3\x1e\x69\x78\xba\xb1\x72\xe4\x88\x54\xd8\x5d\xd0\xa8\x3a\x74\xad\xe5\xc7\xc1\x59\x7c\x78\x15\x26\x37\x3d\x50\xae\xb3\xa4\x5b\x6c\x7d\x65\x66\x85\x4d\x16\x9a\x67\x74\xad\x55\x32\x3a\x84\x85\x0b\x6a\xeb\x24\x97\xb4\x20\x4d\xca\x41\x61\x7a\xd1\x7b\x60\xdb\x7f\xd5\x61\x22\xcf\xd1\x7e\x4c\xf3\x85\xfd\x13\x63\xe4\x9d\xed\xac\x13\x0a\xa0\x92\xb7\x34\xde\x65\x0f\xd9\x0f\x9b\xac\xe2\x47\xe8\x5c\xb3\x11\x8e\xc6\x08\x19\xd0\xb0\x85\x52\xc8\x5c\x1b\x08\x0a\xce\xc9\x6b\xa7\xef\x95\x2f\xd0\xb8\x63\xe5\x4c\xd4\xed\x6e\x87\xe9\xd4\x0a\xe6\x11\x44\x63\x00\x94\x18\xe9\x28\xba\xcf\x92\x43\x06\x59\xdd\x37\x4f\xd3\xef\x9d\x31\x5e\x9b\x48\xf9\x1f\x3e\x7b\x95\x3a\xbd\x1f\x71\x55\x0c\x06\xf9\x86\xf8\x3d\x39\x16\x50\xb3\x21\x11\x19\x6f\x70\xa9\x48\xe8\xbb\x0a\x11\x23\xf8\xab\xfe\x44\xe0\xbb\xe8\x64\xfa\x85\xe4\x02\x55\x88\x41\xc6\x30\x7f\x10\xad\x75\x02\x4b\xef\xe1\x0b\x06\x3c\x10\x49\x83\xf9\xd1\x3e\x3e\x67\x86\x4c\xf8\x9d\xde\x5a\xc4\xc8\xcf\xb6\xf4\xb0\xd3\x34\x58\xd4\x7b\x4d\xd3\x37\x63\xb2\x48\x8a\x7e\x20\x00\xde\xb4\x42\x8f\xda\xe9\x43\x9e\x0c\x16\xce\x79\xac\x2c\x70\xc1\x89\x05\x36\x62\x6e\xd9\xbc\xfb\x63\xc6\x79\x89\x3c\x90\x89\x2b\xd1\x8c\xe0\xc2\x54\xc7\xd6\xb4\xe8\x9e\x96\x55\x6e\x7b\xd5\x7f\xac\xd4\xa7\x1c\xa0\xdf\x01\x30\xad\xc0\x9f\x69\x06\x10\x43\x7f\xf4\x5d\x62\xa3\xea\x73\xf2\x14\x79\x19\x13\xea\x59\x14\x79\xa8\xe7\xce\xce\x44\x25\x13\x41\x18\x57\xdd\xce\xe4\xbe\xcc\x20\x80\x29\x71\x73\xa7\x7c\x86\x39\x76\xf4\xa7\x1c\x63\x24\x21\x93\x1e\xb5\x9a\x5c\x8a\x9e\xda\x8b\x9d\x88\x97\xfc\x98\x7d\x26\x74\x04\x1f\xa8\x10\x4f\x45\xcd\x46\xe8\x28\xe4\x8e\x59\x67\x63\x4a\xcf\x1e\xed\xdd\xbb\x79\x2f\x8d\x94\xab\xfc\xdb\xc5\x79\x1a\x4d\xcd\x53\x41\xdf\xd1\x7a\x8f\x46\x3e\x1f\x79\x88\xe3\xee\x9f\xc4\xc1\xe6\x2e\x89\x4d\x28\xc9\xca\x28\xc2\x0a\xc5\xc7\xf1\x22\xcd\xb3\x36\xfa\xe3\x7e\xa6\xcd\x95\x55\x5e\x0e\x1a\x75\x7f\x65\x27\xd3\x37\x4f\x23\xc5\xab\x49\x68\x4e\x02\xb5\xbf\xd7\x95\xc0\x78\x67\xbc\x1a\xe9\xae\x6f\x44\x58\x8a\xc2\xce\x42\x98\x4e\x77\xc7\x2a\xa0\xa7\x7d\xe4\x3b\xd1\x20\x82\x1a\xd3\xe2\xc7\x76\x5d\x06\x46\xb5\x24\xd7\xfb\x57\x63\x2b\x19\x51\x48\x65\x6d\xfb\xe0\x98\xd1\x14\x0e\x17\x64\x29\x34\x6f\x6e\x66\x9e\x8d\xc9\x89\x49\x69\xee\x74\xf3\x35\xe6\x8b\x67\x56\x95\x7f\x1b\xe9\xed\x8c\x0f\xe2\x19\x59\xbf\x03\x35\x55\x3c\x04\xbc\x40\x52\x90\x10\x08\xad\xa7\x65\xe0\x31\xcb\xcf\x3d\xd4\x62\x68\x01\x0d\xed\xf5\x28\x64\x2d\xaa\x7c\x99\x15\x8d\x70\x32\x53\xb8\x9d\x0a\x3c\xbf\x91\x02\x04\xd0\xee\x87\xce\x04\xcc\x3e\xa8\x20\xfd\x97\xdf\xbf\x4a\xbc\xfc\xc9\x7c\x77\x21\xcc\x23\x6f\x59\x38\xd8\xd9\xa0\x0e\xb1\x23\x4e\x04\x3f\x14\x9e\xcc\x05\x54\xab\x20\x69\xed\xa4\xd5\x1d\xb4\x1b\x52\xed\x6a\xea\xeb\x7f\xd1\xbc\xfd\x75\x20\xa0\x1c\x59\x8c\x5a\xa1\x2a\x70\x64\x11\xb1\x7b\xc1\x24\x80\x28\x51\x4c\x94\xa1\x95\x64\x72\xe8\x90\x67\x38\x74\x2b\xab\x38\x46\x12\x71\xce\x19\x98\x98\xf7\x89\xd4\xfe\x2f\x2a\xc5\x61\x20\xd0\xa4\x1a\x51\x3c\x82\xc8\x18\x31\x7a\x10\xe8\x1c\xc6\x95\x5a\xa0\x82\x88\xce\x8f\x4b\x47\x85\x7e\x89\x95\x95\x52\x1e\xac\xce\x45\x57\x61\x38\x97\x2b\x62\xa5\x14\x6f\xc3\xaa\x6c\x35\x83\xc9\xa3\x1e\x30\x89\xf4\xb1\xea\x4f\x39\xde\xde\xc7\x46\x5c\x0e\x85\x41\xec\x6a\xa4\xcb\xee\x70\x9c\x57\xd9\xf4\xa1\xc3\x9c\x2a\x0a\xf0\x5d\x58\xb0\xae\xd4\xdc\xc5\x6a\xa8\x34\xfa\x23\xef\xef\x08\x39\xc3\x3d\xea\x11\x6e\x6a\xe0\x1e\xd0\x52\xa8\xc3\x6e\xc9\x1c\xfc\xd0\x0c\x4c\xea\x0d\x82\xcb\xdd\x29\x1a\xc4\x4f\x6e\xa3\x4d\xcb\x7a\x38\x77\xe5\x15\x6e\xad\xfa\x9d\x2f\x02\xb6\x39\x84\x3a\x60\x8f\x71\x9f\x92\xe5\x24\x4f\xbd\x18\x49\xd5\xef\xbf\x70\xfb\xd1\x4c\x2e\xfc\x2f\x36\xf3\x00\x31\x2e\x90\x18\xcc\xf4\x71\xb9\xe4\xf9\xbe\xcb\x5e\xff\xf3\xe7\xf8\xca\x03\x60\x66\xb3\xc9\x5a\xf9\x74\x09\x02\x57\xb6\x90\x94\xfc\x41\x35\xdc\x35\x3f\x32\x7a\xa6\xa5\xcd\x8a\x8f\xc8\x3d\xc8\x81\xc3\xec\x37\x74\x86\x61\x41\x0d\xc5\xe2\xc8\x0c\x84\x2b\x3b\x71\x58\xde\x1b\xe3\x20\x65\x2e\x76\xf4\x98\xd8\xaa\x78\xe6\xeb\xb8\x85\x0d\xa0\xd0\xf5\x57\x64\x01\x58\x55\x82\xd5\x0f\x2d\x9c\x3e\x2a\xa0\x7e\xaf\x42\xf3\x37\xd1\xb3\xaf\xda\x5b\xa9\xda\xe3\x89\x5d\xf1\xca\xa5\x12\x3d\xe7\x91\x95\x53\x21\x72\xca\x7f\xf6\x79\x59\x21\xcf\x30\x18\xfb\x78\x55\x40\x59\xc3\xf9\xf1\xdd\x58\x44\x5e\x83\x11\x5c\x2d\x1d\x91\xf6\x01\x3d\x3f\xd4\x33\x81\x66\x6c\x40\x7a\x9d\x70\x10\x58\xe6\x53\xad\x85\x11\x99\x3e\x4b\xbc\x31\xc6\x78\x9d\x79\xc5\xde\x9f\x2e\x43\xfa\x76\x84\x2f\xfd\x28\x75\x12\x48\x25\xfd\x15\x8c\x29\x6a\x91\xa4\x63\xc0\xa2\x8c\x41\x3c\xf1\xb0\xf8\xdf\x66\xeb\xbd\x14\x88\xa9\x81\xa7\x35\xc4\x41\x40\x6c\x10\x3f\x09\xbd\xb5\xd3\x7a\xee\x4b\xd5\x86\xff\x36\x03\x6b\x78\xde".to_vec(),
        b"\x62\x01\x53\x8a\xe9\x25\xe1\x06\x09\x8e\xba\x12\x74\x87\x09\x9a\x95\xe4\x86\x62\x2b\x4b\xf9\xa6\x2e\x7b\x35\x43\xf7\x39\x99\x0f\x3b\x6f\xfd\x1a\x6e\x23\x54\x70\xb5\x1d\x10\x1c\x63\x40\x96\x99\x41\xb6\x96\x0b\x70\x98\xec\x17\xb0\xaa\xdc\x4a\xab\xe8\x3b\xb7\x6b\x00\x1c\x5b\xc3\xe0\xa2\x8b\x7c\x17\xc8\x92\xc9\xb0\x92\xb6\x70\x84\x95\x30".to_vec(),
        b"\x4e\x01\xe5\x04\x35\xac\x00\x00\x80".to_vec(),
        b"\x62\x01\x41\xb0\x75\x5c\x27\x46\xef\x8a\xe7\x1d\x50\x38\xb2\x13\x33\xe0\x79\x35\x1b\xc2\xb5\x79\x73\xe7\xc2\x6f\xb9\x1a\x8c\x21\x0e\xa9\x54\x17\x6c\x41\xab\xc8\x16\x57\xec\x5e\xeb\x89\x3b\xa9\x90\x8c\xff\x4d\x46\x8b\xf0\xd9\xc0\xd0\x51\xcf\x8b\x88\xf1\x5f\x1e\x9e\xc1\xb9\x1f\xe3\x06\x45\x35\x8a\x47\xe8\x9a\xf2\x4f\x19\x4c\xf8\xce\x68\x1b\x63\x34\x11\x75\xea\xe5\xb1\x0f\x38\xcc\x05\x09\x8b\x3e\x2b\x88\x84\x9d\xc5\x03\xc3\xc0\x90\x32\xe2\x45\x69\xb1\xe5\xf7\x68\x6b\x16\x90\xa0\x40\xe6\x18\x74\xd8\x68\xf3\x34\x38\x99\xf2\x6c\xb7\x1a\x35\x21\xca\x52\x56\x4c\x7f\xb2\xa3\xd5\xb8\x40\x50\x48\x3e\xdc\xdf\x0b\xf5\x54\x5a\x15\x1a\xe2\xc3\xb4\x94\xda\x3f\xb5\x34\xa2\xca\xbc\x2f\xe0\xa4\xe5\x69\xf4\xbf\x62\x4d\x15\x21\x1b\x11\xfc\x39\xaa\x86\x74\x96\x63\xfd\x07\x53\x26\xf6\x34\x72\xeb\x14\x37\x98\x0d\xf4\x68\x91\x2c\x6b\x46\x83\x88\x82\x04\x8b\x9f\xb8\x32\x73\x75\x8b\xf9\xac\x71\x42\xd1\x2d\xb4\x28\x28\xf5\x78\xe0\x32\xf3\xe1\xfc\x43\x6b\xf9\x92\xf7\x48\xfe\x7f\xc0\x17\xbd\xfd\xba\x2f\x58\x6f\xee\x84\x03\x18\xce\xb0\x9d\x8d\xeb\x22\xf1\xfc\xb1\xcf\xff\x2f\xb2\x9f\x6c\xe5\xb4\x69\xdc\xdd\x20\x93\x00\x30\xad\x56\x04\x66\x7e\xa3\x3c\x18\x4b\x43\x66\x00\x27\x1e\x1c\x09\x11\xd8\xf4\x8a\x9e\xc5\x6a\x94\xe5\xae\x0b\x8a\xbe\x84\xda\xe5\x44\x7f\x38\x1c\xe7\xbb\x03\x19\x66\xe1\x5d\x1d\xc1\xbd\x3d\xc6\xb7\xe3\xff\x7f\x8e\xff\x1e\xf6\x9e\x6f\x58\x27\x74\x65\xef\x02\x5d\xa4\xde\x27\x7f\x51\xe3\x4b\x9e\x3f\x79\x83\xbd\x1b\x8f\x0d\x77\xfb\xbc\xc5\x9f\x15\xa7\x4e\x05\x8a\x24\x97\x66\xb2\x7c\xf6\xe1\x84\x54\xdb\x39\x5e\xf6\x1b\x8f\x05\x73\x1d\xb6\x8e\xd7\x09\x9a\xc5\x92\x80".to_vec(),
    ];

        for cur in tests {
            let mut pck = H265Depacketizer::default();
            let mut out = Vec::new();
            let mut extra = CodecExtra::None;
            let _ = pck.depacketize(&cur, &mut out, &mut extra)?;
        }

        Ok(())
    }
}
