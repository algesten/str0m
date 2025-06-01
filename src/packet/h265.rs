#![allow(clippy::all)]
#![allow(unused)]

use super::{CodecExtra, Depacketizer, PacketError, Packetizer};

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
    fn is_partition_head(&self, packet: &[u8]) -> bool {
        if packet.len() < 3 {
            return false;
        }

        let header = H265NALUHeader::new(packet[0], packet[1]);

        if header.is_fragmentation_unit() {
            H265FragmentationUnitHeader(packet[2]).s()
        } else {
            true // AP and Single NALU packets are always partition heads
        }
    }

    fn is_partition_tail(&self, marker: bool, _payload: &[u8]) -> bool {
        marker
    }
}

#[derive(Default, Debug, Clone)]
pub struct H265Packetizer {
    pub add_donl: bool,
    pub skip_aggregation: bool,
    pub donl: u16,
}

impl H265Packetizer {
    // Helper function to find next Annex B start code (copied from H264)
    fn next_ind(nalu: &[u8], start: usize) -> (isize, isize) {
        let mut zero_count = 0;

        for (i, &b) in nalu[start..].iter().enumerate() {
            if b == 0 {
                zero_count += 1;
                continue;
            } else if b == 1 && zero_count >= 2 {
                return ((start + i - zero_count) as isize, zero_count as isize + 1);
            }
            zero_count = 0
        }
        (-1, -1)
    }

    // Process individual NALU
    fn process_nalu(
        &mut self,
        nalu: &[u8],
        mtu: usize,
        buffered_nalus: &mut Vec<Vec<u8>>,
        aggregation_buffer_size: &mut usize,
        payloads: &mut Vec<Vec<u8>>,
    ) {
        if nalu.len() < H265NALU_HEADER_SIZE {
            return;
        }

        let header = H265NALUHeader::new(nalu[0], nalu[1]);
        let nalu_type = header.nalu_type();

        // Calculate size needed for this NALU
        let single_nalu_size = if self.add_donl {
            nalu.len() + 2
        } else {
            nalu.len()
        };

        // Handle large NALUs via fragmentation
        if single_nalu_size + H265NALU_HEADER_SIZE > mtu {
            if !buffered_nalus.is_empty() {
                self.flush_buffered_nalus(buffered_nalus, payloads);
                *aggregation_buffer_size = 0;
            }
            self.fragment_nalu(nalu, mtu, payloads);
            return;
        }

        // Calculate marginal size if added to aggregation packet
        let marginal_size = if buffered_nalus.is_empty() {
            // Aggregation header + NALU size + possible DONL
            2 + 2 + nalu.len() + if self.add_donl { 2 } else { 0 }
        } else {
            // NALU size + possible DOND
            2 + nalu.len() + if self.add_donl { 1 } else { 0 }
        };

        // Flush if this NALU doesn't fit in current aggregation
        if *aggregation_buffer_size + marginal_size > mtu {
            self.flush_buffered_nalus(buffered_nalus, payloads);
            *aggregation_buffer_size = 0;
        }

        // Add to buffer or output immediately
        if self.skip_aggregation {
            self.output_single_nalu(nalu, payloads);
        } else {
            buffered_nalus.push(nalu.to_vec());
            *aggregation_buffer_size += marginal_size;
        }
    }

    // Output a single NALU packet
    fn output_single_nalu(&mut self, nalu: &[u8], payloads: &mut Vec<Vec<u8>>) {
        if self.add_donl {
            let mut packet = Vec::with_capacity(nalu.len() + 2);
            packet.extend_from_slice(&nalu[0..2]);
            packet.extend_from_slice(&self.donl.to_be_bytes());
            packet.extend_from_slice(&nalu[2..]);
            payloads.push(packet);
            self.donl = self.donl.wrapping_add(1);
        } else {
            payloads.push(nalu.to_vec());
        }
    }

    // Flush buffered NALUs as aggregation packet or singles
    fn flush_buffered_nalus(
        &mut self,
        buffered_nalus: &mut Vec<Vec<u8>>,
        payloads: &mut Vec<Vec<u8>>,
    ) {
        match buffered_nalus.len() {
            0 => return,
            1 => {
                let nalu = buffered_nalus.remove(0);
                self.output_single_nalu(&nalu, payloads);
            }
            _ => {
                let mut layer_id = u8::MAX;
                let mut tid = u8::MAX;

                // Find min layer_id and tid
                for nalu in buffered_nalus.iter() {
                    let header = H265NALUHeader::new(nalu[0], nalu[1]);
                    layer_id = layer_id.min(header.layer_id());
                    tid = tid.min(header.tid());
                }

                // Build aggregation header
                let aggregation_header = H265NALUHeader(
                    (0 << 15) // F=0
                        | ((H265NALU_AGGREGATION_PACKET_TYPE as u16) << 9)
                        | ((layer_id as u16) << 3)
                        | (tid as u16),
                );

                let mut packet = Vec::new();
                packet.push((aggregation_header.0 >> 8) as u8);
                packet.push(aggregation_header.0 as u8);

                // Add DONL if needed
                if self.add_donl {
                    packet.extend_from_slice(&self.donl.to_be_bytes());
                }

                // Add all buffered NALUs
                for (i, nalu) in buffered_nalus.iter().enumerate() {
                    if self.add_donl && i > 0 {
                        packet.push((i - 1) as u8);
                    }
                    packet.extend_from_slice(&(nalu.len() as u16).to_be_bytes());
                    packet.extend_from_slice(nalu);
                }

                payloads.push(packet);
            }
        }
        buffered_nalus.clear();
    }

    // Fragment a large NALU
    fn fragment_nalu(&mut self, nalu: &[u8], mtu: usize, payloads: &mut Vec<Vec<u8>>) {
        let header = H265NALUHeader::new(nalu[0], nalu[1]);
        let nalu_type = header.nalu_type();
        let payload = &nalu[2..];

        // Calculate available payload size
        let fu_header_size = 1 + if self.add_donl { 2 } else { 0 };

        if mtu <= H265NALU_HEADER_SIZE + fu_header_size {
            return; // Not enough space for even a single FU header
        }

        let max_fragment_size = mtu - H265NALU_HEADER_SIZE - fu_header_size;

        let mut offset = 0;
        let payload_len = payload.len();
        let mut is_first = true;

        while offset < payload_len {
            let fragment_size = std::cmp::min(max_fragment_size, payload_len - offset);
            let is_last = offset + fragment_size == payload_len;

            // Build fragmentation header
            let fragmentation_header = H265NALUHeader(
                (header.0 & 0x81FF) // Keep F and layer/tid bits
                    | ((H265NALU_FRAGMENTATION_UNIT_TYPE as u16) << 9),
            );

            let mut packet =
                Vec::with_capacity(H265NALU_HEADER_SIZE + fu_header_size + fragment_size);

            // Add NALU header
            packet.push((fragmentation_header.0 >> 8) as u8);
            packet.push(fragmentation_header.0 as u8);

            // Add FU header
            let fu_header =
                nalu_type | if is_first { 0x80 } else { 0 } | if is_last { 0x40 } else { 0 };
            packet.push(fu_header);

            // Add DONL if needed
            if self.add_donl {
                packet.extend_from_slice(&self.donl.to_be_bytes());
                self.donl = self.donl.wrapping_add(1);
            }

            // Add payload fragment
            packet.extend_from_slice(&payload[offset..offset + fragment_size]);

            payloads.push(packet);

            offset += fragment_size;
            is_first = false;
        }
    }
}

impl Packetizer for H265Packetizer {
    fn packetize(&mut self, mtu: usize, payload: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        let mut payloads = Vec::new();
        let mut buffered_nalus = Vec::new();
        let mut aggregation_buffer_size = 0;

        // Split into NALUs using Annex B start codes
        let (mut next_ind_start, mut next_ind_len) = Self::next_ind(payload, 0);
        if next_ind_start == -1 {
            // Single NALU mode
            self.process_nalu(
                payload,
                mtu,
                &mut buffered_nalus,
                &mut aggregation_buffer_size,
                &mut payloads,
            );
        } else {
            let mut start = 0;
            while next_ind_start != -1 {
                let nalu_start = (next_ind_start + next_ind_len) as usize;
                let (next_ind_start2, next_ind_len2) = Self::next_ind(payload, nalu_start);
                next_ind_start = next_ind_start2;
                next_ind_len = next_ind_len2;

                let nalu_end = if next_ind_start == -1 {
                    payload.len()
                } else {
                    next_ind_start as usize
                };

                self.process_nalu(
                    &payload[nalu_start..nalu_end],
                    mtu,
                    &mut buffered_nalus,
                    &mut aggregation_buffer_size,
                    &mut payloads,
                );
            }
        }

        // Flush any remaining buffered NALUs
        self.flush_buffered_nalus(&mut buffered_nalus, &mut payloads);

        Ok(payloads)
    }

    fn is_marker(&mut self, _data: &[u8], _previous: Option<&[u8]>, last: bool) -> bool {
        last
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

    #[test]
    fn test_h265_is_partition_head() {
        let depacketizer = H265Depacketizer::default();

        assert!(
            !depacketizer.is_partition_head(&[]),
            "empty nalu must not be a partition head"
        );

        let single_nalu = [0x01, 0x01, 0xab, 0xcd, 0xef];
        assert!(
            depacketizer.is_partition_head(&single_nalu),
            "single nalu must be a partition head"
        );

        let fbit_nalu = [0x80, 0x00, 0x00];
        assert!(
            depacketizer.is_partition_head(&fbit_nalu),
            "fbit nalu must be a partition head"
        );

        let fu_start_nalu = [0x62, 0x01, 0x93];
        assert!(
            depacketizer.is_partition_head(&fu_start_nalu),
            "fu start nalu must be a partition head"
        );

        let fu_end_nalu = [0x62, 0x01, 0x53];
        assert!(
            !depacketizer.is_partition_head(&fu_end_nalu),
            "fu end nalu must not be a partition head"
        );
    }

    struct H265PayloadTestCase<'a> {
        name: &'a str,
        data: &'a [u8],
        mtu: usize,
        add_donl: bool,
        skip_aggregation: bool,
        expected_len: Option<usize>,
        expected_data: Option<Vec<Vec<u8>>>,
        msg: &'a str,
    }

    #[test]
    fn test_h265_payload() -> Result<()> {
        let test_cases = vec![
            H265PayloadTestCase {
                name: "Positive MTU, nil payload",
                mtu: 1,
                data: &[],
                add_donl: false,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "Generated payload must be empty",
            },
            H265PayloadTestCase {
                name: "Positive MTU, empty NAL",
                mtu: 1,
                data: &[],
                add_donl: false,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "Generated payload should be empty",
            },
            H265PayloadTestCase {
                name: "Zero MTU, start code",
                mtu: 0,
                data: &[0x00, 0x00, 0x01],
                add_donl: false,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "Generated payload should be empty",
            },
            H265PayloadTestCase {
                name: "Positive MTU, 1 byte payload",
                mtu: 1,
                data: &[0x90],
                add_donl: false,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "Generated payload should be empty. H.265 nal unit too small",
            },
            H265PayloadTestCase {
                name: "MTU:1, 2 byte payload",
                mtu: 1,
                data: &[0x46, 0x01],
                add_donl: false,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "Generated payload should be empty. H.265 nal unit too small",
            },
            H265PayloadTestCase {
                name: "MTU:2, 2 byte payload",
                mtu: 2,
                data: &[0x46, 0x01],
                add_donl: false,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "Generated payload should be empty. min MTU is 4",
            },
            H265PayloadTestCase {
                name: "MTU:4, 2 byte payload",
                mtu: 4,
                data: &[0x46, 0x01],
                add_donl: false,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![vec![0x46, 0x01]]),
                msg: "AUD packetization failed",
            },
            H265PayloadTestCase {
                name: "Negative MTU, small payload",
                mtu: 0,
                data: &[0x90, 0x90, 0x90],
                add_donl: false,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "",
            },
            H265PayloadTestCase {
                name: "MTU:1, small payload",
                mtu: 1,
                data: &[0x90, 0x90, 0x90],
                add_donl: false,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "",
            },
            H265PayloadTestCase {
                name: "MTU:5, small payload",
                mtu: 5,
                data: &[0x90, 0x90, 0x90],
                add_donl: false,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![vec![0x90, 0x90, 0x90]]),
                msg: "",
            },
            H265PayloadTestCase {
                name: "Large payload",
                mtu: 5,
                data: &[
                    0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                ],
                add_donl: false,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![
                    vec![0x62, 0x01, 0x80, 0x02, 0x03],
                    vec![0x62, 0x01, 0x00, 0x04, 0x05],
                    vec![0x62, 0x01, 0x00, 0x06, 0x07],
                    vec![0x62, 0x01, 0x00, 0x08, 0x09],
                    vec![0x62, 0x01, 0x00, 0x10, 0x11],
                    vec![0x62, 0x01, 0x00, 0x12, 0x13],
                    vec![0x62, 0x01, 0x40, 0x14, 0x15],
                ]),
                msg: "Large payload split across fragmentation Packets",
            },
            H265PayloadTestCase {
                name: "Short MTU, multiple NALUs flushed in single packet",
                mtu: 5,
                data: &[0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03],
                add_donl: false,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![vec![0x00, 0x01], vec![0x02, 0x03]]),
                msg: "multiple Single NALUs packetization should succeed",
            },
            H265PayloadTestCase {
                name: "Enough MTU, multiple NALUs create Single Packet",
                mtu: 10,
                data: &[0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03],
                add_donl: false,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![vec![
                    0x60, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x02, 0x03,
                ]]),
                msg: "Aggregation packetization should succeed",
            },
            H265PayloadTestCase {
                name: "Enough MTU, multiple NALUs flushed two Packets, don't aggregate",
                mtu: 5,
                data: &[
                    0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x01,
                    0x04, 0x05,
                ],
                add_donl: false,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![vec![0x00, 0x01], vec![0x02, 0x03], vec![0x04, 0x05]]),
                msg: "multiple Single NALUs packetization should succeed",
            },
            H265PayloadTestCase {
                name: "Enough MTU, multiple NALUs flushed two Packets, aggregate",
                mtu: 15,
                data: &[
                    0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x01,
                    0x04, 0x05,
                ],
                add_donl: false,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![vec![
                    0x60, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x02, 0x03, 0x00, 0x02, 0x04,
                    0x05,
                ]]),
                msg: "Aggregation packetization should succeed",
            },
            // Add DONL = true
            H265PayloadTestCase {
                name: "DONL, invalid MTU:1",
                mtu: 1,
                data: &[0x01],
                add_donl: true,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "Generated payload must be empty",
            },
            H265PayloadTestCase {
                name: "DONL MTU:4, 2 byte payload",
                mtu: 4,
                data: &[0x00, 0x01],
                add_donl: true,
                skip_aggregation: false,
                expected_len: Some(0),
                expected_data: None,
                msg: "Generated payload must be empty",
            },
            H265PayloadTestCase {
                name: "DONL single NALU minimum payload",
                mtu: 6,
                data: &[0x00, 0x01],
                add_donl: true,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![vec![0x00, 0x01, 0x00, 0x00]]),
                msg: "single NALU should be packetized",
            },
            H265PayloadTestCase {
                name: "DONL multiple NALU",
                mtu: 6,
                data: &[
                    0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x01,
                    0x04, 0x05,
                ],
                add_donl: true,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![
                    vec![0x00, 0x01, 0x00, 0x00],
                    vec![0x02, 0x03, 0x00, 0x01],
                    vec![0x04, 0x05, 0x00, 0x02],
                ]),
                msg: "DONL should be incremented",
            },
            H265PayloadTestCase {
                name: "DONL aggregation minimum payload",
                mtu: 18,
                data: &[
                    0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x01,
                    0x04, 0x05,
                ],
                add_donl: true,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![vec![
                    0x60, 0x01, // NALU Header + Layer ID + TID
                    0x00, 0x00, // DONL
                    0x00, 0x02, 0x00, 0x01, 0x00, // DONL
                    0x00, 0x02, 0x02, 0x03, 0x01, // DONL
                    0x00, 0x02, 0x04, 0x05,
                ]]),
                msg: "DONL Aggregation packetization should succeed",
            },
            H265PayloadTestCase {
                name: "DONL Large payload",
                mtu: 7,
                data: &[
                    0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                ],
                add_donl: true,
                skip_aggregation: false,
                expected_len: None,
                expected_data: Some(vec![
                    vec![0x62, 0x01, 0x80, 0x00, 0x00, 0x02, 0x03],
                    vec![0x62, 0x01, 0x00, 0x00, 0x01, 0x04, 0x05],
                    vec![0x62, 0x01, 0x00, 0x00, 0x02, 0x06, 0x07],
                    vec![0x62, 0x01, 0x00, 0x00, 0x03, 0x08, 0x09],
                    vec![0x62, 0x01, 0x00, 0x00, 0x04, 0x10, 0x11],
                    vec![0x62, 0x01, 0x00, 0x00, 0x05, 0x12, 0x13],
                    vec![0x62, 0x01, 0x40, 0x00, 0x06, 0x14, 0x15],
                ]),
                msg: "DONL Large payload split across fragmentation Packets",
            },
            // SkipAggregation = true
            H265PayloadTestCase {
                name: "SkipAggregation Enough MUT, multiple NALUs",
                mtu: 4,
                data: &[
                    0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x01,
                    0x04, 0x05,
                ],
                add_donl: false,
                skip_aggregation: true,
                expected_len: None,
                expected_data: Some(vec![vec![0x00, 0x01], vec![0x02, 0x03], vec![0x04, 0x05]]),
                msg: "Aggregation packetization should be skipped",
            },
        ];

        for case in test_cases {
            let mut pck = H265Packetizer {
                add_donl: case.add_donl,
                skip_aggregation: case.skip_aggregation,
                donl: 0,
            };

            let res = pck.packetize(case.mtu, case.data)?;

            if let Some(expected_data) = case.expected_data {
                assert_eq!(res, expected_data, "{}: {}", case.name, case.msg);
            } else if let Some(expected_len) = case.expected_len {
                assert_eq!(res.len(), expected_len, "{}: {}", case.name, case.msg);
            }
        }

        Ok(())
    }

    #[test]
    fn test_h265_real_payload() -> Result<()> {
        // curl -LO "https://test-videos.co.uk/vids/bigbuckbunny/mp4/h265/1080/Big_Buck_Bunny_1080_10s_1MB.mp4"
        // ffmpeg -i Big_Buck_Bunny_1080_10s_1MB.mp4 -c:v copy Big_Buck_Bunny_1080_10s_1MB.h265
        // hexdump -v -e '1/1 "0x%02x, "' Big_Buck_Bunny_1080_10s_1MB.h265 > aaa

        let payload: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x00, 0x90, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x78, 0x95, 0x98, 0x09,
            0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x78, 0xa0, 0x03, 0xc0, 0x80, 0x10, 0xe5,
            0x96, 0x56, 0x69, 0x24, 0xca, 0xf0, 0x10, 0x10, 0x00, 0x00, 0x03, 0x00, 0x10, 0x00,
            0x00, 0x03, 0x01, 0xe0, 0x80, 0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xc1, 0x72, 0xb4,
            0x62, 0x40, 0x00, 0x00, 0x00, 0x01, 0x4e, 0x01, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x71, 0x2c, 0xa2, 0xde, 0x09, 0xb5, 0x17, 0x47, 0xdb, 0xbb, 0x55, 0xa4,
            0xfe, 0x7f, 0xc2, 0xfc, 0x4e, 0x78, 0x32, 0x36, 0x35, 0x20, 0x28, 0x62, 0x75, 0x69,
            0x6c, 0x64, 0x20, 0x31, 0x35, 0x31, 0x29, 0x20, 0x2d, 0x20, 0x32, 0x2e, 0x36, 0x2b,
            0x34, 0x39, 0x2d, 0x37, 0x32, 0x31, 0x39, 0x33, 0x37, 0x36, 0x64, 0x65, 0x34, 0x32,
            0x61, 0x3a, 0x5b, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5d, 0x5b, 0x47, 0x43,
            0x43, 0x20, 0x37, 0x2e, 0x33, 0x2e, 0x30, 0x5d, 0x5b, 0x36, 0x34, 0x20, 0x62, 0x69,
            0x74, 0x5d, 0x20, 0x38, 0x62, 0x69, 0x74, 0x2b, 0x31, 0x30, 0x62, 0x69, 0x74, 0x20,
            0x2d, 0x20, 0x48, 0x2e, 0x32, 0x36, 0x35, 0x2f, 0x48, 0x45, 0x56, 0x43, 0x20, 0x63,
            0x6f, 0x64, 0x65, 0x63, 0x20, 0x2d, 0x20, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67,
            0x68, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33, 0x2d, 0x32, 0x30, 0x31, 0x38, 0x20, 0x28,
            0x63, 0x29, 0x20, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x63, 0x6f, 0x72, 0x65, 0x77, 0x61,
            0x72, 0x65, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x20, 0x2d, 0x20, 0x68, 0x74, 0x74, 0x70,
            0x3a, 0x2f, 0x2f, 0x78, 0x32, 0x36, 0x35, 0x2e, 0x6f, 0x72, 0x67, 0x20, 0x2d, 0x20,
            0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x3a, 0x20, 0x63, 0x70, 0x75, 0x69, 0x64,
            0x3d, 0x31, 0x30, 0x35, 0x30, 0x31, 0x31, 0x31, 0x20, 0x66, 0x72, 0x61, 0x6d, 0x65,
            0x2d, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x73, 0x3d, 0x33, 0x20, 0x6e, 0x75, 0x6d,
            0x61, 0x2d, 0x70, 0x6f, 0x6f, 0x6c, 0x73, 0x3d, 0x38, 0x20, 0x77, 0x70, 0x70, 0x20,
            0x6e, 0x6f, 0x2d, 0x70, 0x6d, 0x6f, 0x64, 0x65, 0x20, 0x6e, 0x6f, 0x2d, 0x70, 0x6d,
            0x65, 0x20, 0x6e, 0x6f, 0x2d, 0x70, 0x73, 0x6e, 0x72, 0x20, 0x6e, 0x6f, 0x2d, 0x73,
            0x73, 0x69, 0x6d, 0x20, 0x6c, 0x6f, 0x67, 0x2d, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x3d,
            0x32, 0x20, 0x62, 0x69, 0x74, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3d, 0x38, 0x20, 0x69,
            0x6e, 0x70, 0x75, 0x74, 0x2d, 0x63, 0x73, 0x70, 0x3d, 0x31, 0x20, 0x66, 0x70, 0x73,
            0x3d, 0x33, 0x30, 0x2f, 0x31, 0x20, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x2d, 0x72, 0x65,
            0x73, 0x3d, 0x31, 0x39, 0x32, 0x30, 0x78, 0x31, 0x30, 0x38, 0x30, 0x20, 0x69, 0x6e,
            0x74, 0x65, 0x72, 0x6c, 0x61, 0x63, 0x65, 0x3d, 0x30, 0x20, 0x74, 0x6f, 0x74, 0x61,
            0x6c, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x73, 0x3d, 0x30, 0x20, 0x6c, 0x65, 0x76,
            0x65, 0x6c, 0x2d, 0x69, 0x64, 0x63, 0x3d, 0x30, 0x20, 0x68, 0x69, 0x67, 0x68, 0x2d,
            0x74, 0x69, 0x65, 0x72, 0x3d, 0x31, 0x20, 0x75, 0x68, 0x64, 0x2d, 0x62, 0x64, 0x3d,
            0x30, 0x20, 0x72, 0x65, 0x66, 0x3d, 0x34, 0x20, 0x6e, 0x6f, 0x2d, 0x61, 0x6c, 0x6c,
            0x6f, 0x77, 0x2d, 0x6e, 0x6f, 0x6e, 0x2d, 0x63, 0x6f, 0x6e, 0x66, 0x6f, 0x72, 0x6d,
            0x61, 0x6e, 0x63, 0x65, 0x20, 0x6e, 0x6f, 0x2d, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74,
            0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x20, 0x61, 0x6e, 0x6e, 0x65, 0x78,
            0x62, 0x20, 0x6e, 0x6f, 0x2d, 0x61, 0x75, 0x64, 0x20, 0x6e, 0x6f, 0x2d, 0x68, 0x72,
            0x64, 0x20, 0x69, 0x6e, 0x66, 0x6f, 0x20, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x30, 0x20,
            0x6e, 0x6f, 0x2d, 0x74, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x61, 0x6c, 0x2d, 0x6c, 0x61,
            0x79, 0x65, 0x72, 0x73, 0x20, 0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x67, 0x6f, 0x70, 0x20,
            0x6d, 0x69, 0x6e, 0x2d, 0x6b, 0x65, 0x79, 0x69, 0x6e, 0x74, 0x3d, 0x32, 0x35, 0x20,
            0x6b, 0x65, 0x79, 0x69, 0x6e, 0x74, 0x3d, 0x32, 0x35, 0x30, 0x20, 0x67, 0x6f, 0x70,
            0x2d, 0x6c, 0x6f, 0x6f, 0x6b, 0x61, 0x68, 0x65, 0x61, 0x64, 0x3d, 0x30, 0x20, 0x62,
            0x66, 0x72, 0x61, 0x6d, 0x65, 0x73, 0x3d, 0x34, 0x20, 0x62, 0x2d, 0x61, 0x64, 0x61,
            0x70, 0x74, 0x3d, 0x32, 0x20, 0x62, 0x2d, 0x70, 0x79, 0x72, 0x61, 0x6d, 0x69, 0x64,
            0x20, 0x62, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x2d, 0x62, 0x69, 0x61, 0x73, 0x3d, 0x30,
            0x20, 0x72, 0x63, 0x2d, 0x6c, 0x6f, 0x6f, 0x6b, 0x61, 0x68, 0x65, 0x61, 0x64, 0x3d,
            0x32, 0x35, 0x20, 0x6c, 0x6f, 0x6f, 0x6b, 0x61, 0x68, 0x65, 0x61, 0x64, 0x2d, 0x73,
            0x6c, 0x69, 0x63, 0x65, 0x73, 0x3d, 0x34, 0x20, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x63,
            0x75, 0x74, 0x3d, 0x34, 0x30, 0x20, 0x72, 0x61, 0x64, 0x6c, 0x3d, 0x30, 0x20, 0x6e,
            0x6f, 0x2d, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x2d, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73,
            0x68, 0x20, 0x63, 0x74, 0x75, 0x3d, 0x36, 0x34, 0x20, 0x6d, 0x69, 0x6e, 0x2d, 0x63,
            0x75, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x38, 0x20, 0x72, 0x65, 0x63, 0x74, 0x20,
            0x6e, 0x6f, 0x2d, 0x61, 0x6d, 0x70, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x74, 0x75, 0x2d,
            0x73, 0x69, 0x7a, 0x65, 0x3d, 0x33, 0x32, 0x20, 0x74, 0x75, 0x2d, 0x69, 0x6e, 0x74,
            0x65, 0x72, 0x2d, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3d, 0x31, 0x20, 0x74, 0x75, 0x2d,
            0x69, 0x6e, 0x74, 0x72, 0x61, 0x2d, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3d, 0x31, 0x20,
            0x6c, 0x69, 0x6d, 0x69, 0x74, 0x2d, 0x74, 0x75, 0x3d, 0x30, 0x20, 0x72, 0x64, 0x6f,
            0x71, 0x2d, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x3d, 0x32, 0x20, 0x64, 0x79, 0x6e, 0x61,
            0x6d, 0x69, 0x63, 0x2d, 0x72, 0x64, 0x3d, 0x30, 0x2e, 0x30, 0x30, 0x20, 0x6e, 0x6f,
            0x2d, 0x73, 0x73, 0x69, 0x6d, 0x2d, 0x72, 0x64, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x68,
            0x69, 0x64, 0x65, 0x20, 0x6e, 0x6f, 0x2d, 0x74, 0x73, 0x6b, 0x69, 0x70, 0x20, 0x6e,
            0x72, 0x2d, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x3d, 0x30, 0x20, 0x6e, 0x72, 0x2d, 0x69,
            0x6e, 0x74, 0x65, 0x72, 0x3d, 0x30, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x73,
            0x74, 0x72, 0x61, 0x69, 0x6e, 0x65, 0x64, 0x2d, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x20,
            0x73, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x2d, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x2d, 0x73,
            0x6d, 0x6f, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x6d,
            0x65, 0x72, 0x67, 0x65, 0x3d, 0x33, 0x20, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x2d, 0x72,
            0x65, 0x66, 0x73, 0x3d, 0x33, 0x20, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x2d, 0x6d, 0x6f,
            0x64, 0x65, 0x73, 0x20, 0x6d, 0x65, 0x3d, 0x33, 0x20, 0x73, 0x75, 0x62, 0x6d, 0x65,
            0x3d, 0x33, 0x20, 0x6d, 0x65, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x35, 0x37, 0x20,
            0x74, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x61, 0x6c, 0x2d, 0x6d, 0x76, 0x70, 0x20, 0x77,
            0x65, 0x69, 0x67, 0x68, 0x74, 0x70, 0x20, 0x6e, 0x6f, 0x2d, 0x77, 0x65, 0x69, 0x67,
            0x68, 0x74, 0x62, 0x20, 0x6e, 0x6f, 0x2d, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65,
            0x2d, 0x73, 0x72, 0x63, 0x2d, 0x70, 0x69, 0x63, 0x73, 0x20, 0x64, 0x65, 0x62, 0x6c,
            0x6f, 0x63, 0x6b, 0x3d, 0x30, 0x3a, 0x30, 0x20, 0x73, 0x61, 0x6f, 0x20, 0x6e, 0x6f,
            0x2d, 0x73, 0x61, 0x6f, 0x2d, 0x6e, 0x6f, 0x6e, 0x2d, 0x64, 0x65, 0x62, 0x6c, 0x6f,
            0x63, 0x6b, 0x20, 0x72, 0x64, 0x3d, 0x34, 0x20, 0x6e, 0x6f, 0x2d, 0x65, 0x61, 0x72,
            0x6c, 0x79, 0x2d, 0x73, 0x6b, 0x69, 0x70, 0x20, 0x72, 0x73, 0x6b, 0x69, 0x70, 0x20,
            0x6e, 0x6f, 0x2d, 0x66, 0x61, 0x73, 0x74, 0x2d, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x20,
            0x6e, 0x6f, 0x2d, 0x74, 0x73, 0x6b, 0x69, 0x70, 0x2d, 0x66, 0x61, 0x73, 0x74, 0x20,
            0x6e, 0x6f, 0x2d, 0x63, 0x75, 0x2d, 0x6c, 0x6f, 0x73, 0x73, 0x6c, 0x65, 0x73, 0x73,
            0x20, 0x6e, 0x6f, 0x2d, 0x62, 0x2d, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x20, 0x6e, 0x6f,
            0x2d, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x72, 0x64, 0x2d, 0x73, 0x6b, 0x69, 0x70, 0x20,
            0x72, 0x64, 0x70, 0x65, 0x6e, 0x61, 0x6c, 0x74, 0x79, 0x3d, 0x30, 0x20, 0x70, 0x73,
            0x79, 0x2d, 0x72, 0x64, 0x3d, 0x32, 0x2e, 0x30, 0x30, 0x20, 0x70, 0x73, 0x79, 0x2d,
            0x72, 0x64, 0x6f, 0x71, 0x3d, 0x31, 0x2e, 0x30, 0x30, 0x20, 0x6e, 0x6f, 0x2d, 0x72,
            0x64, 0x2d, 0x72, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x20, 0x6e, 0x6f, 0x2d, 0x6c, 0x6f,
            0x73, 0x73, 0x6c, 0x65, 0x73, 0x73, 0x20, 0x63, 0x62, 0x71, 0x70, 0x6f, 0x66, 0x66,
            0x73, 0x3d, 0x30, 0x20, 0x63, 0x72, 0x71, 0x70, 0x6f, 0x66, 0x66, 0x73, 0x3d, 0x30,
            0x20, 0x72, 0x63, 0x3d, 0x61, 0x62, 0x72, 0x20, 0x62, 0x69, 0x74, 0x72, 0x61, 0x74,
            0x65, 0x3d, 0x38, 0x38, 0x30, 0x20, 0x71, 0x63, 0x6f, 0x6d, 0x70, 0x3d, 0x30, 0x2e,
            0x36, 0x30, 0x20, 0x71, 0x70, 0x73, 0x74, 0x65, 0x70, 0x3d, 0x34, 0x20, 0x73, 0x74,
            0x61, 0x74, 0x73, 0x2d, 0x77, 0x72, 0x69, 0x74, 0x65, 0x3d, 0x30, 0x20, 0x73, 0x74,
            0x61, 0x74, 0x73, 0x2d, 0x72, 0x65, 0x61, 0x64, 0x3d, 0x30, 0x20, 0x69, 0x70, 0x72,
            0x61, 0x74, 0x69, 0x6f, 0x3d, 0x31, 0x2e, 0x34, 0x30, 0x20, 0x70, 0x62, 0x72, 0x61,
            0x74, 0x69, 0x6f, 0x3d, 0x31, 0x2e, 0x33, 0x30, 0x20, 0x61, 0x71, 0x2d, 0x6d, 0x6f,
            0x64, 0x65, 0x3d, 0x31, 0x20, 0x61, 0x71, 0x2d, 0x73, 0x74, 0x72, 0x65, 0x6e, 0x67,
            0x74, 0x68, 0x3d, 0x31, 0x2e, 0x30, 0x30, 0x20, 0x63, 0x75, 0x74, 0x72, 0x65, 0x65,
            0x20, 0x7a, 0x6f, 0x6e, 0x65, 0x2d, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3d, 0x30, 0x20,
            0x6e, 0x6f, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x63, 0x74, 0x2d, 0x63, 0x62, 0x72, 0x20,
            0x71, 0x67, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x33, 0x32, 0x20, 0x6e, 0x6f, 0x2d,
            0x72, 0x63, 0x2d, 0x67, 0x72, 0x61, 0x69, 0x6e, 0x20, 0x71, 0x70, 0x6d, 0x61, 0x78,
            0x3d, 0x36, 0x39, 0x20, 0x71, 0x70, 0x6d, 0x69, 0x6e, 0x3d, 0x30, 0x20, 0x6e, 0x6f,
            0x2d, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x2d, 0x76, 0x62, 0x76, 0x20, 0x73, 0x61, 0x72,
            0x3d, 0x31, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x73, 0x63, 0x61, 0x6e, 0x3d, 0x30, 0x20,
            0x76, 0x69, 0x64, 0x65, 0x6f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x3d, 0x35, 0x20,
            0x72, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x30, 0x20, 0x63, 0x6f, 0x6c, 0x6f, 0x72, 0x70,
            0x72, 0x69, 0x6d, 0x3d, 0x32, 0x20, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72,
            0x3d, 0x32, 0x20, 0x63, 0x6f, 0x6c, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x72, 0x69, 0x78,
            0x3d, 0x32, 0x20, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x61, 0x6c, 0x6f, 0x63, 0x3d, 0x30,
            0x20, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x2d, 0x77, 0x69, 0x6e, 0x64, 0x6f,
            0x77, 0x3d, 0x30, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x63, 0x6c, 0x6c, 0x3d, 0x30, 0x2c,
            0x30, 0x20, 0x6d, 0x69, 0x6e, 0x2d, 0x6c, 0x75, 0x6d, 0x61, 0x3d, 0x30, 0x20, 0x6d,
            0x61, 0x78, 0x2d, 0x6c, 0x75, 0x6d, 0x61, 0x3d, 0x32, 0x35, 0x35, 0x20, 0x6c, 0x6f,
            0x67, 0x32, 0x2d, 0x6d, 0x61, 0x78, 0x2d, 0x70, 0x6f, 0x63, 0x2d, 0x6c, 0x73, 0x62,
            0x3d, 0x38, 0x20, 0x76, 0x75, 0x69, 0x2d, 0x74, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x2d,
            0x69, 0x6e, 0x66, 0x6f, 0x20, 0x76, 0x75, 0x69, 0x2d, 0x68, 0x72, 0x64, 0x2d, 0x69,
            0x6e, 0x66, 0x6f, 0x20, 0x73, 0x6c, 0x69, 0x63, 0x65, 0x73, 0x3d, 0x31, 0x20, 0x6e,
            0x6f, 0x2d, 0x6f, 0x70, 0x74, 0x2d, 0x71, 0x70, 0x2d, 0x70, 0x70, 0x73, 0x20, 0x6e,
            0x6f, 0x2d, 0x6f, 0x70, 0x74, 0x2d, 0x72, 0x65, 0x66, 0x2d, 0x6c, 0x69, 0x73, 0x74,
            0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x2d, 0x70, 0x70, 0x73, 0x20, 0x6e, 0x6f,
            0x2d, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x2d, 0x70, 0x61, 0x73, 0x73, 0x2d, 0x6f, 0x70,
            0x74, 0x2d, 0x72, 0x70, 0x73, 0x20, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x63, 0x75, 0x74,
            0x2d, 0x62, 0x69, 0x61, 0x73, 0x3d, 0x30, 0x2e, 0x30, 0x35, 0x20, 0x6e, 0x6f, 0x2d,
            0x6f, 0x70, 0x74, 0x2d, 0x63, 0x75, 0x2d, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x2d, 0x71,
            0x70, 0x20, 0x6e, 0x6f, 0x2d, 0x61, 0x71, 0x2d, 0x6d, 0x6f, 0x74, 0x69, 0x6f, 0x6e,
            0x20, 0x6e, 0x6f, 0x2d, 0x68, 0x64, 0x72, 0x20, 0x6e, 0x6f, 0x2d, 0x68, 0x64, 0x72,
            0x2d, 0x6f, 0x70, 0x74, 0x20, 0x6e, 0x6f, 0x2d, 0x64, 0x68, 0x64, 0x72, 0x31, 0x30,
            0x2d, 0x6f, 0x70, 0x74, 0x20, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x73, 0x69, 0x73, 0x2d,
            0x72, 0x65, 0x75, 0x73, 0x65, 0x2d, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x3d, 0x35, 0x20,
            0x73, 0x63, 0x61, 0x6c, 0x65, 0x2d, 0x66, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x3d, 0x30,
            0x20, 0x72, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x2d, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x3d,
            0x30, 0x20, 0x72, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72,
            0x3d, 0x30, 0x20, 0x72, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x2d, 0x6d, 0x76, 0x3d, 0x30,
            0x20, 0x6e, 0x6f, 0x2d, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x2d, 0x73, 0x61, 0x6f, 0x20,
            0x63, 0x74, 0x75, 0x2d, 0x69, 0x6e, 0x66, 0x6f, 0x3d, 0x30, 0x20, 0x6e, 0x6f, 0x2d,
            0x6c, 0x6f, 0x77, 0x70, 0x61, 0x73, 0x73, 0x2d, 0x64, 0x63, 0x74, 0x20, 0x72, 0x65,
            0x66, 0x69, 0x6e, 0x65, 0x2d, 0x6d, 0x76, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x3d, 0x30,
            0x20, 0x63, 0x6f, 0x70, 0x79, 0x2d, 0x70, 0x69, 0x63, 0x3d, 0x31, 0x80,
        ];

        let mut pck = H265Packetizer::default();

        let res = pck.packetize(1400, payload)?;

        // These expected results are obtained from running pion's golang code
        let res_exp_1 = &[
            96, 1, 0, 24, 64, 1, 12, 1, 255, 255, 1, 96, 0, 0, 3, 0, 144, 0, 0, 3, 0, 0, 3, 0, 120,
            149, 152, 9, 0, 43, 66, 1, 1, 1, 96, 0, 0, 3, 0, 144, 0, 0, 3, 0, 0, 3, 0, 120, 160, 3,
            192, 128, 16, 229, 150, 86, 105, 36, 202, 240, 16, 16, 0, 0, 3, 0, 16, 0, 0, 3, 1, 224,
            128, 0, 7, 68, 1, 193, 114, 180, 98, 64,
        ];

        let res_exp_2 = &[
            98, 1, 167, 5, 255, 255, 255, 255, 255, 255, 255, 113, 44, 162, 222, 9, 181, 23, 71,
            219, 187, 85, 164, 254, 127, 194, 252, 78, 120, 50, 54, 53, 32, 40, 98, 117, 105, 108,
            100, 32, 49, 53, 49, 41, 32, 45, 32, 50, 46, 54, 43, 52, 57, 45, 55, 50, 49, 57, 51,
            55, 54, 100, 101, 52, 50, 97, 58, 91, 87, 105, 110, 100, 111, 119, 115, 93, 91, 71, 67,
            67, 32, 55, 46, 51, 46, 48, 93, 91, 54, 52, 32, 98, 105, 116, 93, 32, 56, 98, 105, 116,
            43, 49, 48, 98, 105, 116, 32, 45, 32, 72, 46, 50, 54, 53, 47, 72, 69, 86, 67, 32, 99,
            111, 100, 101, 99, 32, 45, 32, 67, 111, 112, 121, 114, 105, 103, 104, 116, 32, 50, 48,
            49, 51, 45, 50, 48, 49, 56, 32, 40, 99, 41, 32, 77, 117, 108, 116, 105, 99, 111, 114,
            101, 119, 97, 114, 101, 44, 32, 73, 110, 99, 32, 45, 32, 104, 116, 116, 112, 58, 47,
            47, 120, 50, 54, 53, 46, 111, 114, 103, 32, 45, 32, 111, 112, 116, 105, 111, 110, 115,
            58, 32, 99, 112, 117, 105, 100, 61, 49, 48, 53, 48, 49, 49, 49, 32, 102, 114, 97, 109,
            101, 45, 116, 104, 114, 101, 97, 100, 115, 61, 51, 32, 110, 117, 109, 97, 45, 112, 111,
            111, 108, 115, 61, 56, 32, 119, 112, 112, 32, 110, 111, 45, 112, 109, 111, 100, 101,
            32, 110, 111, 45, 112, 109, 101, 32, 110, 111, 45, 112, 115, 110, 114, 32, 110, 111,
            45, 115, 115, 105, 109, 32, 108, 111, 103, 45, 108, 101, 118, 101, 108, 61, 50, 32, 98,
            105, 116, 100, 101, 112, 116, 104, 61, 56, 32, 105, 110, 112, 117, 116, 45, 99, 115,
            112, 61, 49, 32, 102, 112, 115, 61, 51, 48, 47, 49, 32, 105, 110, 112, 117, 116, 45,
            114, 101, 115, 61, 49, 57, 50, 48, 120, 49, 48, 56, 48, 32, 105, 110, 116, 101, 114,
            108, 97, 99, 101, 61, 48, 32, 116, 111, 116, 97, 108, 45, 102, 114, 97, 109, 101, 115,
            61, 48, 32, 108, 101, 118, 101, 108, 45, 105, 100, 99, 61, 48, 32, 104, 105, 103, 104,
            45, 116, 105, 101, 114, 61, 49, 32, 117, 104, 100, 45, 98, 100, 61, 48, 32, 114, 101,
            102, 61, 52, 32, 110, 111, 45, 97, 108, 108, 111, 119, 45, 110, 111, 110, 45, 99, 111,
            110, 102, 111, 114, 109, 97, 110, 99, 101, 32, 110, 111, 45, 114, 101, 112, 101, 97,
            116, 45, 104, 101, 97, 100, 101, 114, 115, 32, 97, 110, 110, 101, 120, 98, 32, 110,
            111, 45, 97, 117, 100, 32, 110, 111, 45, 104, 114, 100, 32, 105, 110, 102, 111, 32,
            104, 97, 115, 104, 61, 48, 32, 110, 111, 45, 116, 101, 109, 112, 111, 114, 97, 108, 45,
            108, 97, 121, 101, 114, 115, 32, 111, 112, 101, 110, 45, 103, 111, 112, 32, 109, 105,
            110, 45, 107, 101, 121, 105, 110, 116, 61, 50, 53, 32, 107, 101, 121, 105, 110, 116,
            61, 50, 53, 48, 32, 103, 111, 112, 45, 108, 111, 111, 107, 97, 104, 101, 97, 100, 61,
            48, 32, 98, 102, 114, 97, 109, 101, 115, 61, 52, 32, 98, 45, 97, 100, 97, 112, 116, 61,
            50, 32, 98, 45, 112, 121, 114, 97, 109, 105, 100, 32, 98, 102, 114, 97, 109, 101, 45,
            98, 105, 97, 115, 61, 48, 32, 114, 99, 45, 108, 111, 111, 107, 97, 104, 101, 97, 100,
            61, 50, 53, 32, 108, 111, 111, 107, 97, 104, 101, 97, 100, 45, 115, 108, 105, 99, 101,
            115, 61, 52, 32, 115, 99, 101, 110, 101, 99, 117, 116, 61, 52, 48, 32, 114, 97, 100,
            108, 61, 48, 32, 110, 111, 45, 105, 110, 116, 114, 97, 45, 114, 101, 102, 114, 101,
            115, 104, 32, 99, 116, 117, 61, 54, 52, 32, 109, 105, 110, 45, 99, 117, 45, 115, 105,
            122, 101, 61, 56, 32, 114, 101, 99, 116, 32, 110, 111, 45, 97, 109, 112, 32, 109, 97,
            120, 45, 116, 117, 45, 115, 105, 122, 101, 61, 51, 50, 32, 116, 117, 45, 105, 110, 116,
            101, 114, 45, 100, 101, 112, 116, 104, 61, 49, 32, 116, 117, 45, 105, 110, 116, 114,
            97, 45, 100, 101, 112, 116, 104, 61, 49, 32, 108, 105, 109, 105, 116, 45, 116, 117, 61,
            48, 32, 114, 100, 111, 113, 45, 108, 101, 118, 101, 108, 61, 50, 32, 100, 121, 110, 97,
            109, 105, 99, 45, 114, 100, 61, 48, 46, 48, 48, 32, 110, 111, 45, 115, 115, 105, 109,
            45, 114, 100, 32, 115, 105, 103, 110, 104, 105, 100, 101, 32, 110, 111, 45, 116, 115,
            107, 105, 112, 32, 110, 114, 45, 105, 110, 116, 114, 97, 61, 48, 32, 110, 114, 45, 105,
            110, 116, 101, 114, 61, 48, 32, 110, 111, 45, 99, 111, 110, 115, 116, 114, 97, 105,
            110, 101, 100, 45, 105, 110, 116, 114, 97, 32, 115, 116, 114, 111, 110, 103, 45, 105,
            110, 116, 114, 97, 45, 115, 109, 111, 111, 116, 104, 105, 110, 103, 32, 109, 97, 120,
            45, 109, 101, 114, 103, 101, 61, 51, 32, 108, 105, 109, 105, 116, 45, 114, 101, 102,
            115, 61, 51, 32, 108, 105, 109, 105, 116, 45, 109, 111, 100, 101, 115, 32, 109, 101,
            61, 51, 32, 115, 117, 98, 109, 101, 61, 51, 32, 109, 101, 114, 97, 110, 103, 101, 61,
            53, 55, 32, 116, 101, 109, 112, 111, 114, 97, 108, 45, 109, 118, 112, 32, 119, 101,
            105, 103, 104, 116, 112, 32, 110, 111, 45, 119, 101, 105, 103, 104, 116, 98, 32, 110,
            111, 45, 97, 110, 97, 108, 121, 122, 101, 45, 115, 114, 99, 45, 112, 105, 99, 115, 32,
            100, 101, 98, 108, 111, 99, 107, 61, 48, 58, 48, 32, 115, 97, 111, 32, 110, 111, 45,
            115, 97, 111, 45, 110, 111, 110, 45, 100, 101, 98, 108, 111, 99, 107, 32, 114, 100, 61,
            52, 32, 110, 111, 45, 101, 97, 114, 108, 121, 45, 115, 107, 105, 112, 32, 114, 115,
            107, 105, 112, 32, 110, 111, 45, 102, 97, 115, 116, 45, 105, 110, 116, 114, 97, 32,
            110, 111, 45, 116, 115, 107, 105, 112, 45, 102, 97, 115, 116, 32, 110, 111, 45, 99,
            117, 45, 108, 111, 115, 115, 108, 101, 115, 115, 32, 110, 111, 45, 98, 45, 105, 110,
            116, 114, 97, 32, 110, 111, 45, 115, 112, 108, 105, 116, 114, 100, 45, 115, 107, 105,
            112, 32, 114, 100, 112, 101, 110, 97, 108, 116, 121, 61, 48, 32, 112, 115, 121, 45,
            114, 100, 61, 50, 46, 48, 48, 32, 112, 115, 121, 45, 114, 100, 111, 113, 61, 49, 46,
            48, 48, 32, 110, 111, 45, 114, 100, 45, 114, 101, 102, 105, 110, 101, 32, 110, 111, 45,
            108, 111, 115, 115, 108, 101, 115, 115, 32, 99, 98, 113, 112, 111, 102, 102, 115, 61,
            48, 32, 99, 114, 113, 112, 111, 102, 102, 115, 61, 48, 32, 114, 99, 61, 97, 98, 114,
            32, 98, 105, 116, 114, 97, 116, 101, 61, 56, 56, 48, 32, 113, 99, 111, 109, 112, 61,
            48, 46, 54, 48, 32, 113, 112, 115, 116, 101, 112, 61, 52, 32, 115, 116, 97, 116, 115,
            45, 119, 114, 105, 116, 101, 61, 48, 32, 115, 116, 97, 116, 115, 45, 114, 101, 97, 100,
            61, 48, 32, 105, 112, 114, 97, 116, 105, 111, 61, 49, 46, 52, 48, 32, 112, 98, 114, 97,
            116, 105, 111, 61, 49, 46, 51, 48, 32, 97, 113, 45, 109, 111, 100, 101, 61, 49, 32, 97,
            113, 45, 115, 116, 114, 101, 110, 103, 116, 104, 61, 49, 46, 48, 48, 32, 99, 117, 116,
            114, 101, 101, 32, 122, 111, 110, 101, 45, 99, 111, 117, 110, 116, 61, 48, 32, 110,
            111, 45, 115, 116, 114, 105, 99, 116, 45, 99, 98, 114, 32, 113, 103, 45, 115, 105, 122,
            101, 61, 51, 50, 32, 110, 111, 45, 114, 99, 45, 103, 114, 97, 105, 110, 32, 113, 112,
            109, 97, 120, 61, 54, 57, 32, 113,
        ];

        let res_exp_3 = &[
            98, 1, 103, 112, 109, 105, 110, 61, 48, 32, 110, 111, 45, 99, 111, 110, 115, 116, 45,
            118, 98, 118, 32, 115, 97, 114, 61, 49, 32, 111, 118, 101, 114, 115, 99, 97, 110, 61,
            48, 32, 118, 105, 100, 101, 111, 102, 111, 114, 109, 97, 116, 61, 53, 32, 114, 97, 110,
            103, 101, 61, 48, 32, 99, 111, 108, 111, 114, 112, 114, 105, 109, 61, 50, 32, 116, 114,
            97, 110, 115, 102, 101, 114, 61, 50, 32, 99, 111, 108, 111, 114, 109, 97, 116, 114,
            105, 120, 61, 50, 32, 99, 104, 114, 111, 109, 97, 108, 111, 99, 61, 48, 32, 100, 105,
            115, 112, 108, 97, 121, 45, 119, 105, 110, 100, 111, 119, 61, 48, 32, 109, 97, 120, 45,
            99, 108, 108, 61, 48, 44, 48, 32, 109, 105, 110, 45, 108, 117, 109, 97, 61, 48, 32,
            109, 97, 120, 45, 108, 117, 109, 97, 61, 50, 53, 53, 32, 108, 111, 103, 50, 45, 109,
            97, 120, 45, 112, 111, 99, 45, 108, 115, 98, 61, 56, 32, 118, 117, 105, 45, 116, 105,
            109, 105, 110, 103, 45, 105, 110, 102, 111, 32, 118, 117, 105, 45, 104, 114, 100, 45,
            105, 110, 102, 111, 32, 115, 108, 105, 99, 101, 115, 61, 49, 32, 110, 111, 45, 111,
            112, 116, 45, 113, 112, 45, 112, 112, 115, 32, 110, 111, 45, 111, 112, 116, 45, 114,
            101, 102, 45, 108, 105, 115, 116, 45, 108, 101, 110, 103, 116, 104, 45, 112, 112, 115,
            32, 110, 111, 45, 109, 117, 108, 116, 105, 45, 112, 97, 115, 115, 45, 111, 112, 116,
            45, 114, 112, 115, 32, 115, 99, 101, 110, 101, 99, 117, 116, 45, 98, 105, 97, 115, 61,
            48, 46, 48, 53, 32, 110, 111, 45, 111, 112, 116, 45, 99, 117, 45, 100, 101, 108, 116,
            97, 45, 113, 112, 32, 110, 111, 45, 97, 113, 45, 109, 111, 116, 105, 111, 110, 32, 110,
            111, 45, 104, 100, 114, 32, 110, 111, 45, 104, 100, 114, 45, 111, 112, 116, 32, 110,
            111, 45, 100, 104, 100, 114, 49, 48, 45, 111, 112, 116, 32, 97, 110, 97, 108, 121, 115,
            105, 115, 45, 114, 101, 117, 115, 101, 45, 108, 101, 118, 101, 108, 61, 53, 32, 115,
            99, 97, 108, 101, 45, 102, 97, 99, 116, 111, 114, 61, 48, 32, 114, 101, 102, 105, 110,
            101, 45, 105, 110, 116, 114, 97, 61, 48, 32, 114, 101, 102, 105, 110, 101, 45, 105,
            110, 116, 101, 114, 61, 48, 32, 114, 101, 102, 105, 110, 101, 45, 109, 118, 61, 48, 32,
            110, 111, 45, 108, 105, 109, 105, 116, 45, 115, 97, 111, 32, 99, 116, 117, 45, 105,
            110, 102, 111, 61, 48, 32, 110, 111, 45, 108, 111, 119, 112, 97, 115, 115, 45, 100, 99,
            116, 32, 114, 101, 102, 105, 110, 101, 45, 109, 118, 45, 116, 121, 112, 101, 61, 48,
            32, 99, 111, 112, 121, 45, 112, 105, 99, 61, 49, 128,
        ];

        assert_eq!(res.len(), 3, "Generated payload should be 3");
        assert_eq!(res[0], res_exp_1, "First packet does not match expected");
        assert_eq!(res[1], res_exp_2, "Second packet does not match expected");
        assert_eq!(res[2], res_exp_3, "Third packet does not match expected");

        Ok(())
    }
}
