use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt::Debug;
use std::marker::PhantomData;
use tracing::warn;
// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

use crate::SctpError;

#[derive(Debug)]
pub enum Chunks {
    Init(Chunk<Init>),
    InitAck(Chunk<InitAck, InitAckParam>),
    Data(Chunk<Data>),
    Sack(Chunk<Sack>),
    Heartbeat(Chunk<Heartbeat, HeartbeatParam>),
    HeartbeatAck(Chunk<HeartbeatAck, HeartbeatParam>),
    CookieEcho(Chunk<CookieEcho>),
    CookieAck(Chunk<CookieAck>),
    Unknown(u8),
}

impl Chunks {
    pub fn parse_next(buf: &[u8]) -> Result<(Option<Self>, usize), SctpError> {
        if buf.is_empty() {
            return Ok((None, 0));
        }
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if length == 0 {
            return Ok((None, 0));
        }
        let chunk = Chunks::try_from(buf)?;
        Ok((Some(chunk), length))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    Data = 0,
    Init = 1,
    InitAck = 2,
    Sack = 3,
    Heartbeat = 4,
    HeartbeatAck = 5,
    CookieEcho = 10,
    CookieAck = 11,
}

impl<'a> TryFrom<&'a [u8]> for Chunks {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        let typ = buf[0];
        let chunk = match typ {
            0 => Chunks::Data(buf.try_into()?),
            1 => Chunks::Init(buf.try_into()?),
            2 => Chunks::InitAck(buf.try_into()?),
            3 => Chunks::Sack(buf.try_into()?),
            4 => Chunks::Heartbeat(buf.try_into()?),
            5 => Chunks::HeartbeatAck(buf.try_into()?),
            10 => Chunks::CookieEcho(buf.try_into()?),
            11 => Chunks::CookieAck(buf.try_into()?),
            _ => Chunks::Unknown(typ),
        };
        Ok(chunk)
    }
}

impl WriteTo for Chunks {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        match self {
            Chunks::Init(v) => v.write_to(buf),
            Chunks::InitAck(v) => v.write_to(buf),
            Chunks::Data(v) => v.write_to(buf),
            Chunks::Sack(v) => v.write_to(buf),
            Chunks::Heartbeat(v) => v.write_to(buf),
            Chunks::HeartbeatAck(v) => v.write_to(buf),
            Chunks::CookieEcho(v) => v.write_to(buf),
            Chunks::CookieAck(v) => v.write_to(buf),
            Chunks::Unknown(_) => 0,
        }
    }
}

pub trait WriteTo {
    fn write_to(&self, buf: &mut [u8]) -> usize;
}

pub struct Header {
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
    pub checksum: u32,
}

pub struct Chunk<T: Debug, P = NoParam> {
    pub chunk_type: u8,
    pub length: usize, // only set when parsing
    pub flags: Flags<T>,
    pub value: T,
    pub params: Vec<P>,
}

impl<T: Debug, P> Debug for Chunk<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chunk")
            .field("chunk_type", &self.chunk_type)
            .field("length", &self.length)
            .field("value", &self.value)
            .finish()
    }
}

impl<T: Debug, P> Chunk<T, P> {
    pub fn new(typ: ChunkType, value: T) -> Self {
        Chunk {
            chunk_type: typ as u8,
            length: 0,
            flags: Flags::default(),
            value,
            params: vec![],
        }
    }
}

pub struct NoParam(u16);

impl From<Parameter<'_>> for NoParam {
    fn from(p: Parameter<'_>) -> Self {
        NoParam(p.ptype)
    }
}

impl WriteTo for NoParam {
    fn write_to(&self, _buf: &mut [u8]) -> usize {
        0
    }
}

impl ChunkParameter for NoParam {
    fn contains_required_params(_params: &[Self]) -> bool {
        true
    }

    fn len(&self) -> usize {
        0
    }
}

pub struct Flags<T> {
    pub flags: u8,
    _ph: PhantomData<T>,
}

impl<T> Default for Flags<T> {
    fn default() -> Self {
        Self {
            flags: 0,
            _ph: Default::default(),
        }
    }
}

impl<T: ChunkPayload, P: ChunkParameter> Chunk<T, P> {
    pub fn length_bytes(&self) -> u16 {
        4 + self.value.len() as u16 + self.params.iter().map(|p| p.len()).sum::<usize>() as u16
    }

    pub fn skip_on_unrecognized(&self) -> bool {
        self.chunk_type & 0b1000_0000 > 0
    }

    pub fn report_unrecognized(&self) -> bool {
        self.chunk_type & 0b0100_0000 > 0
    }
}

impl<T, P> WriteTo for Chunk<T, P>
where
    T: WriteTo,
    T: ChunkPayload,
    P: WriteTo,
    P: ChunkParameter,
{
    fn write_to(&self, buf: &mut [u8]) -> usize {
        buf[0] = self.chunk_type;
        buf[1] = self.flags.flags;
        buf[2..4].copy_from_slice(&self.length_bytes().to_be_bytes());
        let buf = &mut buf[4..];
        let len_value = self.value.write_to(buf);
        let mut len_params = 0;
        let mut buf = &mut buf[len_value..];
        for p in &self.params {
            if p.len() == 0 {
                continue;
            }
            let n = p.write_to(buf);
            len_params += n;
            buf = &mut buf[n..];
            let padding = 4 - n % 4;
            if padding == 4 {
                continue;
            }
            len_params += padding;
            for _ in 0..padding {
                buf[0] = 0;
                buf = &mut buf[1..];
            }
        }
        4 + len_value + len_params
    }
}

pub trait ChunkPayload: Debug {
    fn len(&self) -> usize;
}

pub trait ChunkParameter: Sized {
    fn contains_required_params(params: &[Self]) -> bool;
    fn len(&self) -> usize;
}

impl<'a, T, P> Chunk<T, P>
where
    T: TryFrom<(&'a [u8], usize), Error = SctpError>,
    T: ChunkPayload,
    P: From<Parameter<'a>>,
    P: ChunkParameter,
{
    fn read_from(buf: &'a [u8]) -> Result<Self, SctpError> {
        let chunk_type = buf[0];
        let flags = buf[1];

        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if length < 4 {
            return Err(SctpError::ShortPacket);
        }

        let value = T::try_from((&buf[4..], length - 4))?;
        let param_offset = value.len() + 4;
        let mut pbuf = &buf[param_offset..];

        let mut params = vec![];

        loop {
            if pbuf.len() < 4 {
                break;
            }

            let untyped = read_parameter(pbuf)?;
            let padded_length = untyped.padded_length();

            if padded_length == 0 {
                break;
            }

            let typed: P = untyped.into();
            params.push(typed);

            pbuf = &pbuf[padded_length..];
        }

        if !P::contains_required_params(&params) {
            return Err(SctpError::MissingRequiredParam);
        }

        Ok(Chunk {
            chunk_type,
            length,
            flags: Flags {
                flags,
                ..Default::default()
            },
            value,
            params,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Header {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 12 {
            return Err(SctpError::ShortPacket);
        }

        let source_port = u16::from_be_bytes([buf[0], buf[1]]);
        let destination_port = u16::from_be_bytes([buf[2], buf[3]]);
        let verification_tag = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let checksum = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        Ok(Header {
            source_port,
            destination_port,
            verification_tag,
            checksum,
        })
    }
}

impl WriteTo for Header {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        buf[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.verification_tag.to_be_bytes());
        buf[8..12].copy_from_slice(&self.checksum.to_be_bytes());
        12
    }
}

macro_rules! set_get_flag {
    ($getter:ident, $setter:ident, $flag_no:expr) => {
        pub fn $getter(&self) -> bool {
            self.flags & (1 << $flag_no) > 0
        }

        pub fn $setter(&mut self, v: bool) {
            if v {
                self.flags |= (1 << $flag_no);
            } else {
                self.flags &= !(1 << $flag_no);
            }
        }
    };
}

pub struct Data {
    pub tsn: u32,
    pub stream_id: u16,
    pub stream_seq: u16,
    pub payload_protocol_id: u32,
    pub user_data: Vec<u8>,
}

impl Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Data")
            .field("tsn", &self.tsn)
            .field("stream_id", &self.stream_id)
            .field("stream_seq", &self.stream_seq)
            .field("payload_protocol_id", &self.payload_protocol_id)
            .finish()
    }
}

impl Flags<Data> {
    set_get_flag! { unordered, set_unordered, 0 }
    set_get_flag! { beginning, set_beginning, 1 }
    set_get_flag! { ending, set_ending, 2 }
}

impl ChunkPayload for Data {
    fn len(&self) -> usize {
        12 + self.user_data.len()
    }
}

impl<'a> TryFrom<&'a [u8]> for Chunk<Data> {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        Chunk::read_from(buf)
    }
}

impl<'a> TryFrom<(&'a [u8], usize)> for Data {
    type Error = SctpError;

    fn try_from((buf, len): (&'a [u8], usize)) -> Result<Self, Self::Error> {
        if buf.len() < 12 {
            return Err(SctpError::ShortPacket);
        }

        let tsn = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let stream_id = u16::from_be_bytes([buf[4], buf[5]]);
        let stream_seq = u16::from_be_bytes([buf[6], buf[7]]);
        let payload_protocol_id = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let user_data = (&buf[12..len]).to_vec();

        Ok(Data {
            tsn,
            stream_id,
            stream_seq,
            payload_protocol_id,
            user_data,
        })
    }
}

impl WriteTo for Data {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        buf[0..4].copy_from_slice(&self.tsn.to_be_bytes());
        buf[4..6].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.stream_seq.to_be_bytes());
        buf[8..12].copy_from_slice(&self.payload_protocol_id.to_be_bytes());
        let buf = &mut buf[12..];
        let len = self.user_data.len();
        buf[..len].copy_from_slice(&self.user_data);
        len + 12
    }
}

pub struct Init {
    pub initiate_tag: u32,
    pub a_rwnd: u32,
    pub no_outbound: u16,
    pub no_inbound: u16,
    pub initial_tsn: u32,
}

impl Debug for Init {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Init")
            .field("initiate_tag", &self.initiate_tag)
            .field("a_rwnd", &self.a_rwnd)
            .field("no_outbound", &self.no_outbound)
            .field("no_inbound", &self.no_inbound)
            .field("initial_tsn", &self.initial_tsn)
            .finish()
    }
}

impl Flags<Init> {}

impl ChunkPayload for Init {
    fn len(&self) -> usize {
        16
    }
}

impl<'a> TryFrom<&'a [u8]> for Chunk<Init> {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        Chunk::read_from(buf)
    }
}

impl<'a> TryFrom<(&'a [u8], usize)> for Init {
    type Error = SctpError;

    fn try_from((buf, _len): (&'a [u8], usize)) -> Result<Self, Self::Error> {
        if buf.len() < 12 {
            return Err(SctpError::ShortPacket);
        }

        let initiate_tag = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let a_rwnd = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let no_outbound = u16::from_be_bytes([buf[8], buf[9]]);
        let no_inbound = u16::from_be_bytes([buf[10], buf[11]]);
        let initial_tsn = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

        Ok(Init {
            initiate_tag,
            a_rwnd,
            no_outbound,
            no_inbound,
            initial_tsn,
        })
    }
}

impl WriteTo for Init {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        buf[0..4].copy_from_slice(&self.initiate_tag.to_be_bytes());
        buf[4..8].copy_from_slice(&self.a_rwnd.to_be_bytes());
        buf[8..10].copy_from_slice(&self.no_outbound.to_be_bytes());
        buf[10..12].copy_from_slice(&self.no_inbound.to_be_bytes());
        buf[12..16].copy_from_slice(&self.initial_tsn.to_be_bytes());
        16
    }
}

pub struct InitAck(pub Init);

impl Flags<InitAck> {}

pub enum InitAckParam {
    StateCookie(Vec<u8>),
    Unknown(u16),
}

impl Debug for InitAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("InitAck").field(&self.0).finish()
    }
}

impl From<Parameter<'_>> for InitAckParam {
    fn from(p: Parameter<'_>) -> Self {
        match p.ptype {
            7 => InitAckParam::StateCookie(p.value.to_vec()),
            _ => InitAckParam::Unknown(p.ptype),
        }
    }
}

impl WriteTo for InitAckParam {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        match self {
            InitAckParam::StateCookie(v) => {
                let len = 4 + v.len();
                let buf = write_param_type_and_len(buf, 7, len);
                (&mut buf[..v.len()]).copy_from_slice(&v);
                len
            }
            InitAckParam::Unknown(_) => 0,
        }
    }
}

impl ChunkParameter for InitAckParam {
    fn contains_required_params(params: &[Self]) -> bool {
        params
            .iter()
            .any(|p| matches!(p, InitAckParam::StateCookie(_)))
    }

    fn len(&self) -> usize {
        match self {
            InitAckParam::StateCookie(v) => 4 + v.len(),
            InitAckParam::Unknown(_) => 0,
        }
    }
}

impl ChunkPayload for InitAck {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> TryFrom<&'a [u8]> for Chunk<InitAck, InitAckParam> {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        Chunk::read_from(buf)
    }
}

impl<'a> TryFrom<(&'a [u8], usize)> for InitAck {
    type Error = SctpError;

    fn try_from((buf, len): (&'a [u8], usize)) -> Result<Self, Self::Error> {
        let init = Init::try_from((buf, len))?;
        Ok(InitAck(init))
    }
}

impl WriteTo for InitAck {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        self.0.write_to(buf)
    }
}

pub struct Sack {
    pub cumulative_tsn_ack: u32,
    pub a_rwnd: u32,
    pub gap_ack_blocks: Vec<GapAckBlock>,
    pub duplicate_tsns: Vec<u32>,
}

impl Debug for Sack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sack")
            .field("cumulative_tsn_ack", &self.cumulative_tsn_ack)
            .field("a_rwnd", &self.a_rwnd)
            .field("gap_ack_blocks", &self.gap_ack_blocks.len())
            .field("duplicate_tsns", &self.duplicate_tsns.len())
            .finish()
    }
}

pub struct GapAckBlock {
    pub start: u16,
    pub end: u16,
}

impl Flags<Sack> {}

impl ChunkPayload for Sack {
    fn len(&self) -> usize {
        12 + self.gap_ack_blocks.len() * 4 + self.duplicate_tsns.len() * 4
    }
}

impl<'a> TryFrom<&'a [u8]> for Chunk<Sack> {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        Chunk::read_from(buf)
    }
}

impl<'a> TryFrom<(&'a [u8], usize)> for Sack {
    type Error = SctpError;

    fn try_from((buf, _len): (&'a [u8], usize)) -> Result<Self, Self::Error> {
        if buf.len() < 12 {
            return Err(SctpError::ShortPacket);
        }

        let cumulative_tsn_ack = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let a_rwnd = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let number_of_gap_acks = u16::from_be_bytes([buf[8], buf[9]]);
        let number_of_dup_tsns = u16::from_be_bytes([buf[10], buf[11]]);

        let mut buf = &buf[8..];

        let mut gap_ack_blocks = vec![];
        for _ in 0..number_of_gap_acks {
            buf = &buf[4..];
            let start = u16::from_be_bytes([buf[0], buf[1]]);
            let end = u16::from_be_bytes([buf[2], buf[3]]);
            gap_ack_blocks.push(GapAckBlock { start, end });
        }

        let mut duplicate_tsns = vec![];
        for _ in 0..number_of_dup_tsns {
            buf = &buf[4..];
            let tsn = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            duplicate_tsns.push(tsn);
        }

        Ok(Sack {
            cumulative_tsn_ack,
            a_rwnd,
            gap_ack_blocks,
            duplicate_tsns,
        })
    }
}

impl WriteTo for Sack {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        buf[0..4].copy_from_slice(&self.cumulative_tsn_ack.to_be_bytes());
        buf[4..8].copy_from_slice(&self.a_rwnd.to_be_bytes());
        let number_of_gap_acks = self.gap_ack_blocks.len() as u16;
        buf[8..10].copy_from_slice(&number_of_gap_acks.to_be_bytes());
        let number_of_dup_tsns = self.duplicate_tsns.len() as u16;
        buf[10..12].copy_from_slice(&number_of_dup_tsns.to_be_bytes());

        let mut buf = &mut buf[8..];

        for g in &self.gap_ack_blocks {
            buf = &mut buf[4..];
            buf[0..2].copy_from_slice(&g.start.to_be_bytes());
            buf[2..4].copy_from_slice(&g.end.to_be_bytes());
        }

        for g in &self.duplicate_tsns {
            buf = &mut buf[4..];
            buf[0..4].copy_from_slice(&g.to_be_bytes());
        }

        12 + self.gap_ack_blocks.len() * 4 + self.duplicate_tsns.len() * 4
    }
}

pub struct Heartbeat;

impl Debug for Heartbeat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Heartbeat").finish()
    }
}

impl Flags<Heartbeat> {}

pub enum HeartbeatParam {
    HeartbeatInfo(Vec<u8>),
    Unknown(u16),
}

impl From<Parameter<'_>> for HeartbeatParam {
    fn from(p: Parameter<'_>) -> Self {
        match p.ptype {
            1 => HeartbeatParam::HeartbeatInfo(p.value.to_vec()),
            _ => HeartbeatParam::Unknown(p.ptype),
        }
    }
}

impl WriteTo for HeartbeatParam {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        match self {
            HeartbeatParam::HeartbeatInfo(v) => {
                let len = 4 + v.len();
                let buf = write_param_type_and_len(buf, 7, len);
                (&mut buf[..v.len()]).copy_from_slice(&v);
                len
            }
            HeartbeatParam::Unknown(_) => 0,
        }
    }
}

impl ChunkParameter for HeartbeatParam {
    fn contains_required_params(params: &[Self]) -> bool {
        params
            .iter()
            .any(|p| matches!(p, HeartbeatParam::HeartbeatInfo(_)))
    }

    fn len(&self) -> usize {
        match self {
            HeartbeatParam::HeartbeatInfo(v) => 4 + v.len(),
            HeartbeatParam::Unknown(_) => 0,
        }
    }
}

impl ChunkPayload for Heartbeat {
    fn len(&self) -> usize {
        0
    }
}

impl<'a> TryFrom<&'a [u8]> for Chunk<Heartbeat, HeartbeatParam> {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        Chunk::read_from(buf)
    }
}

impl<'a> TryFrom<(&'a [u8], usize)> for Heartbeat {
    type Error = SctpError;

    fn try_from((_buf, _len): (&'a [u8], usize)) -> Result<Self, Self::Error> {
        Ok(Heartbeat)
    }
}

impl WriteTo for Heartbeat {
    fn write_to(&self, _buf: &mut [u8]) -> usize {
        0
    }
}

pub struct HeartbeatAck;

impl Debug for HeartbeatAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeartbeatAck").finish()
    }
}

impl Flags<HeartbeatAck> {}

impl ChunkPayload for HeartbeatAck {
    fn len(&self) -> usize {
        0
    }
}

impl<'a> TryFrom<&'a [u8]> for Chunk<HeartbeatAck, HeartbeatParam> {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        Chunk::read_from(buf)
    }
}

impl<'a> TryFrom<(&'a [u8], usize)> for HeartbeatAck {
    type Error = SctpError;

    fn try_from((_buf, _len): (&'a [u8], usize)) -> Result<Self, Self::Error> {
        Ok(HeartbeatAck)
    }
}

impl WriteTo for HeartbeatAck {
    fn write_to(&self, _buf: &mut [u8]) -> usize {
        0
    }
}

pub struct CookieEcho {
    pub cookie: Vec<u8>,
}

impl Debug for CookieEcho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieEcho")
            .field("cookie", &self.cookie.len())
            .finish()
    }
}

impl Flags<CookieEcho> {}

impl ChunkPayload for CookieEcho {
    fn len(&self) -> usize {
        self.cookie.len()
    }
}

impl WriteTo for CookieEcho {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        let len = self.cookie.len();
        (&mut buf[..len]).copy_from_slice(&self.cookie);
        len
    }
}

impl<'a> TryFrom<&'a [u8]> for Chunk<CookieEcho> {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        Chunk::read_from(buf)
    }
}

impl<'a> TryFrom<(&'a [u8], usize)> for CookieEcho {
    type Error = SctpError;

    fn try_from((buf, len): (&'a [u8], usize)) -> Result<Self, Self::Error> {
        if len < 4 {
            return Err(SctpError::TooShortLength);
        }

        Ok(CookieEcho {
            cookie: (&buf[0..len]).to_vec(),
        })
    }
}

pub struct CookieAck;

impl Debug for CookieAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieAck").finish()
    }
}

impl Flags<CookieAck> {}

impl ChunkPayload for CookieAck {
    fn len(&self) -> usize {
        0
    }
}

impl WriteTo for CookieAck {
    fn write_to(&self, _buf: &mut [u8]) -> usize {
        0
    }
}

impl<'a> TryFrom<&'a [u8]> for Chunk<CookieAck> {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        Chunk::read_from(buf)
    }
}

impl<'a> TryFrom<(&'a [u8], usize)> for CookieAck {
    type Error = SctpError;

    fn try_from((_buf, _len): (&'a [u8], usize)) -> Result<Self, Self::Error> {
        Ok(CookieAck)
    }
}

fn write_param_type_and_len(buf: &mut [u8], typ: u16, len: usize) -> &mut [u8] {
    (&mut buf[0..2]).copy_from_slice(&typ.to_be_bytes());
    (&mut buf[2..4]).copy_from_slice(&(len as u16).to_be_bytes());
    &mut buf[4..]
}

fn read_parameter(buf: &[u8]) -> Result<Parameter<'_>, SctpError> {
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |        Parameter Type         |       Parameter Length        |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    \                                                               \
    //    /                        Parameter Value                        /
    //    \                                                               \
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // The Parameter Length field contains the size of the parameter in bytes,
    // including the Parameter Type, Parameter Length, and Parameter Value fields.
    //
    // The total length of a parameter (including Parameter Type, Parameter Length,
    // and Parameter Value fields) MUST be a multiple of 4 bytes. If the length of
    // the parameter is not a multiple of 4 bytes, the sender pads the parameter
    // at the end (i.e., after the Parameter Value field) with all zero bytes.
    // The length of the padding is not included in the Parameter Length field.
    // A sender MUST NOT pad with more than 3 bytes.

    if buf.len() < 4 {
        return Err(SctpError::ShortPacket);
    }

    let ptype = u16::from_be_bytes([buf[0], buf[1]]);
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;

    if length < 4 {
        return Err(SctpError::TooShortLength);
    }

    if buf.len() < length {
        return Err(SctpError::ShortPacket);
    }

    let buf = &buf[4..];
    let value = &buf[..(length - 4)];

    Ok(Parameter {
        ptype,
        length,
        value,
    })
}

#[derive(Debug)]
pub struct Parameter<'a> {
    ptype: u16,
    length: usize,
    value: &'a [u8],
}

impl Parameter<'_> {
    fn padded_length(&self) -> usize {
        let padding = 4 - self.length % 4;
        self.length + if padding < 4 { padding } else { 0 }
    }
}

pub struct StateCookie {
    pub checksum: u32,
    pub association_tag_local: u32,
    pub association_tag_remote: u32,
    pub salt: u32,
}

impl StateCookie {
    pub fn to_bytes(&self, key: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 16];
        self.write_to(&mut bytes);

        (&mut bytes[0..4]).copy_from_slice(&0_u32.to_be_bytes());
        let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC secret");
        hmac.update(&bytes);
        let checksum = hmac.finalize().into_bytes();
        (&mut bytes[0..4]).copy_from_slice(&checksum[0..4]);

        bytes
    }

    pub fn from_bytes(key: &[u8], buf: &[u8]) -> Option<Self> {
        let cookie = Self::try_from(buf).ok()?;

        let mut tmp = [0_u8; 16];
        (&mut tmp[4..]).copy_from_slice(&buf[4..16]);

        let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC secret");
        hmac.update(&tmp);
        let checksum = hmac.finalize().into_bytes();

        if checksum[0..4] != cookie.checksum.to_be_bytes() {
            warn!("Cookie validation failed");
            return None;
        }

        Some(cookie)
    }
}

impl WriteTo for StateCookie {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        (&mut buf[0..4]).copy_from_slice(&self.checksum.to_be_bytes());
        (&mut buf[4..8]).copy_from_slice(&self.association_tag_local.to_be_bytes());
        (&mut buf[8..12]).copy_from_slice(&self.association_tag_remote.to_be_bytes());
        (&mut buf[12..16]).copy_from_slice(&self.salt.to_be_bytes());
        16
    }
}

impl<'a> TryFrom<&'a [u8]> for StateCookie {
    type Error = SctpError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 16 {
            return Err(SctpError::TooShortLength);
        }

        let checksum = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let association_tag_local = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let association_tag_remote = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let salt = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

        Ok(StateCookie {
            checksum,
            association_tag_local,
            association_tag_remote,
            salt,
        })
    }
}
