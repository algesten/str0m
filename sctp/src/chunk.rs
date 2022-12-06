use std::fmt;

use crate::{pad4, SctpError};

const PARAM_STATE_COOKIE: u16 = 7;
const PARAM_HEARTBEAT_DATA: u16 = 1;

const CHUNK_DATA: u8 = 0;
const CHUNK_INIT: u8 = 1;
const CHUNK_INIT_ACK: u8 = 2;
const CHUNK_SACK: u8 = 3;
const CHUNK_HEARTBEAT: u8 = 4;
const CHUNK_HEARTBEAT_ACK: u8 = 5;
const CHUNK_COOKIE_ECHO: u8 = 10;
const CHUNK_COOKIE_ACK: u8 = 11;

pub trait WriteTo {
    fn write_to(&self, buf: &mut [u8]);
    fn len(&self) -> usize;
}

#[derive(Debug)]
pub enum Chunk {
    Header(Header),
    Init(Init),
    InitAck(InitAck),
    Data(Data),
    Sack(Sack),
    Heartbeat(Heartbeat),
    HeartbeatAck(HeartbeatAck),
    CookieEcho(CookieEcho),
    CookieAck(CookieAck),
    Unknown(u8, usize),
}

impl Chunk {
    pub fn parsed_len(&self) -> usize {
        match self {
            Chunk::Header(_) => 12,
            Chunk::Init(v) => v.chunk.length,
            Chunk::InitAck(v) => v.init.chunk.length,
            Chunk::Data(v) => v.chunk.length,
            Chunk::Sack(v) => v.chunk.length,
            Chunk::Heartbeat(v) => v.chunk.length,
            Chunk::HeartbeatAck(v) => v.heartbeat.chunk.length,
            Chunk::CookieEcho(v) => v.chunk.length,
            Chunk::CookieAck(v) => v.chunk.length,
            Chunk::Unknown(_, l) => *l,
        }
    }

    pub fn update_chunk_header(&mut self) {
        match self {
            Chunk::Header(_) => {}
            Chunk::Init(v) => {
                v.chunk.chunk_type = CHUNK_INIT;
                v.chunk.length = v.len();
            }
            Chunk::InitAck(v) => {
                v.init.chunk.chunk_type = CHUNK_INIT_ACK;
                v.init.chunk.length = v.len();
            }
            Chunk::Data(v) => {
                v.chunk.chunk_type = CHUNK_DATA;
                v.chunk.length = v.len();
            }
            Chunk::Sack(v) => {
                v.chunk.chunk_type = CHUNK_SACK;
                v.chunk.length = v.len();
            }
            Chunk::Heartbeat(v) => {
                v.chunk.chunk_type = CHUNK_HEARTBEAT;
                v.chunk.length = v.len();
            }
            Chunk::HeartbeatAck(v) => {
                v.heartbeat.chunk.chunk_type = CHUNK_HEARTBEAT_ACK;
                v.heartbeat.chunk.length = v.len();
            }
            Chunk::CookieEcho(v) => {
                v.chunk.chunk_type = CHUNK_COOKIE_ECHO;
                v.chunk.length = v.len();
            }
            Chunk::CookieAck(v) => {
                v.chunk.chunk_type = CHUNK_COOKIE_ACK;
                v.chunk.length = v.len();
            }
            Chunk::Unknown(_, _) => {}
        }
    }
}

impl TryFrom<&[u8]> for Chunk {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let ctype = buf[0];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;

        let c = match ctype {
            CHUNK_DATA => Chunk::Data(buf.try_into()?),
            CHUNK_INIT => Chunk::Init(buf.try_into()?),
            CHUNK_INIT_ACK => Chunk::InitAck(buf.try_into()?),
            CHUNK_SACK => Chunk::Sack(buf.try_into()?),
            CHUNK_HEARTBEAT => Chunk::Heartbeat(buf.try_into()?),
            CHUNK_HEARTBEAT_ACK => Chunk::HeartbeatAck(buf.try_into()?),
            CHUNK_COOKIE_ECHO => Chunk::CookieEcho(buf.try_into()?),
            CHUNK_COOKIE_ACK => Chunk::CookieAck(buf.try_into()?),
            _ => Chunk::Unknown(ctype, len),
        };

        Ok(c)
    }
}

impl WriteTo for Chunk {
    fn write_to(&self, buf: &mut [u8]) {
        match self {
            Chunk::Header(v) => v.write_to(buf),
            Chunk::Init(v) => v.write_to(buf),
            Chunk::InitAck(v) => v.write_to(buf),
            Chunk::Data(v) => v.write_to(buf),
            Chunk::Sack(v) => v.write_to(buf),
            Chunk::Heartbeat(v) => v.write_to(buf),
            Chunk::HeartbeatAck(v) => v.write_to(buf),
            Chunk::CookieEcho(v) => v.write_to(buf),
            Chunk::CookieAck(v) => v.write_to(buf),
            Chunk::Unknown(_, _) => {}
        }
    }

    fn len(&self) -> usize {
        match self {
            Chunk::Header(_) => 12,
            Chunk::Init(v) => v.len(),
            Chunk::InitAck(v) => v.len(),
            Chunk::Data(v) => v.len(),
            Chunk::Sack(v) => v.len(),
            Chunk::Heartbeat(v) => v.len(),
            Chunk::HeartbeatAck(v) => v.len(),
            Chunk::CookieEcho(v) => v.len(),
            Chunk::CookieAck(v) => v.len(),
            Chunk::Unknown(_, l) => *l,
        }
    }
}

#[derive(Debug)]
pub struct Header {
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
    pub checksum: u32,
}

impl TryFrom<&[u8]> for Header {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 12 {
            return Err(SctpError::ShortPacket);
        }

        Ok(Header {
            source_port: u16::from_be_bytes([buf[0], buf[1]]),
            destination_port: u16::from_be_bytes([buf[2], buf[3]]),
            verification_tag: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            checksum: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }
}

impl WriteTo for Header {
    fn write_to(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.verification_tag.to_be_bytes());
        buf[8..12].copy_from_slice(&self.checksum.to_be_bytes());
    }

    fn len(&self) -> usize {
        12
    }
}

#[derive(Debug, Default)]
pub struct ChunkStart {
    pub chunk_type: u8,
    pub flags: u8,
    pub length: usize, // u16
}

impl TryFrom<&[u8]> for ChunkStart {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 4 {
            return Err(SctpError::ShortPacket);
        }
        Ok(ChunkStart {
            chunk_type: buf[0],
            flags: buf[1],
            length: u16::from_be_bytes([buf[2], buf[3]]) as usize,
        })
    }
}

impl WriteTo for ChunkStart {
    fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.chunk_type;
        buf[1] = self.flags;
        buf[2..4].copy_from_slice(&(self.length as u16).to_be_bytes());
    }

    fn len(&self) -> usize {
        4
    }
}

#[derive(Debug)]
pub struct Init {
    pub chunk: ChunkStart,
    pub initiate_tag: u32,
    pub a_rwnd: u32,
    pub no_outbound: u16,
    pub no_inbound: u16,
    pub initial_tsn: u32,
}

impl TryFrom<&[u8]> for Init {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let chunk = ChunkStart::try_from(buf)?;
        let buf = &buf[4..];
        if buf.len() < 16 {
            return Err(SctpError::ShortPacket);
        }
        Ok(Init {
            chunk,
            initiate_tag: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            a_rwnd: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            no_outbound: u16::from_be_bytes([buf[8], buf[9]]),
            no_inbound: u16::from_be_bytes([buf[10], buf[11]]),
            initial_tsn: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
        })
    }
}

impl WriteTo for Init {
    fn write_to(&self, buf: &mut [u8]) {
        self.chunk.write_to(buf);
        let buf = &mut buf[4..];
        buf[0..4].copy_from_slice(&self.initiate_tag.to_be_bytes());
        buf[4..8].copy_from_slice(&self.a_rwnd.to_be_bytes());
        buf[8..10].copy_from_slice(&self.no_outbound.to_be_bytes());
        buf[10..12].copy_from_slice(&self.no_inbound.to_be_bytes());
        buf[12..16].copy_from_slice(&self.initial_tsn.to_be_bytes());
    }

    fn len(&self) -> usize {
        self.chunk.len() + 16
    }
}

pub struct InitAck {
    pub init: Init,
    pub cookie: Vec<u8>,
}

impl TryFrom<&[u8]> for InitAck {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let init = Init::try_from(buf)?;
        if buf.len() < init.chunk.length || init.chunk.length < 20 {
            return Err(SctpError::TooShortLength);
        }
        let cookie = find_param(&buf[20..init.chunk.length], PARAM_STATE_COOKIE)
            .ok_or(SctpError::MissingRequiredParam)?;
        Ok(InitAck {
            init,
            cookie: cookie.into(),
        })
    }
}

impl WriteTo for InitAck {
    fn write_to(&self, buf: &mut [u8]) {
        self.init.write_to(buf);
        write_param(&mut buf[20..], PARAM_STATE_COOKIE, &self.cookie);
    }

    fn len(&self) -> usize {
        self.init.len() + self.cookie.len() + 4
    }
}

pub struct Data {
    pub chunk: ChunkStart,
    pub tsn: u32,
    pub stream_id: u16,
    pub stream_seq: u16,
    pub payload_protocol_id: u32,
    pub user_data: Vec<u8>,
}

impl TryFrom<&[u8]> for Data {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let chunk = ChunkStart::try_from(buf)?;
        let buf = &buf[4..];
        let len = chunk.length - 4;
        if len < 12 {
            return Err(SctpError::TooShortLength);
        }
        if buf.len() < len {
            return Err(SctpError::ShortPacket);
        }
        Ok(Data {
            chunk,
            tsn: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            stream_id: u16::from_be_bytes([buf[4], buf[5]]),
            stream_seq: u16::from_be_bytes([buf[6], buf[7]]),
            payload_protocol_id: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            user_data: buf[12..len].to_vec(),
        })
    }
}

impl WriteTo for Data {
    fn write_to(&self, buf: &mut [u8]) {
        self.chunk.write_to(buf);
        let buf = &mut buf[4..];
        buf[0..4].copy_from_slice(&self.tsn.to_be_bytes());
        buf[4..6].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.stream_seq.to_be_bytes());
        buf[8..12].copy_from_slice(&self.payload_protocol_id.to_be_bytes());
        let buf = &mut buf[12..];
        let len = self.user_data.len();
        buf[..len].copy_from_slice(&self.user_data);
    }

    fn len(&self) -> usize {
        self.chunk.len() + 12 + self.user_data.len()
    }
}

#[derive(Debug)]
pub struct Sack {
    pub chunk: ChunkStart,
    pub cumulative_tsn_ack: u32,
    pub a_rwnd: u32,
    pub gap_ack_blocks: Vec<(u16, u16)>,
    pub duplicate_tsns: Vec<u32>,
}

impl TryFrom<&[u8]> for Sack {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let chunk = ChunkStart::try_from(buf)?;
        let buf = &buf[4..];

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
            if buf.len() < 4 {
                return Err(SctpError::ShortPacket);
            }
            buf = &buf[4..];
            let start = u16::from_be_bytes([buf[0], buf[1]]);
            let end = u16::from_be_bytes([buf[2], buf[3]]);
            gap_ack_blocks.push((start, end));
        }

        let mut duplicate_tsns = vec![];
        for _ in 0..number_of_dup_tsns {
            if buf.len() < 4 {
                return Err(SctpError::ShortPacket);
            }
            buf = &buf[4..];
            let tsn = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            duplicate_tsns.push(tsn);
        }

        Ok(Sack {
            chunk,
            cumulative_tsn_ack,
            a_rwnd,
            gap_ack_blocks,
            duplicate_tsns,
        })
    }
}

impl WriteTo for Sack {
    fn write_to(&self, buf: &mut [u8]) {
        self.chunk.write_to(buf);
        let buf = &mut buf[4..];

        buf[0..4].copy_from_slice(&self.cumulative_tsn_ack.to_be_bytes());
        buf[4..8].copy_from_slice(&self.a_rwnd.to_be_bytes());
        let number_of_gap_acks = self.gap_ack_blocks.len() as u16;
        buf[8..10].copy_from_slice(&number_of_gap_acks.to_be_bytes());
        let number_of_dup_tsns = self.duplicate_tsns.len() as u16;
        buf[10..12].copy_from_slice(&number_of_dup_tsns.to_be_bytes());

        let mut buf = &mut buf[8..];

        for g in &self.gap_ack_blocks {
            buf = &mut buf[4..];
            buf[0..2].copy_from_slice(&g.0.to_be_bytes());
            buf[2..4].copy_from_slice(&g.1.to_be_bytes());
        }

        for g in &self.duplicate_tsns {
            buf = &mut buf[4..];
            buf[0..4].copy_from_slice(&g.to_be_bytes());
        }
    }

    fn len(&self) -> usize {
        self.chunk.len() + 12 + self.gap_ack_blocks.len() * 4 + self.duplicate_tsns.len() * 4
    }
}

#[derive(Debug)]
pub struct Heartbeat {
    pub chunk: ChunkStart,
    pub info: Vec<u8>,
}

impl TryFrom<&[u8]> for Heartbeat {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let chunk = ChunkStart::try_from(buf)?;
        if buf.len() < chunk.length || chunk.length < 4 {
            return Err(SctpError::TooShortLength);
        }
        let info = find_param(&buf[4..chunk.length], PARAM_HEARTBEAT_DATA)
            .ok_or(SctpError::MissingRequiredParam)?;
        Ok(Heartbeat {
            chunk,
            info: info.into(),
        })
    }
}

impl WriteTo for Heartbeat {
    fn write_to(&self, buf: &mut [u8]) {
        self.chunk.write_to(buf);
        write_param(&mut buf[4..], PARAM_HEARTBEAT_DATA, &self.info);
    }

    fn len(&self) -> usize {
        self.chunk.len() + self.info.len()
    }
}

#[derive(Debug)]
pub struct HeartbeatAck {
    pub heartbeat: Heartbeat,
}

impl TryFrom<&[u8]> for HeartbeatAck {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let heartbeat = Heartbeat::try_from(buf)?;
        Ok(HeartbeatAck { heartbeat })
    }
}

impl WriteTo for HeartbeatAck {
    fn write_to(&self, buf: &mut [u8]) {
        self.heartbeat.write_to(buf)
    }

    fn len(&self) -> usize {
        self.heartbeat.len()
    }
}

pub struct CookieEcho {
    pub chunk: ChunkStart,
    pub cookie: Vec<u8>,
}

impl TryFrom<&[u8]> for CookieEcho {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let chunk = ChunkStart::try_from(buf)?;
        let buf = &buf[4..];
        let len = chunk.length - 4;
        if buf.len() < len {
            return Err(SctpError::ShortPacket);
        }
        let cookie = &buf[0..len];
        Ok(CookieEcho {
            chunk,
            cookie: cookie.into(),
        })
    }
}

impl WriteTo for CookieEcho {
    fn write_to(&self, buf: &mut [u8]) {
        self.chunk.write_to(buf);
        let buf = &mut buf[4..];
        buf[..self.cookie.len()].copy_from_slice(&self.cookie);
    }

    fn len(&self) -> usize {
        self.chunk.len() + self.cookie.len()
    }
}

#[derive(Debug)]
pub struct CookieAck {
    pub chunk: ChunkStart,
}

impl TryFrom<&[u8]> for CookieAck {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let chunk = ChunkStart::try_from(buf)?;
        Ok(CookieAck { chunk })
    }
}

impl WriteTo for CookieAck {
    fn write_to(&self, buf: &mut [u8]) {
        self.chunk.write_to(buf)
    }

    fn len(&self) -> usize {
        self.chunk.len()
    }
}

fn find_param(mut buf: &[u8], param: u16) -> Option<&[u8]> {
    while !buf.is_empty() {
        let (n, p, value) = read_param(buf);
        if p == param {
            return Some(value);
        }
        buf = &buf[n..];
    }
    None
}

fn read_param(buf: &[u8]) -> (usize, u16, &[u8]) {
    let ptype = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if len < 4 {
        return (0, 0, &[]);
    }
    let val = &buf[4..(len - 4)];
    (pad4(len), ptype, val)
}

fn write_param(buf: &mut [u8], param: u16, value: &[u8]) -> usize {
    let len = value.len() + 4;
    buf[0..2].copy_from_slice(&param.to_be_bytes());
    buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    buf[4..(4 + value.len())].copy_from_slice(value);
    pad4(len)
}

impl fmt::Debug for InitAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitAck")
            .field("init", &self.init)
            .field("cookie", &self.cookie.len())
            .finish()
    }
}

impl fmt::Debug for CookieEcho {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieEcho")
            .field("chunk", &self.chunk)
            .field("cookie", &self.cookie.len())
            .finish()
    }
}

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Data")
            .field("chunk", &self.chunk)
            .field("tsn", &self.tsn)
            .field("stream_id", &self.stream_id)
            .field("stream_seq", &self.stream_seq)
            .field("payload_protocol_id", &self.payload_protocol_id)
            .field("user_data", &self.user_data.len())
            .finish()
    }
}
