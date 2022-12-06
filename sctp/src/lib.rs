#![allow(clippy::new_without_default)]

#[macro_use]
extern crate tracing;

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use message::{parse_chunks, StateCookie};
use thiserror::Error;

mod chunk;
use chunk::*;

mod message;

// Values from here
// https://webrtc.googlesource.com/src//+/c7b690272d85861a23d2f2688472971ecd3585f8/net/dcsctp/public/dcsctp_options.h

const RTO_INIT: Duration = Duration::from_millis(500);
const RTO_MAX: Duration = Duration::from_millis(60_000);
const RTO_MIN: Duration = Duration::from_millis(400);
const INIT_TIMEOUT: Duration = Duration::from_millis(1_000);
const COOKIE_TIMEOUT: Duration = Duration::from_millis(1_000);
// const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(30_000);
pub const MTU: usize = 1300;

/// Errors arising in packet- and depacketization.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SctpError {
    #[error("Packet is too short")]
    ShortPacket,
    #[error("Length field is shorter than allowed value")]
    TooShortLength,
    #[error("Missing required parameter")]
    MissingRequiredParam,
    #[error("Incorrect CRC32")]
    BadChecksum,
}

pub struct SctpAssociation {
    active: bool,
    state: AssociationState,
    association_tag_local: u32,
    pub(crate) association_tag_remote: Option<u32>,
    a_rwnd_local: u32,
    a_rwnd_remote: u32,
    tsn_local: u64,
    pub(crate) to_send: VecDeque<Chunk>,
    close_at: Option<Instant>,
    cookie_secret: [u8; 16],
    streams: HashMap<u16, Stream>,
    cumulative_tsn_ack: u64,
}

#[derive(Default)]
struct Stream {
    data: Vec<u8>,
    stream_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationState {
    Closed,
    CookieEchoWait,
    CookieWait,
    CookieEchoed,
    Established,
}

pub enum SctpInput<'a> {
    Data(&'a mut [u8]),
}

pub enum SctpEvent {
    Data(Vec<u8>),
    Text(String),
}

impl SctpAssociation {
    pub fn new() -> Self {
        let association_tag_local = loop {
            let t: u32 = rand::random();
            // Initiate Tag values SHOULD be selected from the range of 1 to 2^32 - 1
            if t != 0 {
                break t;
            }
        };
        SctpAssociation {
            active: false,
            state: AssociationState::Closed,
            association_tag_local,
            association_tag_remote: None,
            a_rwnd_local: 1500,
            a_rwnd_remote: 1500,
            tsn_local: rand::random::<u32>() as u64,
            to_send: VecDeque::new(),
            close_at: None,
            cookie_secret: rand::random(),
            streams: HashMap::new(),
            cumulative_tsn_ack: 0,
        }
    }

    pub fn poll_event(&mut self) -> Option<SctpEvent> {
        // If there is output data, that trumps all othera
        if let Some(x) = self.poll_event_output() {
            return Some(x);
        }

        None
    }

    fn poll_event_output(&mut self) -> Option<SctpEvent> {
        if let Some(data) = self.write_chunks() {
            return Some(SctpEvent::Data(data));
        }

        None
    }

    pub fn handle_input(&mut self, input: SctpInput<'_>, now: Instant) -> Result<(), SctpError> {
        match input {
            SctpInput::Data(v) => self.handle_input_data(v, now)?,
        }

        Ok(())
    }

    fn handle_input_data(&mut self, data: &mut [u8], now: Instant) -> Result<(), SctpError> {
        let chunks = parse_chunks(data)?;

        for chunk in chunks {
            self.handle_chunk(chunk, now);
        }

        Ok(())
    }

    fn handle_chunk(&mut self, chunk: Chunk, now: Instant) {
        debug!("RECV {:?}", chunk);

        match chunk {
            Chunk::Header(_) => {}
            Chunk::Init(v) => self.handle_init(v, now),
            Chunk::InitAck(v) => self.handle_init_ack(v, now),
            Chunk::Data(v) => self.handle_data(v, now),
            Chunk::Sack(v) => self.handle_sack(v, now),
            Chunk::Heartbeat(v) => self.handle_heartbeat(v, now),
            Chunk::HeartbeatAck(v) => self.handle_heartbeat_ack(v, now),
            Chunk::CookieEcho(v) => self.handle_cookie_echo(v),
            Chunk::CookieAck(v) => self.handle_cookie_ack(v),
            Chunk::Unknown(_, _) => {}
        }
    }

    // passive
    fn handle_init(&mut self, init: Init, now: Instant) {
        self.active = false;
        self.association_tag_remote = Some(init.initiate_tag);
        self.a_rwnd_remote = init.a_rwnd;
        debug!("Initial a_rwnd_remote: {}", init.a_rwnd);

        let cookie = StateCookie::new(&self.cookie_secret);

        let ack = InitAck {
            init: Init {
                chunk: ChunkStart::default(),
                initiate_tag: self.association_tag_local,
                a_rwnd: self.a_rwnd_local,
                no_outbound: u16::MAX,
                no_inbound: u16::MAX,
                initial_tsn: self.tsn_local as u32,
            },
            cookie: cookie.to_bytes(),
        };

        self.to_send.push_back(Chunk::InitAck(ack));

        self.close_at = Some(now + INIT_TIMEOUT);
        self.set_state(AssociationState::CookieEchoWait);
    }

    // passive
    fn handle_cookie_echo(&mut self, echo: CookieEcho) {
        let Some(cookie) = StateCookie::try_from(echo.cookie.as_ref()).ok() else {
            return;
        };

        if !cookie.check_valid(&self.cookie_secret) {
            return;
        }

        let ack = CookieAck {
            chunk: ChunkStart::default(),
        };
        self.to_send.push_back(Chunk::CookieAck(ack));

        self.close_at = None;
        self.set_state(AssociationState::Established);
    }

    // active
    pub fn send_init(&mut self, now: Instant) {
        assert_eq!(self.state, AssociationState::Closed);

        self.active = true;

        let init = Init {
            chunk: ChunkStart::default(),
            initiate_tag: self.association_tag_local,
            a_rwnd: self.a_rwnd_local,
            // The number of streams negotiated during SCTP association setup
            // SHOULD be 65535, which is the maximum number of streams that
            // can be negotiated during the association setup.
            no_outbound: u16::MAX,
            no_inbound: u16::MAX,
            initial_tsn: self.tsn_local as u32,
        };

        self.to_send.push_back(Chunk::Init(init));

        self.close_at = Some(now + INIT_TIMEOUT);
        self.set_state(AssociationState::CookieWait);
    }

    // active
    fn handle_init_ack(&mut self, ack: InitAck, now: Instant) {
        self.association_tag_remote = Some(ack.init.initiate_tag);
        self.a_rwnd_remote = ack.init.a_rwnd;
        debug!("Initial a_rwnd_remote: {}", ack.init.a_rwnd);

        let echo = CookieEcho {
            chunk: ChunkStart::default(),
            cookie: ack.cookie,
        };
        self.to_send.push_back(Chunk::CookieEcho(echo));

        self.close_at = Some(now + COOKIE_TIMEOUT);
        self.set_state(AssociationState::CookieEchoed);
    }

    // active
    fn handle_cookie_ack(&mut self, _ack: CookieAck) {
        self.close_at = None;
        self.set_state(AssociationState::Established);
    }

    fn set_state(&mut self, state: AssociationState) {
        debug!("{:?} -> {:?}", self.state, state);
        self.state = state;
    }

    pub(crate) fn handle_data(&mut self, data: Data, _now: Instant) {
        let _flag_immediate_ack = data.chunk.flags & 0b1000 > 0;
        let _flag_unordered = data.chunk.flags & 0b0100 > 0;
        let _flag_begin = data.chunk.flags & 0b0010 > 0;
        let _flag_end = data.chunk.flags & 0b0001 > 0;

        let _stream = self.streams.entry(data.stream_id).or_default();

        //
    }

    pub(crate) fn handle_sack(&mut self, _ack: Sack, _now: Instant) {
        //
    }

    pub(crate) fn handle_heartbeat(&mut self, _heart: Heartbeat, _now: Instant) {
        //
    }

    pub(crate) fn handle_heartbeat_ack(&mut self, _ack: HeartbeatAck, _now: Instant) {
        //
    }
}

pub(crate) fn pad4(len: usize) -> usize {
    let pad = 4 - len % 4;
    if pad < 4 {
        len + pad
    } else {
        len
    }
}
