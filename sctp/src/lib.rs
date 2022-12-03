// #[macro_use]
// extern crate tracing;

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crc::{Crc, CRC_32_ISCSI};
use thiserror::Error;
use tracing::{debug, warn};

mod chunk;
mod message;

// Values from here
// https://webrtc.googlesource.com/src//+/c7b690272d85861a23d2f2688472971ecd3585f8/net/dcsctp/public/dcsctp_options.h

const RTO_INIT: Duration = Duration::from_millis(500);
const RTO_MAX: Duration = Duration::from_millis(60_000);
const RTO_MIN: Duration = Duration::from_millis(400);
const INIT_TIMEOUT: Duration = Duration::from_millis(1_000);
const COOKIE_TIMEOUT: Duration = Duration::from_millis(1_000);
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(30_000);
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
}

// pub struct SctpAssociation {
//     active: bool,
//     state: AssociationState,
//     association_tag_local: u32,
//     association_tag_remote: Option<u32>,
//     a_rwnd_local: u32,
//     a_rwnd_remote: u32,
//     tsn_local: u32,
//     to_send: VecDeque<Chunks>,
//     close_at: Option<Instant>,
//     cookie_secret: [u8; 16],
// }

// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum AssociationState {
//     Closed,
//     CookieEchoWait,
//     CookieWait,
//     CookieEchoed,
//     Established,
// }

// pub enum SctpInput<'a> {
//     Data(&'a mut [u8]),
// }

// pub enum SctpEvent {
//     Data(Vec<u8>),
//     Text(String),
// }

// impl SctpAssociation {
//     pub fn new() -> Self {
//         let association_tag_local = loop {
//             let t: u32 = rand::random();
//             // Initiate Tag values SHOULD be selected from the range of 1 to 2^32 - 1
//             if t != 0 {
//                 break t;
//             }
//         };
//         SctpAssociation {
//             active: false,
//             state: AssociationState::Closed,
//             association_tag_local,
//             association_tag_remote: None,
//             a_rwnd_local: 1500,
//             a_rwnd_remote: 1500,
//             tsn_local: rand::random(),
//             to_send: VecDeque::new(),
//             close_at: None,
//             cookie_secret: rand::random(),
//         }
//     }

//     pub fn poll_event(&mut self) -> Option<SctpEvent> {
//         // If there is output data, that trumps all othera
//         if let Some(x) = self.poll_event_output() {
//             return Some(x);
//         }

//         None
//     }

//     fn poll_event_output(&mut self) -> Option<SctpEvent> {
//         if let Some(data) = self.poll_event_data() {
//             return Some(SctpEvent::Data(data));
//         }

//         None
//     }

//     fn poll_event_data(&mut self) -> Option<Vec<u8>> {
//         let c = self.to_send.pop_front()?;
//         debug!("SEND {:?}", c);

//         let mut buf = vec![0_u8; MTU];

//         let is_init = matches!(c, Chunks::Init(_));
//         let verification_tag = if is_init {
//             0
//         } else {
//             self.association_tag_remote.expect("Remote association tag")
//         };

//         let header = Header {
//             checksum: 0,
//             source_port: 5000,
//             destination_port: 5000,
//             verification_tag,
//         };
//         let len_h = header.write_to(&mut buf);
//         let len_c = c.write_to(&mut buf[len_h..]);

//         let total = len_h + len_c;
//         assert!(total % 4 == 0, "Packet must be multiple of 4");

//         buf.truncate(total);

//         let checksum = sctp_crc(&buf);
//         (&mut buf[8..12]).copy_from_slice(&checksum.to_be_bytes());

//         Some(buf)
//     }

//     pub fn handle_input(&mut self, input: SctpInput<'_>, now: Instant) {
//         match input {
//             SctpInput::Data(v) => self.handle_input_data(v, now),
//         }
//     }

//     fn handle_input_data(&mut self, data: &mut [u8], now: Instant) {
//         //     0                   1                   2                   3
//         //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//         //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         //    |                         Common Header                         |
//         //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         //    |                           Chunk #1                            |
//         //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         //    |                              ...                              |
//         //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         //    |                           Chunk #n                            |
//         //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//         // First comes the common header.
//         let header = match Header::try_from(&*data) {
//             Ok(v) => v,
//             Err(err) => {
//                 warn!("Incorrect common header in SCTP packet: {:?}", err);
//                 return;
//             }
//         };

//         // When an SCTP packet is received, the receiver MUST first check the CRC32c checksum as follows:
//         // 1) Store the received CRC32c checksum value aside.
//         // 2) Replace the 32 bits of the checksum field in the received SCTP packet with
//         //    0 and calculate a CRC32c checksum value of the whole received packet.

//         (&mut data[8..12]).copy_from_slice(&0_u32.to_be_bytes());
//         let checksum = sctp_crc(&data);

//         let is_init = data[12] == 1;

//         if !is_init && header.checksum != checksum {
//             debug!(
//                 "Drop SCTP, checksum mismatch {} != {}",
//                 header.checksum, checksum
//             );
//             return;
//         }

//         let mut buf = &data[12..];
//         loop {
//             match Chunks::parse_next(buf) {
//                 Ok((chunk, len)) => {
//                     let Some(chunk) = chunk else {
//                         break;
//                     };
//                     self.handle_chunk(chunk, now);
//                     let pad = 4 - len % 4;
//                     let padded = len + if pad < 4 { pad } else { 0 };
//                     buf = &buf[padded..];
//                 }
//                 Err(err) => {
//                     warn!("Failed to parse chunk: {:?}", err);
//                     break;
//                 }
//             }
//         }
//     }

//     fn handle_chunk(&mut self, chunk: Chunks, now: Instant) {
//         debug!("RECV {:?}", chunk);

//         match (self.state, chunk) {
//             (AssociationState::Closed, Chunks::Init(v)) => self.handle_init(v, now),
//             (AssociationState::CookieEchoWait, Chunks::CookieEcho(v)) => self.handle_cookie_echo(v),
//             (AssociationState::CookieWait, Chunks::InitAck(v)) => self.handle_init_ack(v, now),
//             (AssociationState::CookieEchoed, Chunks::CookieAck(v)) => self.handle_cookie_ack(v),
//             (AssociationState::Established, Chunks::Data(_)) => todo!(),
//             (AssociationState::Established, Chunks::Sack(_)) => todo!(),
//             (AssociationState::Established, Chunks::Heartbeat(_)) => todo!(),
//             (AssociationState::Established, Chunks::HeartbeatAck(_)) => todo!(),
//             (_state, _chunk) => {
//                 // warn
//             }
//         }
//     }

//     // passive
//     fn handle_init(&mut self, init: Chunk<Init>, now: Instant) {
//         self.active = false;
//         self.association_tag_remote = Some(init.value.initiate_tag);
//         self.a_rwnd_remote = init.value.a_rwnd;

//         let ack = InitAck(Init {
//             initiate_tag: self.association_tag_local,
//             a_rwnd: self.a_rwnd_local,
//             no_outbound: u16::MAX,
//             no_inbound: u16::MAX,
//             initial_tsn: self.tsn_local,
//         });

//         let mut c = Chunk::new(ChunkType::InitAck, ack);

//         let cookie = StateCookie {
//             checksum: 0,
//             association_tag_local: self.association_tag_local,
//             association_tag_remote: init.value.initiate_tag,
//             salt: rand::random(),
//         };

//         let bytes = cookie.to_bytes(&self.cookie_secret);

//         c.params.push(InitAckParam::StateCookie(bytes));
//         self.to_send.push_back(Chunks::InitAck(c));

//         self.close_at = Some(now + INIT_TIMEOUT);
//         self.set_state(AssociationState::CookieEchoWait);
//     }

//     // passive
//     fn handle_cookie_echo(&mut self, echo: Chunk<CookieEcho>) {
//         let Some(cookie) = StateCookie::from_bytes(&self.cookie_secret, &echo.value.cookie) else {
//             return;
//         };

//         if cookie.association_tag_local != self.association_tag_local {
//             warn!("Cookie does match association_tag_local");
//         }

//         if Some(cookie.association_tag_remote) != self.association_tag_remote {
//             warn!("Cookie does match association_tag_remote");
//         }

//         let ack = CookieAck;
//         let c = Chunk::new(ChunkType::CookieAck, ack);
//         self.to_send.push_back(Chunks::CookieAck(c));

//         self.close_at = None;
//         self.set_state(AssociationState::Established);
//         todo!()
//     }

//     // active
//     pub fn send_init(&mut self, now: Instant) {
//         assert_eq!(self.state, AssociationState::Closed);

//         self.active = true;

//         let ack = Init {
//             initiate_tag: self.association_tag_local,
//             a_rwnd: self.a_rwnd_local,
//             // The number of streams negotiated during SCTP association setup
//             // SHOULD be 65535, which is the maximum number of streams that
//             // can be negotiated during the association setup.
//             no_outbound: u16::MAX,
//             no_inbound: u16::MAX,
//             initial_tsn: self.tsn_local,
//         };

//         let c = Chunk::new(ChunkType::Init, ack);
//         self.to_send.push_back(Chunks::Init(c));

//         self.close_at = Some(now + INIT_TIMEOUT);
//         self.set_state(AssociationState::CookieWait);
//     }

//     // active
//     fn handle_init_ack(&mut self, ack: Chunk<InitAck, InitAckParam>, now: Instant) {
//         let cookie = ack.params.into_iter().find_map(|c| {
//             if let InitAckParam::StateCookie(c) = c {
//                 Some(c)
//             } else {
//                 None
//             }
//         });

//         let cookie = cookie.expect("InitAck to have state cookie");

//         let echo = CookieEcho { cookie };
//         let c = Chunk::new(ChunkType::CookieEcho, echo);
//         self.to_send.push_back(Chunks::CookieEcho(c));

//         self.close_at = Some(now + COOKIE_TIMEOUT);
//         self.set_state(AssociationState::CookieEchoed);
//     }

//     // active
//     fn handle_cookie_ack(&mut self, _ack: Chunk<CookieAck>) {
//         self.close_at = None;
//         self.set_state(AssociationState::Established);
//     }

//     fn set_state(&mut self, state: AssociationState) {
//         debug!("{:?} -> {:?}", self.state, state);
//         self.state = state;
//     }
// }

// fn sctp_crc(buf: &[u8]) -> u32 {
//     const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);
//     let mut digest = CRC.digest();
//     digest.update(&buf);
//     // The CRC library calculates something that is reverse from what we expect when
//     // writing to the wire i big endian.
//     digest.finalize().swap_bytes()
// }

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn parse_init_ack() {
//         let mut sctp1 = SctpAssociation::new();
//         let mut sctp2 = SctpAssociation::new();

//         let now = Instant::now();
//         sctp1.send_init(now);

//         let mut packet_init = sctp1.poll_event_data().unwrap();

//         sctp2.handle_input(SctpInput::Data(&mut packet_init), now);

//         let mut packet_init_ack = sctp2.poll_event_data().unwrap();

//         sctp1.handle_input(SctpInput::Data(&mut packet_init_ack), now);
//     }
// }
