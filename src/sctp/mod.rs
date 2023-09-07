#![allow(clippy::new_without_default)]

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::panic::UnwindSafe;
use std::sync::Arc;
use std::time::Instant;

use sctp_proto::{Association, AssociationHandle, ClientConfig, DatagramEvent};
use sctp_proto::{Endpoint, EndpointConfig, Stream, StreamEvent, Transmit};
use sctp_proto::{Event, Payload, PayloadProtocolIdentifier, ServerConfig};
use thiserror::Error;

pub use sctp_proto::Error as ProtoError;
use sctp_proto::ReliabilityType;

mod dcep;
use dcep::DcepOpen;

use dcep::DcepAck;

/// Errors from the SCTP subsystem.
#[derive(Debug, Error, Eq, Clone, PartialEq)]
pub enum SctpError {
    /// Some protocol error as wrapped from the sctp_proto crate.
    #[error("{0}")]
    Proto(#[from] ProtoError),

    /// Stream was not ready and we tried to write.
    #[error("Write on a stream before it was established")]
    WriteBeforeEstablished,

    /// The initial DCEP is not valid.
    #[error("DCEP open message too small")]
    DcepOpenTooSmall,
    /// The initial DCEP is not the correct message type.
    #[error("DCEP incorrect message type")]
    DcepIncorrectMessageType,
    /// The initial DCEP cant be read as utf-8.
    #[error("DCEP bad UTF-8 string")]
    DcepBadUtf8,
}

pub(crate) struct RtcSctp {
    state: RtcSctpState,
    endpoint: Endpoint,
    fake_addr: SocketAddr,
    handle: AssociationHandle,
    assoc: Option<Association>,
    entries: Vec<StreamEntry>,
    pushed_back_transmit: Option<VecDeque<Vec<u8>>>,
    last_now: Instant,
    client: bool,
}

/// This is okay because there is no way for a user of Rtc to interact with the Sctp subsystem
/// in a way that would allow them to observe a potentially broken invariant when catching a panic.
impl UnwindSafe for RtcSctp {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RtcSctpState {
    Uninited,
    AwaitRemoteAssociation,
    AwaitAssociationEstablished,
    Established,
}

impl RtcSctpState {
    pub fn propagate_endpoint_to_assoc(&self) -> bool {
        matches!(
            self,
            RtcSctpState::AwaitAssociationEstablished | RtcSctpState::Established
        )
    }
}

#[derive(Debug)]
struct StreamEntry {
    /// Config as provided when opening the channel. This is None if we discover
    /// the channel from the remote peer before getting a DcepOpen or local open_stream.
    config: Option<ChannelConfig>,
    /// Current state
    state: StreamEntryState,
    /// Actual stream id. Negotiated or automatically allocated.
    id: u16,
    /// If we are to close this entry.
    do_close: bool,
}

pub(crate) enum SctpEvent {
    Transmit {
        packets: VecDeque<Vec<u8>>,
    },
    Open {
        id: u16,
        label: String,
    },
    Close {
        id: u16,
    },
    Data {
        id: u16,
        binary: bool,
        data: Vec<u8>,
    },
}

/// These are the possible paths:
/// ```text
/// local inited, in-band                                     AwaitOpen -> AwaitDcepAck -> Open
/// local inited, out-of-band                                 AwaitOpen                 -> Open
/// remote inited, in-band     AwaitConfig -> (receive dcep)                            -> Open
/// remote inited, out-of-band AwaitConfig -> (open_stream)                             -> Open
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamEntryState {
    /// A new stream declared locally, not discovered from remote.
    AwaitOpen,
    /// A new stream, discovered from remote. It can either be in-band or out-of band
    /// We will either receive DcepOpen in-band, or a open_stream() call out-of-band.
    AwaitConfig,
    /// If we have sent DcepOpen and are waiting for the ack.
    AwaitDcepAck,
    /// Stream is open, ready to send data.
    Open,
    /// If some error occurs.
    Closed,
}

/// (Low level) configuration for a data channel.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct ChannelConfig {
    /// The label to use for the user to identify the channel.
    pub label: String,
    /// Whether channel is guaranteed ordered delivery of messages.
    pub ordered: bool,
    /// The reliability setting, which can allow to drop messages.
    pub reliability: Reliability,
    /// Whether channel is negotiated in-band (DCEP) or out-of-band.
    /// None means in-band negotiated. Some(stream_id) means out-of-band.
    pub negotiated: Option<u16>,
    /// Protocol name.
    ///
    /// Defaults to ""
    pub protocol: String,
}

/// Reliability setting of a data channel.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reliability {
    /// Packets are delivered in order, with retransmits.
    #[default]
    Reliable,
    /// Packets delivered out of order with a max lifetime.
    MaxPacketLifetime {
        /// The lifetime of a packet in milliseconds.
        lifetime: u16,
    },
    /// Packets delivered out of order with a max number of retransmits.
    MaxRetransmits {
        /// Number of retransmits before giving up.
        retransmits: u16,
    },
}

impl StreamEntry {
    fn set_state(&mut self, state: StreamEntryState) -> bool {
        if self.state == state {
            return false;
        }
        debug!("Stream {:?} -> {:?}", self.state, state);
        self.state = state;
        true
    }

    #[must_use]
    fn configure_reliability(&mut self, stream: &mut Stream) -> bool {
        let dcep: DcepOpen = self.config.as_ref().expect("config to be set").into();

        let ret = stream.set_reliability_params(
            dcep.unordered,
            dcep.channel_type,
            dcep.reliability_parameter,
        );

        if let Err(e) = ret {
            warn!(
                "Failed to set reliability params on stream {}: {:?}",
                self.id, e
            );
            self.do_close = true;
            return false;
        }

        true
    }
}

impl RtcSctp {
    pub fn new() -> Self {
        let mut config = EndpointConfig::default();
        // Default here is 1200, I've seen warnings that are 77 over.
        // DTLS above MTU 1200: 1277
        // Let's try 1120, see if we can avoid warnings.
        config.max_payload_size(1120);
        let server_config = ServerConfig::default();
        let endpoint = Endpoint::new(Arc::new(config), Some(Arc::new(server_config)));
        let fake_addr = "1.1.1.1:5000".parse().unwrap();

        RtcSctp {
            state: RtcSctpState::Uninited,
            endpoint,
            fake_addr,
            handle: AssociationHandle(0), // temporary
            assoc: None,
            entries: vec![],
            pushed_back_transmit: None,
            last_now: Instant::now(), // placeholder until init()
            client: false,
        }
    }

    pub fn is_inited(&self) -> bool {
        self.state != RtcSctpState::Uninited
    }

    pub fn init(&mut self, client: bool, now: Instant) {
        assert!(self.state == RtcSctpState::Uninited);

        self.client = client;
        self.last_now = now;

        if client {
            info!("New local association");
            let (handle, assoc) = self
                .endpoint
                .connect(ClientConfig::default(), self.fake_addr)
                .expect("be able to create an association");
            self.handle = handle;
            self.assoc = Some(assoc);
            set_state(&mut self.state, RtcSctpState::AwaitAssociationEstablished);
        } else {
            set_state(&mut self.state, RtcSctpState::AwaitRemoteAssociation);
        }
    }

    pub fn is_client(&self) -> bool {
        self.client
    }

    /// Opens a new stream.
    pub fn open_stream(&mut self, id: u16, config: ChannelConfig) {
        // The channel might already have arrived via SCTP, and if it is negotiated out-of-band
        // we are waiting for the configuration.
        let entry = stream_entry(
            &mut self.entries,
            id,
            StreamEntryState::AwaitOpen,
            "open_stream",
        );

        let in_band = config.negotiated.is_none();

        // Stream should not already have a config, we are either waiting for DcepOpen, or this is
        // out-of-band configuration, in which case this call is setting the config.
        if entry.config.is_some() {
            warn!("Stream is already configured: {}", id);
            entry.do_close = true;
            return;
        } else {
            entry.config = Some(config);
        }

        // If we are in AwaitConfig, the stream was discovered from the remote peer before
        // we got to do open_stream. This means we _must_ be in the out-of-band track,
        // since we shouldn't call open_stream on remotely started in-band.
        if entry.state == StreamEntryState::AwaitConfig {
            if in_band {
                warn!("open_stream in-band negotiation for remote stream: {}", id);
                entry.do_close = true;
            } else {
                // out-of-band where remote started. We can go to Open, but must configure the local
                // stream for it first.

                // The association must be open since we don't get AwaitConfig state without
                // polling from the remote peer.
                let mut stream = self
                    .assoc
                    .as_mut()
                    .expect("association to be open")
                    .stream(entry.id)
                    .expect("stream of entry in AwaitConfig");

                if !entry.configure_reliability(&mut stream) {
                    return;
                }

                entry.set_state(StreamEntryState::Open);
            }
        }
    }

    /// Close stream.
    pub fn close_stream(&mut self, id: u16) {
        if let Some(entry) = self.entries.iter_mut().find(|v| v.id == id) {
            entry.do_close = true;
        }
    }

    pub fn is_open(&self, id: u16) -> bool {
        if self.state != RtcSctpState::Established {
            return false;
        }

        let Some(rec) = self.entries.iter().find(|e| e.id == id) else {
            return false;
        };

        rec.state == StreamEntryState::Open
    }

    pub fn write(&mut self, id: u16, binary: bool, buf: &[u8]) -> Result<usize, SctpError> {
        if self.state != RtcSctpState::Established {
            return Err(SctpError::WriteBeforeEstablished);
        }

        let assoc = self
            .assoc
            .as_mut()
            .ok_or(SctpError::WriteBeforeEstablished)?;

        let rec = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .expect("stream entry for write");

        if rec.state != StreamEntryState::Open {
            return Err(SctpError::WriteBeforeEstablished);
        }

        let mut stream = assoc.stream(id)?;

        let ppi = if binary {
            if buf.is_empty() {
                PayloadProtocolIdentifier::BinaryEmpty
            } else {
                PayloadProtocolIdentifier::Binary
            }
        } else if buf.is_empty() {
            PayloadProtocolIdentifier::StringEmpty
        } else {
            PayloadProtocolIdentifier::String
        };

        Ok(stream.write_with_ppi(buf, ppi)?)
    }

    pub fn handle_input(&mut self, now: Instant, data: &[u8]) {
        trace!("Handle input: {}", data.len());

        // TODO, remove Bytes in sctp and just use &[u8].
        let data = data.to_vec().into();
        let r = self.endpoint.handle(now, self.fake_addr, None, None, data);

        let Some((handle, event)) = r else {
            return;
        };

        match event {
            DatagramEvent::NewAssociation(a) => {
                info!("New remote association");
                // Remote side initiated the association
                self.assoc = Some(a);
                self.handle = handle;
                set_state(&mut self.state, RtcSctpState::AwaitAssociationEstablished);
            }
            DatagramEvent::AssociationEvent(event) => {
                self.assoc
                    .as_mut()
                    .expect("association for event")
                    .handle_event(event);
            }
        }
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        if self.state == RtcSctpState::Uninited {
            // Need to call `init()` before any timeouts are accepted.
            return;
        }

        trace!("Handle timeout: {:?}", now);

        self.last_now = now;

        // Remove closed entries.
        self.entries.retain(|e| e.state != StreamEntryState::Closed);

        let Some(assoc) = &mut self.assoc else {
            return;
        };

        assoc.handle_timeout(now);

        // propagate events between endpoint and association.
        while let Some(e) = assoc.poll_endpoint_event() {
            if let Some(ae) = self.endpoint.handle_event(self.handle, e) {
                assoc.handle_event(ae);
            }
        }
    }

    pub fn poll(&mut self) -> Option<SctpEvent> {
        let r = self.do_poll();

        if let Some(r) = &r {
            trace!("Poll {:?}", r);
        }

        r
    }

    pub fn do_poll(&mut self) -> Option<SctpEvent> {
        if self.state == RtcSctpState::Uninited {
            // Need to call `init()` before any polling starts.
            return None;
        }

        if let Some(t) = self.pushed_back_transmit.take() {
            return Some(SctpEvent::Transmit { packets: t });
        }

        while let Some(t) = self.poll_transmit() {
            let Some(buf) = transmit_to_vec(t) else {
                continue;
            };

            return Some(SctpEvent::Transmit { packets: buf });
        }

        // Don't progress to move data between association and endpoint until we have an
        // association we want to drive forward.
        if !self.state.propagate_endpoint_to_assoc() {
            return None;
        }

        let Some(assoc) = &mut self.assoc else {
            return None;
        };

        while let Some(e) = assoc.poll() {
            if let Event::Connected = e {
                set_state(&mut self.state, RtcSctpState::Established);
                return self.poll();
            }

            // TODO: Do we need to handle AssociationLost?

            if let Event::Stream(se) = e {
                match se {
                    StreamEvent::Readable { id } | StreamEvent::Writable { id } => {
                        stream_entry(
                            &mut self.entries,
                            id,
                            StreamEntryState::AwaitConfig,
                            "readable/writable",
                        );
                    }
                    StreamEvent::Finished { id } | StreamEvent::Stopped { id, .. } => {
                        let entry = stream_entry(
                            &mut self.entries,
                            id,
                            StreamEntryState::AwaitConfig,
                            "closed",
                        );
                        info!("Stream {} closed", id);
                        entry.do_close = true;
                    }
                    _ => {}
                }
            }
        }

        // Must wait for association state to be established before opening streams.
        if self.state != RtcSctpState::Established {
            return None;
        }

        for entry in &mut self.entries {
            let want_open = entry.state == StreamEntryState::AwaitOpen;

            if want_open {
                info!("Open stream {}", entry.id);
                match assoc.open_stream(entry.id, PayloadProtocolIdentifier::Unknown) {
                    Ok(mut s) => {
                        if !entry.configure_reliability(&mut s) {
                            continue;
                        }

                        let config = entry.config.as_ref().expect("config if AwaitOpen");
                        let in_band = config.negotiated.is_none();

                        if in_band {
                            let dcep: DcepOpen = config.into();
                            let mut buf = vec![0; 1500];
                            let n = dcep.marshal_to(&mut buf);
                            buf.truncate(n);

                            let l = s
                                .write_with_ppi(&buf, PayloadProtocolIdentifier::Dcep)
                                .expect("writing dcep open");
                            assert!(n == l);

                            entry.set_state(StreamEntryState::AwaitDcepAck);

                            // Start over with polling, since we might have caused some network traffic by
                            // writing the DcepOpen.
                            return self.do_poll();
                        }

                        // Continuing means we are opening the stream out-of-band.
                    }
                    Err(ProtoError::ErrStreamAlreadyExist) => {
                        let config = entry.config.as_ref().expect("config if AwaitOpen");
                        let in_band = config.negotiated.is_none();

                        if in_band {
                            warn!(
                                "Opening stream {} failed: ErrStreamAlreadyExists with in-band",
                                entry.id
                            );
                            entry.do_close = true;
                            continue;
                        }

                        // Continuing means we are opening the stream out-of-band. The error can happen
                        // if both streams are declared and one side starts sending to the other
                    }
                    Err(e) => {
                        warn!("Opening stream {} failed: {:?}", entry.id, e);
                        entry.do_close = true;
                        continue;
                    }
                }

                // Consider out-of-band stream open.
                let config = entry.config.as_ref().expect("config if AwaitOpen");
                let in_band = config.negotiated.is_none();
                assert!(!in_band);

                let label = config.label.clone();
                entry.set_state(StreamEntryState::Open);

                return Some(SctpEvent::Open {
                    id: entry.id,
                    label,
                });
            }

            if entry.do_close && entry.state != StreamEntryState::Closed {
                entry.set_state(StreamEntryState::Closed);
                return Some(SctpEvent::Close { id: entry.id });
            }

            let mut stream = match assoc.stream(entry.id) {
                Ok(v) => v,
                Err(e) => {
                    // This is expected on browser refresh or similar abrupt shutdown.
                    debug!("Getting stream {} failed: {:?}", entry.id, e);
                    entry.do_close = true;
                    continue;
                }
            };

            match stream_read_data(&mut stream) {
                Ok(Some((buf, ppi))) => {
                    if ppi != PayloadProtocolIdentifier::Dcep {
                        // This is the normal path for incoming data.
                        let buf = ppi_adjust_buf(buf, ppi);
                        let binary = matches!(
                            ppi,
                            PayloadProtocolIdentifier::Binary
                                | PayloadProtocolIdentifier::BinaryEmpty
                        );
                        return Some(SctpEvent::Data {
                            id: entry.id,
                            binary,
                            data: buf,
                        });
                    }

                    // It's Dcep, either a DcepOpen or DcepAck.
                    match entry.state {
                        // We are in AwaitConfig state which means we are either going to get it via
                        // the DcepOpen, or by an out-of-band configuration via open_stream.
                        // This indicates we are doing in-band.
                        StreamEntryState::AwaitConfig => {
                            let dcep: DcepOpen = match buf.as_slice().try_into() {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!("Failed to read incoming DCEP {}: {:?}", entry.id, e);
                                    entry.do_close = true;
                                    continue;
                                }
                            };

                            if entry.config.is_none() {
                                entry.config = Some((&dcep).into());
                            } else {
                                warn!("Received DcepOpen for configured stream: {}", entry.id);
                            }

                            let mut obuf = [0];
                            DcepAck.marshal_to(&mut obuf);
                            let l = stream
                                .write_with_ppi(&obuf, PayloadProtocolIdentifier::Dcep)
                                .expect("writing dcep open");
                            assert!(obuf.len() == l);

                            entry.set_state(StreamEntryState::Open);

                            return Some(SctpEvent::Open {
                                id: entry.id,
                                label: dcep.label,
                            });
                        }
                        StreamEntryState::AwaitDcepAck => {
                            let res: Result<DcepAck, _> = buf.as_slice().try_into();

                            if let Err(e) = res {
                                warn!("Failed to read incoming DCEP ACK {}: {:?}", entry.id, e);
                                entry.do_close = true;
                                continue;
                            }

                            entry.set_state(StreamEntryState::Open);
                            let config = entry.config.as_ref().expect("config when DcepAck");

                            return Some(SctpEvent::Open {
                                id: entry.id,
                                label: config.label.clone(),
                            });
                        }
                        _ => {
                            warn!(
                                "Stream {} in wrong state when receiving DCEP: {:?}",
                                entry.id, entry.state
                            );
                            entry.do_close = true;
                            continue;
                        }
                    }
                }
                Ok(None) => continue,
                Err(_) => entry.do_close = true,
            }
        }

        None
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.assoc.as_mut().and_then(|a| a.poll_timeout())
    }

    pub fn push_back_transmit(&mut self, data: VecDeque<Vec<u8>>) {
        trace!("Push back transmit: {}", data.len());
        assert!(self.pushed_back_transmit.is_none());
        self.pushed_back_transmit = Some(data);
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        if let Some(t) = self.endpoint.poll_transmit() {
            return Some(t);
        }

        if let Some(t) = self.assoc.as_mut()?.poll_transmit(self.last_now) {
            return Some(t);
        }

        None
    }
}

fn transmit_to_vec(t: Transmit) -> Option<VecDeque<Vec<u8>>> {
    let Payload::RawEncode(v) = t.payload else {
        return None;
    };

    Some(v.into_iter().map(|b| b.to_vec()).collect())
}

fn set_state(current_state: &mut RtcSctpState, state: RtcSctpState) {
    if *current_state != state {
        info!("{:?} => {:?}", current_state, state);
        *current_state = state;
    }
}

fn stream_entry<'a>(
    entries: &'a mut Vec<StreamEntry>,
    id: u16,
    initial_state: StreamEntryState,
    reason: &'static str,
) -> &'a mut StreamEntry {
    let idx = entries.iter().position(|v| v.id == id);
    if let Some(idx) = idx {
        entries.get_mut(idx).unwrap()
    } else {
        info!("New stream {} ({:?}): {}", id, initial_state, reason);
        let e = StreamEntry {
            config: None,
            state: initial_state,
            id,
            do_close: false,
        };
        entries.push(e);
        entries.last_mut().unwrap()
    }
}

fn stream_read_data(
    stream: &mut Stream,
) -> Result<Option<(Vec<u8>, PayloadProtocolIdentifier)>, SctpError> {
    let Some(chunks) = stream.read()? else {
        return Ok(None);
    };

    let n = chunks.len();
    let mut buf = vec![0; n];

    let l = chunks.read(&mut buf)?;
    assert!(l == n);

    use PayloadProtocolIdentifier::*;
    match chunks.ppi {
        Dcep | String | Binary => {} // keep as is
        StringEmpty | BinaryEmpty => buf.clear(),
        _ => {
            return Err(SctpError::Proto(ProtoError::Other(
                "Unknown PayloadProtocolIdentifier".into(),
            )));
        }
    }

    Ok(Some((buf, chunks.ppi)))
}

fn ppi_adjust_buf(mut buf: Vec<u8>, ppi: PayloadProtocolIdentifier) -> Vec<u8> {
    match ppi {
        PayloadProtocolIdentifier::StringEmpty | PayloadProtocolIdentifier::BinaryEmpty => {
            buf.clear();
            buf
        }
        _ => buf,
    }
}

impl fmt::Debug for SctpEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transmit { packets } => f
                .debug_struct("Transmit")
                .field("packets", &packets.len())
                .finish(),
            Self::Open { id, label } => f
                .debug_struct("Open")
                .field("id", id)
                .field("label", label)
                .finish(),
            Self::Close { id } => f.debug_struct("Close").field("id", id).finish(),
            Self::Data { id, binary, data } => f
                .debug_struct("Data")
                .field("id", id)
                .field("binary", binary)
                .field("data", &data.len())
                .finish(),
        }
    }
}

impl From<&ChannelConfig> for DcepOpen {
    fn from(v: &ChannelConfig) -> Self {
        let (channel_type, reliability_parameter) = (&v.reliability).into();
        DcepOpen {
            unordered: !v.ordered,
            channel_type,
            reliability_parameter,
            priority: 0,
            label: v.label.clone(),
            protocol: v.protocol.clone(),
        }
    }
}

impl From<&Reliability> for (ReliabilityType, u32) {
    fn from(v: &Reliability) -> Self {
        match v {
            Reliability::Reliable => (ReliabilityType::Reliable, 0),
            Reliability::MaxPacketLifetime { lifetime } => {
                (ReliabilityType::Timed, *lifetime as u32)
            }
            Reliability::MaxRetransmits { retransmits } => {
                (ReliabilityType::Rexmit, *retransmits as u32)
            }
        }
    }
}

impl From<&DcepOpen> for ChannelConfig {
    fn from(v: &DcepOpen) -> Self {
        ChannelConfig {
            label: v.label.clone(),
            ordered: !v.unordered,
            reliability: (v.channel_type, v.reliability_parameter).into(),
            negotiated: None,
            protocol: v.protocol.clone(),
        }
    }
}

impl From<(ReliabilityType, u32)> for Reliability {
    fn from((r, p): (ReliabilityType, u32)) -> Self {
        match r {
            ReliabilityType::Reliable => Reliability::Reliable,
            ReliabilityType::Rexmit => Reliability::MaxRetransmits {
                retransmits: p as u16,
            },
            ReliabilityType::Timed => Reliability::MaxPacketLifetime { lifetime: p as u16 },
        }
    }
}
