#[macro_use]
extern crate tracing;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use sctp_proto::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Event,
    Payload, PayloadProtocolIdentifier, ServerConfig, Stream, StreamEvent, Transmit,
};
use thiserror::Error;

pub use sctp_proto::Error as ProtoError;
pub use sctp_proto::ReliabilityType;

mod dcep;
pub use dcep::DcepOpen;

use crate::dcep::DcepAck;

#[derive(Debug, Error, Eq, Clone, PartialEq)]
pub enum SctpError {
    #[error("{0}")]
    Proto(#[from] ProtoError),

    #[error("Write on a stream before it was established")]
    WriteBeforeEstablished,

    #[error("DCEP open message too small")]
    DcepOpenTooSmall,
    #[error("DCEP incorrect message type")]
    DcepIncorrectMessageType,
    #[error("DCEP bad UTF-8 string")]
    DcepBadUtf8,
}

pub struct RtcSctp {
    state: RtcSctpState,
    endpoint: Endpoint,
    fake_addr: SocketAddr,
    handle: AssociationHandle,
    assoc: Option<Association>,
    entries: Vec<StreamEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcSctpState {
    Uninited,
    AwaitRemoteAssociation,
    AwaitAssociationEstablished,
    Established,
}

impl RtcSctpState {
    pub fn propagate_endpoint_to_assoc(&self) -> bool {
        match self {
            RtcSctpState::AwaitAssociationEstablished => true,
            RtcSctpState::Established => true,
            _ => false,
        }
    }
}

pub struct StreamEntry {
    id: u16,
    state: StreamEntryState,
    do_close: bool,
    dcep: Option<DcepOpen>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEntryState {
    AwaitOpen,
    SendDcepOpen,
    AwaitDcep,
    AwaitDcepAck,
    Open,
    Closed,
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
}

pub enum SctpEvent {
    Transmit(Vec<u8>),
    Open(u16, DcepOpen),
    Close(u16),
    Data(u16, bool, Vec<u8>),
}

impl RtcSctp {
    pub fn new() -> Self {
        let config = EndpointConfig::default();
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
        }
    }

    pub fn is_inited(&self) -> bool {
        self.state != RtcSctpState::Uninited
    }

    pub fn init(&mut self, active: bool) {
        assert!(self.state == RtcSctpState::Uninited);

        if active {
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

    pub fn open_stream(&mut self, id: u16, dcep: DcepOpen) {
        // New entries are added in state AwaitOpen, and the poll() function
        // will create the corresponding streams once the association is established.
        let new_entry = StreamEntry {
            id,
            state: StreamEntryState::AwaitOpen,
            do_close: false,
            dcep: Some(dcep),
        };

        self.entries.push(new_entry);
    }

    pub fn write(&mut self, id: u16, binary: bool, buf: &[u8]) -> Result<usize, SctpError> {
        let assoc = self
            .assoc
            .as_mut()
            .ok_or(SctpError::WriteBeforeEstablished)?;
        let mut stream = assoc.stream(id)?;
        let ppi = if binary {
            if buf.is_empty() {
                PayloadProtocolIdentifier::BinaryEmpty
            } else {
                PayloadProtocolIdentifier::Binary
            }
        } else {
            if buf.is_empty() {
                PayloadProtocolIdentifier::StringEmpty
            } else {
                PayloadProtocolIdentifier::String
            }
        };
        Ok(stream.write(buf, ppi)?)
    }

    pub fn handle_input(&mut self, now: Instant, data: &[u8]) {
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

    pub fn poll(&mut self, now: Instant) -> Option<SctpEvent> {
        if self.state == RtcSctpState::Uninited {
            // Need to call `init()` before any polling starts.
            return None;
        }

        while let Some(t) = self.poll_transmit(now) {
            let Some(buf) = transmit_to_vec(t) else {
                continue;
            };

            return Some(SctpEvent::Transmit(buf));
        }

        // Don't progress to move data between association and endpoint until we have an
        // association we want to drive forward.
        if !self.state.propagate_endpoint_to_assoc() {
            return None;
        }

        let Some(assoc) = &mut self.assoc else {
            return None;
        };

        // propagate events between endpoint and association.
        while let Some(e) = assoc.poll_endpoint_event() {
            if let Some(ae) = self.endpoint.handle_event(self.handle, e) {
                assoc.handle_event(ae);
            }
        }

        while let Some(e) = assoc.poll() {
            if let Event::Connected = e {
                set_state(&mut self.state, RtcSctpState::Established);
                return self.poll(now);
            }

            // TODO: Do we need to handle AssociationLost?

            if let Event::Stream(se) = e {
                match se {
                    StreamEvent::Readable { id } | StreamEvent::Writable { id } => {
                        stream_entry(&mut self.entries, id);
                    }
                    StreamEvent::Finished { id } | StreamEvent::Stopped { id, .. } => {
                        let entry = stream_entry(&mut self.entries, id);
                        info!("Stream {} closed", id);
                        entry.do_close = true;
                    }
                    _ => {}
                }
            }
        }

        // Remove closed entries.
        self.entries.retain(|e| e.state != StreamEntryState::Closed);

        for entry in &mut self.entries {
            let want_open = entry.state == StreamEntryState::AwaitOpen;
            let can_open = self.state == RtcSctpState::Established;

            if want_open && !can_open {
                continue;
            }

            if want_open {
                match assoc.open_stream(entry.id, PayloadProtocolIdentifier::Unknown) {
                    Ok(mut s) => {
                        let dcep = entry.dcep.as_ref().take().expect("AwaitOpen to have dcep");

                        let ret = s.set_reliability_params(
                            dcep.unordered,
                            dcep.channel_type,
                            dcep.reliability_parameter,
                        );

                        if let Err(e) = ret {
                            warn!(
                                "Failed to set reliability params on stream {}: {:?}",
                                entry.id, e
                            );
                            entry.do_close = true;
                            continue;
                        }

                        entry.set_state(StreamEntryState::SendDcepOpen);
                    }
                    Err(e) => {
                        warn!("Opening stream {} failed: {:?}", entry.id, e);
                        entry.do_close = true;
                        continue;
                    }
                };
            }

            if entry.do_close && entry.state != StreamEntryState::Closed {
                entry.set_state(StreamEntryState::Closed);
                return Some(SctpEvent::Close(entry.id));
            }

            let mut stream = match assoc.stream(entry.id) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Getting stream {} failed: {:?}", entry.id, e);
                    entry.do_close = true;
                    continue;
                }
            };

            match entry.state {
                StreamEntryState::SendDcepOpen => {
                    let dcep = entry.dcep.as_ref().expect("dcep to send");

                    let mut buf = vec![0; 1500];
                    let n = dcep.marshal_to(&mut buf);
                    buf.truncate(n);

                    let l = stream
                        .write(&buf, PayloadProtocolIdentifier::Dcep)
                        .expect("writing dcep open");
                    assert!(n == l);

                    entry.set_state(StreamEntryState::AwaitDcepAck);
                    return self.poll(now);
                }
                _ => {}
            }

            match stream_read_data(&mut stream) {
                Ok(Some((buf, ppi))) => {
                    if ppi != PayloadProtocolIdentifier::Dcep {
                        if entry.state != StreamEntryState::Open {
                            warn!(
                                "Received DCEP for not open stream {}: {:?}",
                                entry.id, entry.state
                            );
                            entry.do_close = true;
                            continue;
                        }

                        let buf = ppi_adjust_buf(buf, ppi);
                        let binary = matches!(
                            ppi,
                            PayloadProtocolIdentifier::Binary
                                | PayloadProtocolIdentifier::BinaryEmpty
                        );
                        return Some(SctpEvent::Data(entry.id, binary, buf));
                    }

                    // it's Dcep
                    match entry.state {
                        StreamEntryState::AwaitDcep => {
                            let dcep = match buf.as_slice().try_into() {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!("Failed to read incoming DCEP {}: {:?}", entry.id, e);
                                    entry.do_close = true;
                                    continue;
                                }
                            };

                            let mut obuf = [0];
                            DcepAck.marshal_to(&mut obuf);
                            let l = stream
                                .write(&obuf, PayloadProtocolIdentifier::Dcep)
                                .expect("writing dcep open");
                            assert!(obuf.len() == l);

                            entry.set_state(StreamEntryState::Open);
                            return Some(SctpEvent::Open(entry.id, dcep));
                        }
                        StreamEntryState::AwaitDcepAck => {
                            let res: Result<DcepAck, _> = buf.as_slice().try_into();

                            if let Err(e) = res {
                                warn!("Failed to read incoming DCEP ACK {}: {:?}", entry.id, e);
                                entry.do_close = true;
                                continue;
                            }

                            let dcep = entry.dcep.take().expect("dcep when ack");

                            entry.set_state(StreamEntryState::Open);
                            return Some(SctpEvent::Open(entry.id, dcep));
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

    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit> {
        if let Some(t) = self.endpoint.poll_transmit() {
            return Some(t);
        }

        if let Some(t) = self.assoc.as_mut()?.poll_transmit(now) {
            return Some(t);
        }

        None
    }
}

fn transmit_to_vec(t: Transmit) -> Option<Vec<u8>> {
    let Payload::RawEncode(v) = t.payload else {
        return None;
    };

    let len = v.iter().map(|b| b.len()).sum();
    let mut buf = vec![0; len];
    let mut n = 0;
    for b in v {
        let l = b.len();
        (&mut buf[n..(n + l)]).copy_from_slice(&b);
        n += l;
    }

    Some(buf)
}

fn set_state(current_state: &mut RtcSctpState, state: RtcSctpState) {
    if *current_state != state {
        info!("{:?} => {:?}", current_state, state);
        *current_state = state;
    }
}

fn stream_entry(entries: &mut Vec<StreamEntry>, id: u16) -> &mut StreamEntry {
    let idx = entries.iter().position(|v| v.id == id);
    if let Some(idx) = idx {
        entries.get_mut(idx).unwrap()
    } else {
        let e = StreamEntry {
            id,
            state: StreamEntryState::AwaitDcep,
            do_close: false,
            dcep: None,
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
