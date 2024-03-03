//! Data channel related types.

use std::{fmt, str, time::Instant};

use crate::sctp::RtcSctp;
use crate::util::already_happened;
use crate::{Rtc, RtcError};

pub use crate::sctp::ChannelConfig;
pub use crate::sctp::Reliability;

/// Identifier of a data channel.
///
/// This is NOT the SCTP stream id.
// Deliberately not Deref or From to avoid this Id being created outside of this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(usize);

/// Data channel data from remote peer.
///
/// This is obtained via [`Event::ChannelData`][crate::Event::ChannelData].
#[derive(PartialEq, Eq)]
pub struct ChannelData {
    /// Identifier of the channel this data was sent on.
    ///
    /// The channel would have been previously announced via
    /// [`Event::ChannelOpen`][crate::Event::ChannelOpen].
    pub id: ChannelId,

    /// Tells whether the sender sent this data as binary or text.
    pub binary: bool,

    /// The actual data sent. If `binary` is false, this can be converted to text.
    pub data: Vec<u8>,
}

/// Channel for sending data to the remote peer.
///
/// Get this handle from [`Rtc::channel()`][crate::Rtc::channel()].
pub struct Channel<'a> {
    sctp_stream_id: u16,
    rtc: &'a mut Rtc,
}

impl<'a> Channel<'a> {
    pub(crate) fn new(sctp_stream_id: u16, rtc: &'a mut Rtc) -> Self {
        Channel {
            rtc,
            sctp_stream_id,
        }
    }

    /// Write data to the remote peer and indicate whether it's text or binary.
    pub fn write(&mut self, binary: bool, buf: &[u8]) -> Result<usize, RtcError> {
        Ok(self.rtc.sctp.write(self.sctp_stream_id, binary, buf)?)
    }
}

impl fmt::Debug for ChannelData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("ChannelData");

        ds.field("id", &self.id);
        ds.field("binary", &self.binary);

        let len = &self.data.len();
        if self.binary {
            ds.field("data", len);
        } else {
            match str::from_utf8(&self.data) {
                Ok(s) => {
                    const MAX_LINE_WIDTH: usize = 79;
                    const REST_OF_LINE_WIDTH: usize =
                        "ChannelData { id: ChannelId(0), binary: false, data: \"\" }".len();
                    const TUPLE_WIDTH: usize = "(xxx, ..)".len();
                    const DATA_WIDTH: usize = MAX_LINE_WIDTH - REST_OF_LINE_WIDTH;
                    const PREFIX_WIDTH: usize = DATA_WIDTH - TUPLE_WIDTH;
                    if s.is_ascii() {
                        if len > &DATA_WIDTH {
                            let trunc: String = s.chars().take(PREFIX_WIDTH).collect();
                            ds.field("data", &format_args!("({}, \"{}\"..)", len, trunc));
                        } else {
                            ds.field("data", &s);
                        }
                    } else {
                        ds.field("data", len);
                    }
                }
                Err(e) => {
                    ds.field("data", &format_args!("{:?}", (len, &e)));
                }
            }
        }

        ds.finish()
    }
}

#[derive(Debug, Default)]
pub(crate) struct ChannelHandler {
    allocations: Vec<ChannelAllocation>,
    next_channel_id: usize,
}

#[derive(Debug)]
struct ChannelAllocation {
    id: ChannelId,

    /// Stream id, when it is known. This might be delayed awaiting sctp initialization to
    /// know if we are client or server.
    sctp_stream_id: Option<u16>,

    /// Holds the config until it is used in handle_timeout.
    config: Option<ChannelConfig>,
}

impl ChannelHandler {
    pub fn new_channel(&mut self, config: &ChannelConfig) -> ChannelId {
        let id = self.next_channel_id();

        // For out-of-band negotiated, the id is already set.
        let sctp_stream_id = config.negotiated;
        if let Some(sctp_stream_id) = sctp_stream_id {
            let exists = self
                .allocations
                .iter()
                .any(|a| a.sctp_stream_id == Some(sctp_stream_id));
            assert!(
                !exists,
                "sctp_stream_id ({}) exists already",
                sctp_stream_id
            );
        }

        let alloc = ChannelAllocation {
            id,
            sctp_stream_id,
            // The config is none until we confirm we definitely want this channel.
            config: None,
        };

        debug!("Allocate channel id: {:?}", id);
        self.allocations.push(alloc);

        id
    }

    pub fn confirm(&mut self, id: ChannelId, config: ChannelConfig) {
        let a = self
            .allocations
            .iter_mut()
            .find(|a| a.id == id)
            .expect("Entry for issued channel id");
        a.config = Some(config);
    }

    /// For translating sctp stream id to ChannelId. Any event out of sctp goes via this.
    pub fn channel_id_by_stream_id(&self, sctp_stream_id: u16) -> Option<ChannelId> {
        self.allocations
            .iter()
            .find(|a| a.sctp_stream_id == Some(sctp_stream_id))
            .map(|a| a.id)
    }

    /// Look up sctp stream id for channel id.
    pub fn stream_id_by_channel_id(&self, id: ChannelId) -> Option<u16> {
        self.allocations
            .iter()
            .find(|a| a.id == id)
            .and_then(|a| a.sctp_stream_id)
    }

    pub(crate) fn handle_timeout(&mut self, _now: Instant, sctp: &mut RtcSctp) {
        if !sctp.is_inited() {
            return;
        }

        // Allocate sctp channel ids for ones that are missing.
        self.do_allocations(sctp);

        // After do_allocations so we get a channel for any confirmed.
        self.open_channels(sctp);
    }

    /// Allocate next available `ChannelId`.
    fn next_channel_id(&mut self) -> ChannelId {
        let id = self.next_channel_id;
        self.next_channel_id += 1;

        ChannelId(id)
    }

    fn need_allocation(&self) -> bool {
        self.allocations.iter().any(|a| a.sctp_stream_id.is_none())
    }

    fn need_open(&self) -> bool {
        self.allocations.iter().any(|a| a.config.is_some())
    }

    // Do automatic allocations of sctp stream id.
    fn do_allocations(&mut self, sctp: &mut RtcSctp) {
        if !self.need_allocation() {
            return;
        }

        // RFC 8831
        // Unless otherwise defined or negotiated, the
        // streams are picked based on the DTLS role (the client picks even
        // stream identifiers, and the server picks odd stream identifiers).
        let base = if sctp.is_client() { 0 } else { 1 };

        let mut taken: Vec<u16> = self
            .allocations
            .iter()
            .filter_map(|a| a.sctp_stream_id)
            .collect();

        for a in &mut self.allocations {
            if a.sctp_stream_id.is_some() {
                continue;
            }
            // We need to allocate
            let mut proposed = base;

            while taken.contains(&proposed) {
                proposed += 2
            }

            // Found the next free.
            debug!("Associate stream id {:?} => {}", a.id, proposed);
            a.sctp_stream_id = Some(proposed);
            taken.push(proposed);
        }
    }

    // Actually open channels.
    fn open_channels(&mut self, sctp: &mut RtcSctp) {
        for a in &mut self.allocations {
            let Some(config) = a.config.take() else {
                continue;
            };
            let Some(sctp_stream_id) = a.sctp_stream_id else {
                continue;
            };

            debug!("Open stream for: {:?}", a.id);
            sctp.open_stream(sctp_stream_id, config);
        }
    }

    pub fn poll_timeout(&self, sctp: &RtcSctp) -> Option<Instant> {
        if sctp.is_inited() && (self.need_allocation() || self.need_open()) {
            Some(already_happened())
        } else {
            None
        }
    }

    pub fn ensure_channel_id_for(&mut self, sctp_stream_id: u16) {
        let exists = self
            .allocations
            .iter()
            .any(|a| a.sctp_stream_id == Some(sctp_stream_id));

        if !exists {
            let id = self.next_channel_id();
            let alloc = ChannelAllocation {
                id,
                sctp_stream_id: Some(sctp_stream_id),
                config: None,
            };
            self.allocations.push(alloc);
        }
    }

    pub fn close_channel(&mut self, id: ChannelId, sctp: &mut RtcSctp) {
        if let Some(sctp_stream_id) = self
            .allocations
            .iter()
            .find(|a| a.id == id)
            .and_then(|s| s.sctp_stream_id)
        {
            sctp.close_stream(sctp_stream_id);
        }
    }

    pub fn remove_channel(&mut self, id: ChannelId) {
        self.allocations.retain(|a| a.id != id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_allocation() {
        let mut handler = ChannelHandler::default();

        // allocate first channel, get unique id
        assert_eq!(handler.new_channel(&Default::default()), ChannelId(0));

        // allocate second channel, get unique id
        assert_eq!(handler.new_channel(&Default::default()), ChannelId(1));

        // free channel 0, allocate two more channels and verify that the
        // new channels have unique IDs.
        handler.remove_channel(ChannelId(0));
        assert_eq!(handler.new_channel(&Default::default()), ChannelId(2));
        assert_eq!(handler.new_channel(&Default::default()), ChannelId(3));
    }
}
