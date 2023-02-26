//! Data channel related types.

use std::fmt;

pub use rtp_::ChannelId;

use crate::{Rtc, RtcError};

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
    id: ChannelId,
    rtc: &'a mut Rtc,
}

impl<'a> Channel<'a> {
    pub(crate) fn new(id: ChannelId, rtc: &'a mut Rtc) -> Self {
        Channel { rtc, id }
    }

    /// Write data to the remote peer and indicate whether it's text or binary.
    pub fn write(&mut self, binary: bool, buf: &[u8]) -> Result<usize, RtcError> {
        Ok(self.rtc.sctp.write(*self.id, binary, buf)?)
    }
}

impl fmt::Debug for ChannelData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelData")
            .field("id", &self.id)
            .field("binary", &self.binary)
            .field("data", &self.data.len())
            .finish()
    }
}
