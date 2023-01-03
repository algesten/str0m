//! Data channel related types.

use std::fmt;

pub use rtp::ChannelId;

use crate::{Rtc, RtcError};

/// Data channel data.
#[derive(PartialEq, Eq)]
pub struct ChannelData {
    pub id: ChannelId,
    pub binary: bool,
    pub data: Vec<u8>,
}

pub struct Channel<'a> {
    id: ChannelId,
    rtc: &'a mut Rtc,
}

impl<'a> Channel<'a> {
    pub(crate) fn new(id: ChannelId, rtc: &'a mut Rtc) -> Self {
        Channel { rtc, id }
    }

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
