use sdp::PayloadParams;

use rtp::Pt;
use sdp::{Codec, FormatParams};

pub struct CodecParams(PayloadParams);

impl CodecParams {
    pub fn pt(&self) -> Pt {
        self.0.codec.pt
    }

    pub fn codec(&self) -> Codec {
        self.0.codec.codec
    }

    pub fn clock_rate(&self) -> u32 {
        self.0.codec.clock_rate
    }

    pub fn channels(&self) -> Option<u8> {
        self.0.codec.channels
    }

    pub fn fmtp(&self) -> &FormatParams {
        &self.0.fmtps
    }

    pub(crate) fn inner(&self) -> &PayloadParams {
        &self.0
    }
}
