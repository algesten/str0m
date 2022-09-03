use std::collections::VecDeque;

use crate::{RtcpFb, RtcpHeader, Ssrc};

#[derive(Debug, PartialEq, Eq)]
pub struct Fir {
    /// The SSRC value of the media sender that is
    /// requested to send a decoder refresh point.
    pub ssrc: Ssrc,

    /// Command sequence number.  The sequence number
    /// space is unique for each pairing of the SSRC of command
    /// source and the SSRC of the command target.  The sequence
    /// number SHALL be increased by 1 modulo 256 for each new
    /// command.
    pub seq_no: u8,
}

impl Fir {
    pub(crate) fn write_to(&self, buf: &mut [u8]) -> usize {
        // Shape here
        // https://www.rfc-editor.org/rfc/rfc5104.html#page-42

        // [[header, sender-SSRC], who-knows-SSRC, FCI, FCI, FCI...]
        // FCI = [SSRC, [seq_no (8 bit), reserved]]

        todo!()
    }
}

pub fn parse_fir(_header: &RtcpHeader, buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    //
}
