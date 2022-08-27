use std::collections::VecDeque;

use crate::{RtcpFb, RtcpHeader, Ssrc};

// PT=TransportLayerFeedback and FMT=1
#[derive(Debug, PartialEq, Eq)]
pub struct Nack {
    pub ssrc: Ssrc,
    pub pid: u16, // seq_no
    // bitmask with following lost packets after pid
    // https://www.rfc-editor.org/rfc/rfc4585#section-6.2.1
    pub blp: u16,
}

pub fn parse_nack_fb(header: &RtcpHeader, buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    // [header, sender-SSRC, reported-SSRC, FCI, FCI, FCI...]
    let buf = &buf[8..];
    let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();

    let fci_len = header.length - 12;
    let count = fci_len / 4;
    let mut buf = &buf[4..];

    for _ in 0..count {
        let pid = u16::from_be_bytes([buf[0], buf[1]]);
        let blp = u16::from_be_bytes([buf[2], buf[3]]);

        let nack = Nack { ssrc, pid, blp };
        queue.push_back(RtcpFb::Nack(nack));

        buf = &buf[4..];
    }
}
