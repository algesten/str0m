use std::collections::VecDeque;

use crate::{RtcpFb, RtcpHeader};

pub fn parse_twcc_fb(_header: &RtcpHeader, _buf: &[u8], _queue: &mut VecDeque<RtcpFb>) {
    // TODO: let's deal with this madness later.
}

// #[derive(Debug, Copy, Clone, Eq, PartialEq)]
// /// Record of receiving one transport wide cc.
// pub struct TransportWideCC(pub u16, pub MediaTime);

// pub const TRANSPORT_WIDE_CC_MAX: usize = 4;

// pub fn build_transport_fb(
//     send_transport_cc: &mut u8,
//     ssrc: u32,
//     timestamp: &MediaTime,
//     to_send: &mut [Option<TransportWideCC>],
//     output: &mut Vec<Vec<u8>>,
// ) -> Option<()> {
//     // https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01

//     //     0                   1                   2                   3
//     //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    |V=2|P|  FMT=15 |    PT=205     |           length              |
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    |                     SSRC of packet sender                     |
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    |                      SSRC of media source                     |
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    |      base sequence number     |      packet status count      |
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    |                 reference time                | fb pkt. count |
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    |          packet chunk         |         packet chunk          |
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    .                                                               .
//     //    .                                                               .
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    |         packet chunk          |  recv delta   |  recv delta   |
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    .                                                               .
//     //    .                                                               .
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //    |           recv delta          |  recv delta   | zero padding  |
//     //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//     // Deltas are represented as multiples of 250us:
//     // o  If the "Packet received, small delta" symbol has been appended to
//     //     the status list, an 8-bit unsigned receive delta will be appended
//     //     to recv delta list, representing a delta in the range [0, 63.75]
//     //     ms.
//     // o  If the "Packet received, large or negative delta" symbol has been
//     //     appended to the status list, a 16-bit signed receive delta will be
//     //     appended to recv delta list, representing a delta in the range
//     //     [-8192.0, 8191.75] ms.
//     const DELTA: i64 = 250; // microseconds
//     const WRAP_PERIOD: i64 = 1 << 24;

//     loop {
//         // If no index found, deliberate early return
//         let mut index = to_send.iter().position(|t| t.is_none())?;
//         let first = to_send[index].take()?;

//         let buf = vec![0_u8; 256];
//         output.push(buf);
//         let last = output.len() - 1;

//         let buf = output.get_mut(last).unwrap();
//         buf.resize(20, 0); // space for header + 1 chunk.

//         // 5 bits This field identifies the type
//         // of the FB message.  It must have the value 15.
//         buf[0] = 2 << 6 | 15;
//         // 8 bits This is the RTCP packet type that
//         // identifies the packet as being an RTCP FB message.  The
//         // value must be RTPFB = 205.
//         buf[1] = RtcpType::TransportLayerFeedback as u8;
//         // len and padding written afterwards

//         buf[4..8].copy_from_slice(&ssrc.to_be_bytes());
//         buf[8..12].copy_from_slice(&(ssrc + 1).to_be_bytes());

//         let base_seq = first.0;
//         buf[12..14].copy_from_slice(&base_seq.to_be_bytes());
//         let mut total_count = 0;
//         // packet status count written after

//         let ref_time = first.1;
//         let fb_count = *send_transport_cc;
//         *send_transport_cc += 1;

//         let t_and_c = (((ref_time.as_micros() % WRAP_PERIOD) / DELTA) << 8) | (fb_count as i64);
//         buf[16..20].copy_from_slice(&t_and_c.to_be_bytes());

//         let mut cur = first;
//         let mut deltas = Vec::with_capacity(TRANSPORT_WIDE_CC_MAX);
//         let mut chunks = 0;

//         loop {
//             let delta_ts = cur.1 - ref_time;
//             deltas.push(delta_ts);

//             let delta = delta_ts.as_micros() / DELTA;

//             if delta < -32768 || delta > 32767 {
//                 // If the delta exceeds even the larger limits, a new feedback
//                 // message must be used, where the 24-bit base receive delta can
//                 // cover very large gaps.
//                 break;
//             }

//             // Position for handling next one.
//             index += 1;
//             if index == to_send.len() {
//                 break;
//             }
//             cur = to_send[index].take().unwrap();
//         }

//         // write deltas
//         // write status count, len and padding
//     }

//     Some(())
// }
