use std::collections::VecDeque;
use std::str::from_utf8;

use crate::{RtcpFb, RtcpHeader, Ssrc};

#[derive(Debug, PartialEq, Eq)]
pub struct Sdes {
    pub ssrc: Ssrc,
    pub values: Vec<(SdesType, String)>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SdesType {
    /// End of SDES list
    END = 0,
    /// Canonical name.
    CNAME = 1,
    /// User name
    NAME = 2,
    /// User's electronic mail address
    EMAIL = 3,
    /// User's phone number
    PHONE = 4,
    /// Geographic user location
    LOC = 5,
    /// Name of application or tool
    TOOL = 6,
    /// Notice about the source
    NOTE = 7,
    /// Private extensions
    PRIV = 8,
    /// Who knows
    Unknown,
}

impl SdesType {
    fn from_u8(u: u8) -> Self {
        use SdesType::*;
        match u {
            0 => END,
            1 => CNAME,
            2 => NAME,
            3 => EMAIL,
            4 => PHONE,
            5 => LOC,
            6 => TOOL,
            7 => NOTE,
            8 => PRIV,
            _ => Unknown,
        }
    }
}

pub fn parse_sdes(header: &RtcpHeader, buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    let mut buf = &buf[4..];
    let mut abs = 0;

    for _ in 0..header.fmt.count() {
        let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();

        queue.push_back(RtcpFb::Sdes(Sdes {
            ssrc,
            values: vec![],
        }));

        // TODO there must be a better way, right?
        let sdes = match queue.back_mut().unwrap() {
            RtcpFb::Sdes(v) => v,
            _ => unreachable!(),
        };

        buf = &buf[4..];
        abs += 4;
        loop {
            let stype = SdesType::from_u8(buf[0]);

            if matches!(stype, SdesType::END) {
                // The end of SDES.

                // Each chunk consists of an SSRC/CSRC identifier followed by a list of
                // zero or more items, which carry information about the SSRC/CSRC.
                // Each chunk starts on a 32-bit boundary.
                //
                // Items are contiguous, i.e., items are not individually padded to a
                // 32-bit boundary.  Text is not null terminated because some multi-
                // octet encodings include null octets.
                //
                // No length octet follows the null item type octet, but additional null
                // octets MUST be included if needed to pad until the next 32-bit
                // boundary.

                let pad = abs % 4;
                buf = &buf[pad..];
                abs += pad;

                break;
            }

            let len = buf[1] as usize;
            buf = &buf[2..];
            abs += 2;

            if let Ok(value) = from_utf8(&buf[..len]) {
                sdes.values.push((stype, value.to_string()));
            } else {
                // failed to read as utf-8. skip.
            }

            buf = &buf[len..];
            abs += len;
        }
    }

    //
}
