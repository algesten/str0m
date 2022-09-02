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

impl Sdes {
    fn parse(mut buf: &[u8]) -> Option<(Sdes, usize)> {
        let mut abs = 0;

        let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
        let mut values = vec![];

        if buf.len() < 4 {
            return None;
        }
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

                let pad = 4 - abs % 4;
                if pad < 4 {
                    if buf.len() < pad {
                        return None;
                    }
                    abs += pad;
                }

                break;
            }

            let len = buf[1] as usize;

            if buf.len() < 2 + len {
                return None;
            }
            buf = &buf[2..];
            abs += 2;

            if let Ok(value) = from_utf8(&buf[..len]) {
                values.push((stype, value.to_string()));
            } else {
                // failed to read as utf-8. skip.
            }

            buf = &buf[len..];
            abs += len;
        }

        Some((Sdes { ssrc, values }, abs))
    }

    pub(crate) fn byte_size(&self) -> usize {
        let value_len: usize = self
            .values
            .iter()
            .map(|(_, s)| 2 + s.as_bytes().len())
            .sum();

        let unpadded = 4 + value_len + 1;

        let pad = 4 - (unpadded % 4);

        if pad < 4 {
            unpadded + pad
        } else {
            unpadded
        }
    }

    pub(crate) fn write_to(&self, mut buf: &mut [u8]) -> usize {
        let mut abs = 0;

        (&mut buf[0..4]).copy_from_slice(&self.ssrc.to_be_bytes());

        buf = &mut buf[4..];
        abs += 4;

        for (stype, value) in &self.values {
            buf[0] = *stype as u8;
            let len = value.as_bytes().len();

            if len > 255 {
                // ignore
                continue;
            }

            buf[1] = len as u8;

            buf = &mut buf[2..];
            abs += 2;

            (&mut buf[0..len]).copy_from_slice(value.as_bytes());
            buf = &mut buf[len..];
            abs += len;
        }

        buf[0] = SdesType::END as u8;

        buf = &mut buf[1..];
        abs += 1;

        let pad = 4 - abs % 4;
        if pad < 4 {
            for i in 0..pad {
                buf[i] = 0;
            }
            abs += pad;
        }

        abs
    }
}

pub fn parse_sdes(header: &RtcpHeader, mut buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    for _ in 0..header.fmt.count() {
        if buf.len() < 8 {
            return;
        }

        if let Some((sdes, n)) = Sdes::parse(buf) {
            queue.push_back(RtcpFb::Sdes(sdes));
            if buf.len() < n {
                return;
            }
            buf = &buf[n..];
        } else {
            break;
        }
    }
}
