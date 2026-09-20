use serde::{Deserialize, Serialize};
use std::fmt;

/// Set of telephone-event codes (RFC 4733) supported for a `telephone-event`
/// payload type.
///
/// This is the value of the SDP `a=fmtp` line for a telephone-event payload,
/// e.g. `0-15` or `0-15,66,70`. Event codes 0–9 are the DTMF digits, 10 is `*`,
/// 11 is `#`, and 12–15 are the specialized fourth-column keys `A`–`D`.
/// Event 16 is the legacy hook-flash signal commonly offered by WebRTC peers.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelephoneEvents {
    /// Bitset over the 256 possible event codes.
    bits: [u64; 4],
}

impl TelephoneEvents {
    /// An empty set.
    pub const fn empty() -> Self {
        TelephoneEvents { bits: [0; 4] }
    }

    /// The 16 DTMF keypad symbols plus legacy hook flash (event codes 0–16).
    ///
    /// This is the range commonly offered by web browsers.
    pub fn dtmf() -> Self {
        Self::from_range(0, 16)
    }

    /// Creates a set containing all event codes in the inclusive range.
    ///
    /// A reversed range produces an empty set.
    pub fn from_range(start: u8, end: u8) -> Self {
        let mut s = Self::empty();
        for e in start..=end {
            s.insert(e);
        }
        s
    }

    /// Adds an event code to the set.
    pub fn insert(&mut self, event: u8) {
        let idx = (event / 64) as usize;
        let bit = event % 64;
        self.bits[idx] |= 1 << bit;
    }

    /// Whether the event code is in the set.
    pub fn contains(&self, event: u8) -> bool {
        let idx = (event / 64) as usize;
        let bit = event % 64;
        self.bits[idx] & (1 << bit) != 0
    }

    /// Whether the set has no event codes.
    pub fn is_empty(&self) -> bool {
        self.bits == [0; 4]
    }

    /// Parses an SDP fmtp value such as `0-15`, `0-15,66,70` or `2`.
    ///
    /// Returns `None` if the value is malformed or empty.
    pub fn parse(s: &str) -> Option<Self> {
        let mut set = Self::empty();
        let parse_code = |value: &str| {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            value.parse::<u8>().ok()
        };

        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }

            if let Some((a, b)) = part.split_once('-') {
                let a = parse_code(a)?;
                let b = parse_code(b)?;
                if a > b {
                    return None;
                }
                for e in a..=b {
                    set.insert(e);
                }
            } else {
                let e = parse_code(part)?;
                set.insert(e);
            }
        }

        if set.is_empty() {
            return None;
        }

        Some(set)
    }
}

impl fmt::Display for TelephoneEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut i: u16 = 0;

        while i <= 255 {
            let e = i as u8;
            if !self.contains(e) {
                i += 1;
                continue;
            }

            // Collapse a contiguous run of event codes into `start-end`.
            let start = e;
            let mut end = e;
            while (end as u16) < 255 && self.contains(end + 1) {
                end += 1;
            }

            if !first {
                write!(f, ",")?;
            }
            first = false;

            if start == end {
                write!(f, "{start}")?;
            } else {
                write!(f, "{start}-{end}")?;
            }

            i = end as u16 + 1;
        }

        Ok(())
    }
}

impl fmt::Debug for TelephoneEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TelephoneEvents({self})")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_single_range() {
        let e = TelephoneEvents::parse("0-15").unwrap();
        assert!(e.contains(0));
        assert!(e.contains(15));
        assert!(!e.contains(16));
        assert_eq!(e.to_string(), "0-15");
    }

    #[test]
    fn parse_list_with_ranges_and_singles() {
        let e = TelephoneEvents::parse("0-15,66,70").unwrap();
        assert!(e.contains(0));
        assert!(e.contains(15));
        assert!(e.contains(66));
        assert!(e.contains(70));
        assert!(!e.contains(16));
        assert!(!e.contains(67));
        assert_eq!(e.to_string(), "0-15,66,70");
    }

    #[test]
    fn parse_single_value() {
        let e = TelephoneEvents::parse("2").unwrap();
        assert!(e.contains(2));
        assert_eq!(e.to_string(), "2");
    }

    #[test]
    fn parse_rejects_bad_input() {
        for value in [
            "", "15-0", "abc", "300", ",0-9", "0-9,", "0-9,,12", "+12", "0-+15",
        ] {
            assert!(TelephoneEvents::parse(value).is_none(), "{value}");
        }
    }

    #[test]
    fn ranges_handle_empty_and_full_boundaries() {
        assert!(TelephoneEvents::from_range(15, 0).is_empty());
        assert_eq!(TelephoneEvents::from_range(255, 255).to_string(), "255");
        let all = TelephoneEvents::from_range(0, 255);
        assert!((0..=255).all(|event| all.contains(event)));
        assert_eq!(TelephoneEvents::parse("255,0-254"), Some(all));
    }

    #[test]
    fn dtmf_default_is_0_to_16() {
        assert_eq!(TelephoneEvents::dtmf().to_string(), "0-16");
    }
}
