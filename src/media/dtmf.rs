//! Telephone-event (DTMF, RFC 4733) wire payload helpers.
//!
//! Telephone events use a dedicated `telephone-event` payload type negotiated
//! inside an audio m-line. Each report occupies four bytes; an RTP packet can
//! contain multiple reports. [`Writer::write_dtmf`][crate::media::Writer::write_dtmf]
//! schedules outgoing tones; applications can also send individual RTP reports.
//! The sample API emits each incoming report separately with telephone-event
//! codec metadata, leaving receive-side aggregation to the application.

/// A DTMF keypad symbol or supported legacy telephone event carried by RFC 4733.
///
/// RFC 4733 defines further event codes beyond the ones listed here, so this enum may
/// gain variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Dtmf {
    D0,
    D1,
    D2,
    D3,
    D4,
    D5,
    D6,
    D7,
    D8,
    D9,
    /// The `*` key.
    Star,
    /// The `#` key.
    Pound,
    /// The `A` key from the fourth column of a 16-key DTMF keypad.
    ///
    /// `A`-`D` are uncommon on consumer phones, but remain part of DTMF for
    /// military, network-control, and other specialized telephone systems.
    A,
    /// The specialized `B` key from a 16-key DTMF keypad. See [`Dtmf::A`].
    B,
    /// The specialized `C` key from a 16-key DTMF keypad. See [`Dtmf::A`].
    C,
    /// The specialized `D` key from a 16-key DTMF keypad. See [`Dtmf::A`].
    D,
    /// Briefly interrupts the phone line without ending the call.
    ///
    /// Traditional phone systems call this a *hook flash* and use it for
    /// features such as call waiting, call transfer, and three-way calling.
    /// This is legacy telephone event 16, not a DTMF keypad tone.
    Flash,
}

impl Dtmf {
    /// The RFC 4733 event code for this event.
    pub fn event_code(&self) -> u8 {
        use Dtmf::*;
        match self {
            D0 => 0,
            D1 => 1,
            D2 => 2,
            D3 => 3,
            D4 => 4,
            D5 => 5,
            D6 => 6,
            D7 => 7,
            D8 => 8,
            D9 => 9,
            Star => 10,
            Pound => 11,
            A => 12,
            B => 13,
            C => 14,
            D => 15,
            Flash => 16,
        }
    }

    /// Creates a [`Dtmf`] from an RFC 4733 event code, if it is a known event.
    pub fn from_event_code(code: u8) -> Option<Dtmf> {
        use Dtmf::*;
        Some(match code {
            0 => D0,
            1 => D1,
            2 => D2,
            3 => D3,
            4 => D4,
            5 => D5,
            6 => D6,
            7 => D7,
            8 => D8,
            9 => D9,
            10 => Star,
            11 => Pound,
            12 => A,
            13 => B,
            14 => C,
            15 => D,
            16 => Flash,
            _ => return None,
        })
    }

    /// The dialpad character for this event, if any.
    pub fn to_char(&self) -> Option<char> {
        use Dtmf::*;
        Some(match self {
            D0 => '0',
            D1 => '1',
            D2 => '2',
            D3 => '3',
            D4 => '4',
            D5 => '5',
            D6 => '6',
            D7 => '7',
            D8 => '8',
            D9 => '9',
            Star => '*',
            Pound => '#',
            A => 'A',
            B => 'B',
            C => 'C',
            D => 'D',
            Flash => return None,
        })
    }

    /// Parses a dialpad character (`0`-`9`, `*`, `#`, `A`-`D`) into an event.
    pub fn from_char(c: char) -> Option<Dtmf> {
        use Dtmf::*;
        Some(match c.to_ascii_uppercase() {
            '0' => D0,
            '1' => D1,
            '2' => D2,
            '3' => D3,
            '4' => D4,
            '5' => D5,
            '6' => D6,
            '7' => D7,
            '8' => D8,
            '9' => D9,
            '*' => Star,
            '#' => Pound,
            'A' => A,
            'B' => B,
            'C' => C,
            'D' => D,
            _ => return None,
        })
    }
}

/// A single telephone-event (RFC 4733) RTP payload.
///
/// Use this helper to build payloads for the RTP API or inspect
/// [`Event::RtpPacket`][crate::Event::RtpPacket] payloads. It does not schedule
/// tones or aggregate repeated reports; use
/// [`Writer::write_dtmf`][crate::media::Writer::write_dtmf] for scheduled transmission.
/// The sample API emits each report as
/// [`MediaData`][crate::media::MediaData] with
/// [`CodecExtra::TelephoneEvent`][crate::format::CodecExtra::TelephoneEvent].
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     event     |E|R| volume    |          duration             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// ```
/// use str0m::media::{Dtmf, TelephoneEventPayload};
///
/// let report = TelephoneEventPayload {
///     event: Dtmf::D5.event_code(),
///     end: true,
///     volume: 10,
///     duration: 800,
/// };
/// let bytes = report.to_bytes();
/// assert_eq!(TelephoneEventPayload::parse(&bytes), Some(report));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelephoneEventPayload {
    /// The event code (RFC 4733 Section 2.5.1.1). See [`Dtmf::from_event_code`].
    pub event: u8,

    /// The end bit: set on the final packet(s) of an event (RFC 4733 Section 2.5.1.3).
    pub end: bool,

    /// The volume of the event, in -dBm0 (0-63, RFC 4733 Section 2.5.2.1).
    ///
    /// Only meaningful for DTMF events. Higher values are quieter.
    pub volume: u8,

    /// The duration of the current event segment, in RTP timestamp units
    /// (samples at the negotiated telephone-event clock rate).
    pub duration: u16,
}

impl TelephoneEventPayload {
    /// Parses a telephone-event report from the first four bytes of an RTP payload.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        Some(TelephoneEventPayload {
            event: buf[0],
            end: buf[1] & 0x80 != 0,
            volume: buf[1] & 0x3f,
            duration: u16::from_be_bytes([buf[2], buf[3]]),
        })
    }

    /// Parses every consecutive telephone event in an RTP payload.
    ///
    /// RFC 4733 permits multiple contiguous events in one packet. The payload
    /// must therefore be a non-empty multiple of four bytes.
    pub fn parse_all(buf: &[u8]) -> Option<impl Iterator<Item = Self> + '_> {
        if buf.is_empty() || buf.len() % 4 != 0 {
            return None;
        }

        Some(buf.chunks_exact(4).map(|chunk| {
            // unwrap: chunks_exact guarantees a four-byte chunk.
            Self::parse(chunk).unwrap()
        }))
    }

    /// Serializes this payload to its four wire bytes.
    pub fn to_bytes(&self) -> [u8; 4] {
        let [d0, d1] = self.duration.to_be_bytes();
        let end = if self.end { 0x80 } else { 0x00 };
        [self.event, end | (self.volume & 0x3f), d0, d1]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn payload_roundtrip() {
        let p = TelephoneEventPayload {
            event: 5,
            end: true,
            volume: 10,
            duration: 1600,
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes, [0x05, 0x8a, 0x06, 0x40]);
        assert_eq!(TelephoneEventPayload::parse(&bytes), Some(p));
        for len in 0..4 {
            assert!(TelephoneEventPayload::parse(&bytes[..len]).is_none());
        }
    }

    #[test]
    fn payload_parse_all() {
        let first = TelephoneEventPayload {
            event: 1,
            end: true,
            volume: 10,
            duration: 160,
        };
        let second = TelephoneEventPayload {
            event: 2,
            end: true,
            volume: 10,
            duration: 320,
        };
        let bytes = [first.to_bytes(), second.to_bytes()].concat();

        let mut payloads = TelephoneEventPayload::parse_all(&bytes).unwrap();
        assert_eq!(payloads.next(), Some(first));
        assert_eq!(payloads.next(), Some(second));
        assert_eq!(payloads.next(), None);
        assert!(TelephoneEventPayload::parse_all(&bytes[..7]).is_none());
        assert!(TelephoneEventPayload::parse_all(&[]).is_none());
    }

    #[test]
    fn payload_ignores_reserved_bit_and_masks_volume() {
        let payload = TelephoneEventPayload::parse(&[255, 0xff, 0xff, 0xff]).unwrap();
        assert_eq!(payload.event, 255);
        assert!(payload.end);
        assert_eq!(payload.volume, 63);
        assert_eq!(payload.duration, u16::MAX);
        assert_eq!(payload.to_bytes(), [255, 0xbf, 0xff, 0xff]);
    }

    #[test]
    fn dtmf_char_roundtrip() {
        for c in "0123456789*#ABCD".chars() {
            let d = Dtmf::from_char(c).unwrap();
            assert_eq!(d.to_char(), Some(c));
            assert_eq!(Dtmf::from_event_code(d.event_code()), Some(d));
        }
        assert_eq!(Dtmf::from_char('a'), Some(Dtmf::A));
        assert_eq!(Dtmf::from_char('x'), None);
        assert_eq!(Dtmf::Flash.event_code(), 16);
        assert_eq!(Dtmf::from_event_code(16), Some(Dtmf::Flash));
        assert_eq!(Dtmf::Flash.to_char(), None);
        assert_eq!(Dtmf::from_event_code(17), None);
    }
}
