//! RFC 4733 telephone-event (DTMF) RTP payloads.
//!
//! A payload is one or more 4-byte event reports and is never split across RTP packets.

use super::{CodecExtra, Depacketizer, PacketError, Packetizer};

const REPORT_LEN: usize = 4;

/// A telephone-event (DTMF, RFC 4733) report.
///
/// Builds and parses the 4-byte reports carried in telephone-event RTP payloads.
///
/// ```
/// use str0m::media::TelephoneEventPayload;
///
/// let report = TelephoneEventPayload {
///     event: 5,
///     end: true,
///     volume: 10,
///     duration: 800,
/// };
/// let bytes = report.to_bytes();
/// assert_eq!(TelephoneEventPayload::parse(&bytes), Some(report));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelephoneEventPayload {
    /// The event code (RFC 4733 Section 2.3.1).
    ///
    /// DTMF digits `0`-`9` are codes 0-9, `*` is 10, `#` is 11 and `A`-`D` are 12-15
    /// (RFC 4733 Section 3.2).
    pub event: u8,

    /// Whether this report ends the event (RFC 4733 Section 2.3.2).
    pub end: bool,

    /// The tone power in -dBm0, 0-63 (RFC 4733 Section 2.3.4). Larger values are quieter.
    pub volume: u8,

    /// How long the event has lasted so far, in RTP timestamp units (RFC 4733 Section 2.3.5).
    pub duration: u16,
}

impl TelephoneEventPayload {
    /// Parses the report in the first four bytes of `buf`.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let [event, flags, d0, d1, ..] = *buf else {
            return None;
        };

        Some(TelephoneEventPayload {
            event,
            end: flags & 0x80 != 0,
            volume: flags & 0x3f,
            duration: u16::from_be_bytes([d0, d1]),
        })
    }

    /// Parses every report in an RTP payload.
    ///
    /// A payload can pack consecutive reports (RFC 4733 Section 2.5.1.5): the first starts at the
    /// RTP timestamp and each later one where the previous one ended. Returns `None` unless the
    /// payload is one or more whole reports.
    pub fn parse_all(buf: &[u8]) -> Option<impl Iterator<Item = Self> + '_> {
        if buf.is_empty() || buf.len() % REPORT_LEN != 0 {
            return None;
        }

        Some(buf.chunks_exact(REPORT_LEN).filter_map(Self::parse))
    }

    /// Serializes the report to its four wire bytes.
    ///
    /// The reserved bit is zero and only the low six bits of the volume are sent.
    pub fn to_bytes(&self) -> [u8; 4] {
        let [d0, d1] = self.duration.to_be_bytes();
        let end = if self.end { 0x80 } else { 0 };
        [self.event, end | (self.volume & 0x3f), d0, d1]
    }
}

#[derive(Debug)]
pub struct TelephoneEventPacketizer;

#[derive(Debug)]
pub struct TelephoneEventDepacketizer;

impl Packetizer for TelephoneEventPacketizer {
    fn packetize(&mut self, mtu: usize, payload: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        if payload.is_empty() {
            return Ok(vec![]);
        }

        if payload.len() > mtu {
            return Err(PacketError::ErrPayloadTooLarge);
        }

        Ok(vec![payload.to_vec()])
    }

    fn is_marker(&mut self, _data: &[u8], _previous: Option<&[u8]>, _last: bool) -> bool {
        false
    }

    // The marker bit flags the first packet of an event (RFC 4733 Section 2.2.2), which the
    // sender signals as a start of talkspurt.
    fn marks_talkspurt(&self) -> bool {
        true
    }

    fn nackable(&self) -> bool {
        false
    }
}

impl Depacketizer for TelephoneEventDepacketizer {
    fn out_size_hint(&self, packets_size: usize) -> Option<usize> {
        Some(packets_size)
    }

    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
        codec_extra: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        let reports = TelephoneEventPayload::parse_all(packet)
            .ok_or(PacketError::ErrTelephoneEventCorruptedPacket)?;
        let mut events = Vec::with_capacity(packet.len() / REPORT_LEN);
        events.extend(reports);

        out.extend_from_slice(packet);
        *codec_extra = CodecExtra::TelephoneEvent(events);
        Ok(())
    }

    fn is_partition_head(&self, _packet: &[u8]) -> bool {
        true
    }

    fn is_partition_tail(&self, _marker: bool, _packet: &[u8]) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Event 5, end bit set, volume 10, duration 800.
    const REPORT: [u8; 4] = [0x05, 0x8a, 0x03, 0x20];
    // Event 6, volume 10, duration 320.
    const NEXT: [u8; 4] = [0x06, 0x0a, 0x01, 0x40];

    #[test]
    fn payload_roundtrip() {
        let report = TelephoneEventPayload {
            event: 5,
            end: true,
            volume: 10,
            duration: 800,
        };

        assert_eq!(report.to_bytes(), REPORT);
        assert_eq!(TelephoneEventPayload::parse(&REPORT), Some(report));
        for len in 0..REPORT_LEN {
            assert_eq!(TelephoneEventPayload::parse(&REPORT[..len]), None);
        }
    }

    #[test]
    fn payload_ignores_reserved_bit_and_masks_volume() {
        let report = TelephoneEventPayload::parse(&[0xff; 4]).unwrap();
        assert_eq!(report.volume, 63);
        assert_eq!(report.to_bytes(), [0xff, 0xbf, 0xff, 0xff]);

        let loud = TelephoneEventPayload {
            event: 0,
            end: false,
            volume: 0xff,
            duration: 0,
        };
        assert_eq!(loud.to_bytes(), [0, 0x3f, 0, 0]);
    }

    #[test]
    fn parse_all_requires_whole_reports() {
        let packed = [REPORT, NEXT].concat();

        let reports: Vec<_> = TelephoneEventPayload::parse_all(&packed).unwrap().collect();
        assert_eq!(
            reports,
            [
                TelephoneEventPayload::parse(&REPORT).unwrap(),
                TelephoneEventPayload::parse(&NEXT).unwrap(),
            ]
        );

        for len in [0, 1, 3, 5, 7] {
            assert!(TelephoneEventPayload::parse_all(&packed[..len]).is_none());
        }
    }

    #[test]
    fn packetizer_sends_reports_whole() {
        let mut packetizer = TelephoneEventPacketizer;
        let packed = [REPORT, NEXT].concat();

        assert_eq!(
            packetizer.packetize(4, &REPORT).unwrap(),
            vec![REPORT.to_vec()]
        );
        assert_eq!(packetizer.packetize(1200, &packed).unwrap(), vec![packed]);
    }

    #[test]
    fn packetizer_rejects_payload_larger_than_mtu() {
        let mut packetizer = TelephoneEventPacketizer;

        assert_eq!(
            packetizer.packetize(3, &REPORT),
            Err(PacketError::ErrPayloadTooLarge)
        );
    }

    #[test]
    fn packetizer_does_not_emit_empty_payload() {
        let mut packetizer = TelephoneEventPacketizer;

        assert!(packetizer.packetize(1200, &[]).unwrap().is_empty());
    }

    #[test]
    fn packetizer_marks_start_of_event_and_is_not_nackable() {
        let mut packetizer = TelephoneEventPacketizer;

        assert!(!packetizer.is_marker(&REPORT, None, true));
        assert!(packetizer.marks_talkspurt());
        assert!(!packetizer.nackable());
    }

    #[test]
    fn depacketizer_passes_reports_through() {
        let mut depacketizer = TelephoneEventDepacketizer;
        let first = TelephoneEventPayload::parse(&REPORT).unwrap();
        let second = TelephoneEventPayload::parse(&NEXT).unwrap();
        let packed = [REPORT, NEXT].concat();

        for (packet, expected) in [
            (&REPORT[..], vec![first]),
            (&packed[..], vec![first, second]),
        ] {
            let mut out = Vec::new();
            let mut extra = CodecExtra::None;
            depacketizer
                .depacketize(packet, &mut out, &mut extra)
                .unwrap();

            assert_eq!(out, packet);
            assert_eq!(extra, CodecExtra::TelephoneEvent(expected));
            assert!(depacketizer.is_partition_head(packet));
            assert!(depacketizer.is_partition_tail(false, packet));
        }
    }

    #[test]
    fn depacketizer_rejects_empty_and_partial_reports() {
        let mut depacketizer = TelephoneEventDepacketizer;
        let packed = [REPORT, NEXT].concat();

        for len in [0, 1, 3, 5, 7] {
            let mut out = Vec::new();
            let mut extra = CodecExtra::None;
            let result = depacketizer.depacketize(&packed[..len], &mut out, &mut extra);

            assert_eq!(result, Err(PacketError::ErrTelephoneEventCorruptedPacket));
            assert!(out.is_empty());
            assert_eq!(extra, CodecExtra::None);
        }

        let error = PacketError::ErrTelephoneEventCorruptedPacket;
        assert_eq!(error.to_string(), "Telephone-event corrupted packet");
    }
}
