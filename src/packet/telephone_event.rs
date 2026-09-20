use std::collections::VecDeque;

use crate::media::TelephoneEventPayload;
use crate::rtp_::MediaTime;

use super::buffer_rx::Depacketized;
use super::{CodecExtra, Depacketizer, PacketError, Packetizer};

#[derive(Debug)]
pub struct TelephoneEventPacketizer;

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

    fn marks_talkspurt(&self) -> bool {
        true
    }

    fn nackable(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct TelephoneEventDepacketizer;

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
        let report = TelephoneEventPayload::parse_all(packet)
            .and_then(|mut reports| reports.next())
            .ok_or(PacketError::ErrTelephoneEventCorruptedPacket)?;

        out.extend_from_slice(packet);
        *codec_extra = CodecExtra::TelephoneEvent(report);
        Ok(())
    }

    fn is_partition_head(&self, _packet: &[u8]) -> bool {
        true
    }

    fn is_partition_tail(&self, _marker: bool, _packet: &[u8]) -> bool {
        true
    }
}

impl TelephoneEventDepacketizer {
    pub(super) fn split_reports(&self, packet: Depacketized, out: &mut VecDeque<Depacketized>) {
        let mut time = packet.time;
        for (index, bytes) in packet.data.chunks_exact(4).enumerate() {
            // The depacketizer has already validated the complete packet.
            let report = TelephoneEventPayload::parse(bytes).unwrap();
            out.push_back(Depacketized {
                time,
                contiguous: index > 0 || packet.contiguous,
                meta: packet.meta.clone(),
                data: bytes.to_vec(),
                codec_extra: CodecExtra::TelephoneEvent(report),
            });
            time += MediaTime::new(report.duration as u64, time.frequency());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn packetizer_keeps_reports_whole_and_uses_the_sender_marker() {
        let mut packetizer = TelephoneEventPacketizer;
        let report = [5, 0x8a, 0x03, 0x20];
        assert_eq!(
            packetizer.packetize(1200, &report).unwrap(),
            vec![report.to_vec()]
        );
        assert_eq!(
            packetizer.packetize(3, &report),
            Err(PacketError::ErrPayloadTooLarge)
        );
        assert!(packetizer.packetize(1200, &[]).unwrap().is_empty());
        assert!(!packetizer.is_marker(&report, None, true));
        assert!(packetizer.marks_talkspurt());
        assert!(!packetizer.nackable());
    }

    #[test]
    fn report_preserves_payload_and_exposes_metadata() {
        let mut depacketizer = TelephoneEventDepacketizer;
        let packet = [5, 0xca, 0x06, 0x40];
        let mut out = vec![];
        let mut extra = CodecExtra::None;
        depacketizer
            .depacketize(&packet, &mut out, &mut extra)
            .unwrap();

        assert_eq!(out, packet);
        assert_eq!(
            extra,
            CodecExtra::TelephoneEvent(TelephoneEventPayload {
                event: 5,
                end: true,
                volume: 10,
                duration: 1600,
            })
        );
        assert!(depacketizer.is_partition_head(&packet));
        assert!(depacketizer.is_partition_tail(false, &packet));
    }

    #[test]
    fn accepts_packed_reports_for_splitting() {
        let mut depacketizer = TelephoneEventDepacketizer;
        let packet = [1, 0x8a, 0, 160, 2, 0x8a, 1, 64];
        let mut out = vec![];
        let mut extra = CodecExtra::None;
        depacketizer
            .depacketize(&packet, &mut out, &mut extra)
            .unwrap();
        assert_eq!(out, packet);
        assert_eq!(
            extra,
            CodecExtra::TelephoneEvent(TelephoneEventPayload::parse(&packet).unwrap())
        );
    }

    #[test]
    fn malformed_reports_do_not_emit_partial_payloads() {
        let mut depacketizer = TelephoneEventDepacketizer;
        for packet in [&[][..], &[1], &[1, 2, 3], &[1, 0x8a, 0, 160, 2]] {
            let mut out = vec![];
            let mut extra = CodecExtra::None;
            assert_eq!(
                depacketizer.depacketize(packet, &mut out, &mut extra),
                Err(PacketError::ErrTelephoneEventCorruptedPacket)
            );
            assert!(out.is_empty());
            assert_eq!(extra, CodecExtra::None);
        }
    }
}
