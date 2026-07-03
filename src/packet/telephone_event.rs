use super::{CodecExtra, Depacketizer, PacketError, Packetizer};

/// Packetizes telephone-event (RFC 4733) RTP packets.
///
/// Each telephone-event payload is a small, fixed-size event report (4 bytes)
/// that is never fragmented, so this is a pass-through packetizer.
///
/// ## Unversioned API surface
///
/// This struct is not currently versioned according to semver rules.
/// Breaking changes may be made in minor or patch releases.
#[derive(Default, Debug, Copy, Clone)]
pub struct TelephoneEventPacketizer;

impl Packetizer for TelephoneEventPacketizer {
    fn packetize(&mut self, _mtu: usize, payload: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        if payload.is_empty() {
            return Ok(vec![]);
        }

        Ok(vec![payload.to_vec()])
    }

    fn is_marker(&mut self, _data: &[u8], _previous: Option<&[u8]>, _last: bool) -> bool {
        // The marker bit for the first packet of a new event is set by the
        // caller via the start-of-talkspurt mechanism.
        false
    }
}

/// Depacketizes telephone-event (RFC 4733) RTP packets.
///
/// ## Unversioned API surface
///
/// This struct is not currently versioned according to semver rules.
/// Breaking changes may be made in minor or patch releases.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct TelephoneEventDepacketizer;

impl Depacketizer for TelephoneEventDepacketizer {
    fn out_size_hint(&self, packets_size: usize) -> Option<usize> {
        Some(packets_size)
    }

    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
        _: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        if !packet.is_empty() {
            out.extend_from_slice(packet);
        }

        Ok(())
    }

    fn is_partition_head(&self, _payload: &[u8]) -> bool {
        true
    }

    fn is_partition_tail(&self, _marker: bool, _payload: &[u8]) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn packetize_passthrough() -> Result<(), PacketError> {
        let mut pck = TelephoneEventPacketizer;
        let out = pck.packetize(1200, &[0x01, 0x0a, 0x00, 0xa0])?;
        assert_eq!(out, vec![vec![0x01, 0x0a, 0x00, 0xa0]]);
        Ok(())
    }

    #[test]
    fn packetize_empty() -> Result<(), PacketError> {
        let mut pck = TelephoneEventPacketizer;
        let out = pck.packetize(1200, &[])?;
        assert!(out.is_empty());
        Ok(())
    }

    #[test]
    fn depacketize_passthrough() -> Result<(), PacketError> {
        let mut dep = TelephoneEventDepacketizer;
        let mut out = vec![];
        let mut extra = CodecExtra::None;
        dep.depacketize(&[0x01, 0x0a, 0x00, 0xa0], &mut out, &mut extra)?;
        assert_eq!(out, vec![0x01, 0x0a, 0x00, 0xa0]);
        Ok(())
    }
}
