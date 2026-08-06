//! Runs the DTLS handshake over ICE, inside connectivity checks,
//! to save round trips.
//!
//! Rather than rely on DTLS retransmitting on a timer, DTLS packets are
//! resent until acked.
//!
//! DTLS packets are only read out of connectivity checks that have already
//! passed their `MESSAGE-INTEGRITY` check.
//!
//! This can be safely enabled because if the remote side does not implement it,
//! it does not include the DTLS attributes and the local side disables the extension.
//!
//! Throughout, a *packet* is one datagram the DTLS engine wanted to send, which
//! may hold more than one DTLS *record*. Nothing here looks inside it beyond
//! the first byte, so the distinction only matters when reading the RFCs.
//!
//! There is no IETF standard for this. libwebrtc is basically the documentation.

use std::collections::VecDeque;

use crc::{CRC_32_ISO_HDLC, Crc};
use str0m_proto::DATAGRAM_MTU_TARGET_MIN;

/// How many ACKs can be in one DTLS_ACKS attribute.
/// Small because the attribute has to fit alongside everything else in a
/// connectivity check; older hashes are dropped first.
pub const MAX_DTLS_ACK_COUNT: usize = 4;

/// The largest a connectivity check may grow to.
///
/// A conservative MTU (1200) less room for headers.
const MAX_ICE_CHECK_LENGTH: usize = 1200 - 24 - 8;

/// Space reserved for the authenticated STUN message and the SPED attribute
/// headers around a DTLS packet.
const DTLS_OVER_ICE_OVERHEAD: usize = 150;

/// The length of a DTLS record header.
const DTLS_RECORD_HEADER_LEN: usize = 13;

/// The lowest byte value that can begin a DTLS record, per RFC 7983.
const DTLS_FIRST_BYTE_MIN: u8 = 20;

/// The highest byte value that can begin a DTLS record, per RFC 7983.
const DTLS_FIRST_BYTE_MAX: u8 = 63;

/// The DTLS datagram target that leaves room for SPED encapsulation.
pub fn dtls_mtu(ice_mtu: usize) -> usize {
    ice_mtu
        .saturating_sub(DTLS_OVER_ICE_OVERHEAD)
        .max(DATAGRAM_MTU_TARGET_MIN)
}

/// Runs the DTLS handshake over ICE.
///
/// The ICE agent owns one of these when the extension is enabled. It captures
/// the DTLS packets the application would otherwise have sent as datagrams,
/// attaches them to outgoing connectivity checks, and reports back the packets
/// that arrive on incoming ones.
#[derive(Clone, Debug)]
pub struct DtlsOverIce {
    state: DtlsOverIceState,
    /// Always short, so a deque beats a map.
    packets: VecDeque<DtlsOverIcePacket>,
    acks_to_send: Vec<DtlsAckHash>,
    // %%% meh
    /// Scratch buffer for the encoded ack attribute.
    ack_encoded: Vec<u8>,
    // %%% meh
    data_received_count: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DtlsOverIceState {
    /// We do not yet know whether the remote end supports this, so we send packets
    /// and watch for a reply.
    RemoteSupportUnknown,
    /// The remote end replied with one of the attributes, so it does support it.
    RemoteSupportConfirmed,
    /// Our own handshake finished; we are waiting for the remote end to acknowledge
    /// everything we sent.
    WaitingForAcks,
    /// Finished.
    Complete,
    /// The remote end does not support it, or DTLS failed. Fall back to an ordinary
    /// handshake.
    Disabled,
}

/// A packet taken from the DTLS engine.
/// Taking it means owning it. The engine will never send it again, so it is
/// delivered from here — inside connectivity checks, or as an ordinary datagram
/// when those cannot carry it — until the peer acknowledges it.
#[derive(Clone, Debug)]
struct DtlsOverIcePacket {
    payload: Vec<u8>,
    hash: DtlsAckHash,
    /// How many times it has gone out over ICE.
    ///
    /// Zero means no connectivity check has carried it, which makes it fair
    /// game for an ordinary DTLS packet as soon as ICE is connected. Once a
    /// check has carried it we don't want to send it as an ordinary DTLS packet
    /// too, because that would deliver it twice.
    ///
    /// Above zero it is what keeps the checks cycling: the least sent one goes
    /// next, so the packets take turns without leaving the order they were
    /// handed over in.
    ice_send_count: u64,
}

/// A cheap identity for a DTLS packet, used to acknowledge it.
///
/// CRC-32, so this detects *duplicates*, not tampering. It is a bookkeeping
/// aid, never a security check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DtlsAckHash(u32);

/// The DTLS-over-ICE attributes for one outgoing connectivity check.
///
/// Both fields are already sized to fit in the check they belong to.
pub struct DtlsAttributesToSend {
    /// The DTLS packet to carry, if there is one that fits.
    pub packet: Option<Vec<u8>>,
    /// The encoded acknowledgements, which may be empty.
    pub acks: Vec<u8>,
}

impl DtlsOverIce {
    pub const fn new() -> Self {
        DtlsOverIce {
            state: DtlsOverIceState::RemoteSupportUnknown,
            packets: VecDeque::new(),
            acks_to_send: Vec::new(),
            ack_encoded: Vec::new(),
            data_received_count: 0,
        }
    }

    pub fn state(&self) -> DtlsOverIceState {
        self.state
    }

    /// Takes the packets the DTLS engine wanted to send, to send them over ICE
    ///
    /// DtlsOverIce *takes* them, meaning it takes responsibility for sending them,
    /// either over ICE or as regular DTLS packets.
    pub fn take_dtls_packets_to_send(&mut self, dtls_packets: impl IntoIterator<Item = Vec<u8>>) {
        if !self.state.is_active() {
            return;
        }

        for dtls_packet in dtls_packets {
            let hash = DtlsAckHash::of_packet(&dtls_packet);

            // Don't sent the same DTLS packet twice
            if self.packets.iter().any(|held| held.hash == hash) {
                continue;
            }

            self.packets.push_back(DtlsOverIcePacket {
                payload: dtls_packet,
                hash,
                ice_send_count: 0,
            });
        }
    }

    /// The attributes to attach to an outgoing connectivity check that is
    /// `message_length` bytes without them.
    ///
    /// `None` when the extension is no longer live, or when not even the
    /// acknowledgements fit in the check.
    pub fn attributes_to_send(
        &mut self,
        message_byte_len_so_far: usize,
        ice_mtu: usize,
    ) -> Option<DtlsAttributesToSend> {
        let max_check_length = ice_mtu.min(MAX_ICE_CHECK_LENGTH);

        // The ack attribute goes on every check while the extension is live,
        // even when empty: its presence is what tells the peer we support this.
        let acks = self
            .acks_to_send()
            .filter(|ack| fits_in_ice_check(message_byte_len_so_far, ack.len(), max_check_length))
            .map(|ack| ack.to_vec())?;

        // The packet has to fit in what is left once the acks are in.
        let message_byte_len_with_acks = message_byte_len_so_far + attribute_size(acks.len());
        let packet = self
            .packets_to_send_with_limit(message_byte_len_with_acks, max_check_length)
            .map(|dtls_packet| dtls_packet.to_vec());

        Some(DtlsAttributesToSend { packet, acks })
    }

    /// The encoded acknowledgements to attach to an outgoing connectivity
    /// check.
    ///
    /// Note this returns an empty slice rather than nothing when there is
    /// nothing to acknowledge: the attribute's *presence* is what tells the
    /// peer we support the extension, so an empty one is still worth sending.
    fn acks_to_send(&mut self) -> Option<&[u8]> {
        if !self.state.is_active() {
            return None;
        }
        DtlsAckHash::encode_attribute(&self.acks_to_send, &mut self.ack_encoded);
        Some(&self.ack_encoded)
    }

    /// The packet to attach to an outgoing connectivity check, if any.
    ///
    /// The least sent packet goes next, so a check does not keep resending the
    /// same one while others go unacknowledged, and ties are broken by the
    /// order the packets were handed over in. Nothing is reordered, so a flight
    /// still leaves in the order DTLS produced it. `message_length` is how big
    /// the check already is; a packet that would push it past the MTU is
    /// skipped, so an oversized packet cannot block the smaller ones behind it.
    /// Such a packet goes out as an ordinary datagram instead, via
    /// [`DtlsOverIce::poll_dtls_packet_to_send_not_over_ice`].
    #[cfg(test)]
    fn packets_to_send(&mut self, message_length: usize) -> Option<&[u8]> {
        self.packets_to_send_with_limit(message_length, MAX_ICE_CHECK_LENGTH)
    }

    fn packets_to_send_with_limit(
        &mut self,
        message_length: usize,
        max_check_length: usize,
    ) -> Option<&[u8]> {
        if !self.state.is_active() {
            return None;
        }

        // Anything not shaped like DTLS is not put in the attribute, since the
        // peer would only drop it again. It still goes out as a datagram.
        let index = self
            .packets
            .iter()
            .enumerate()
            .filter(|(_, packet)| {
                is_dtls_packet(&packet.payload)
                    && fits_in_ice_check(message_length, packet.payload.len(), max_check_length)
            })
            .min_by_key(|(_, packet)| packet.ice_send_count)
            .map(|(index, _)| index)?;

        let packet = self.packets.get_mut(index)?;
        packet.ice_send_count += 1;

        Some(&packet.payload)
    }

    pub fn handle_ice_check_received(
        &mut self,
        dtls_packet_attribute: Option<&[u8]>,
        acks_attribute: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        if !self.state.is_active() {
            return None;
        }

        if self.state == DtlsOverIceState::RemoteSupportUnknown {
            if dtls_packet_attribute.is_none() && acks_attribute.is_none() {
                // Neither attribute came back, so the peer does not implement
                // this. Fall back to an ordinary handshake. Note this is not
                // reported as a DTLS failure: DTLS is about to proceed
                // normally, just over plain datagrams.
                //
                // The packets this took on are deliberately kept. They were
                // dropped from the DTLS send queue, so this is the only place
                // they still exist, and it sends them as ordinary datagrams via
                // [`DtlsOverIce::poll_dtls_packet_to_send_not_over_ice`].
                // Any a check already carried have to go out again: the peer
                // ignored the attribute, so it never saw them.
                self.state = DtlsOverIceState::Disabled;
                self.acks_to_send.clear();
                return None;
            }
            self.state = DtlsOverIceState::RemoteSupportConfirmed;
        }

        if let Some(acks_attribute) = acks_attribute {
            if let Some(acks) = DtlsAckHash::decode_attribute(acks_attribute) {
                self.packets.retain(|held| !acks.contains(&held.hash));
            }
        }

        // Anything that is not a DTLS packet is dropped rather than handed to
        // the engine, which has no business parsing arbitrary bytes an
        // attribute happened to contain. An empty attribute fails this too.
        let dtls_packet = dtls_packet_attribute.filter(|attribute| is_dtls_packet(attribute));

        if let Some(dtls_packet) = dtls_packet {
            self.data_received_count += 1;
            self.handle_dtls_packet_received(dtls_packet);
        }

        if self.state == DtlsOverIceState::WaitingForAcks && self.packets.is_empty() {
            self.handle_completed();
        }

        dtls_packet.map(|dtls_packet| dtls_packet.to_vec())
    }

    /// Records that a DTLS packet was received, so it can be acknowledged.
    ///
    /// Called both for packets that arrived inside a connectivity check and for ones that
    /// arrived as ordinary datagrams, since either way the peer deserves an
    /// acknowledgement.
    pub fn handle_dtls_packet_received(&mut self, data: &[u8]) {
        if !self.state.is_active() {
            return;
        }
        let hash = DtlsAckHash::of_packet(data);
        if self.acks_to_send.contains(&hash) {
            return;
        }
        // Bounded, oldest first, so the attribute stays small enough to fit.
        while self.acks_to_send.len() >= MAX_DTLS_ACK_COUNT {
            self.acks_to_send.remove(0);
        }
        self.acks_to_send.push(hash);
    }

    pub fn handle_handshake_completed(&mut self) {
        if self.state != DtlsOverIceState::Disabled {
            self.state = DtlsOverIceState::WaitingForAcks;
        }
    }

    pub fn handle_received_after_handshake_completed(&mut self) {
        if self.state == DtlsOverIceState::WaitingForAcks {
            self.handle_completed();
        }
    }

    /// Both sides have everything: we are done sending and the peer has
    /// acknowledged all of it.
    fn handle_completed(&mut self) {
        self.state = DtlsOverIceState::Complete;
        self.packets.clear();
        self.acks_to_send.clear();
    }

    /// A packet to send as an ordinary DTLS packet, rather than over ICE.
    ///
    /// This took responsibility for the packets, so whenever an ordinary DTLS
    /// packet can be sent, that is the better way to get them there.
    pub fn poll_dtls_packet_to_send_not_over_ice(&mut self) -> Option<Vec<u8>> {
        if !self.state.is_active() {
            // Connectivity checks are no longer a way to reach the peer, so
            // everything still held goes out the ordinary way, including
            // anything a check carried before the extension was turned off.
            return self.packets.pop_front().map(|packet| packet.payload);
        }

        // A check has carried this one, so sending it here as well would
        // deliver it twice, and a duplicate handshake packet costs a round trip.
        let index = self
            .packets
            .iter()
            .position(|packet| packet.ice_send_count == 0)?;

        self.packets.remove(index).map(|packet| packet.payload)
    }
}

/// Whether a packet looks like DTLS.
///
/// This is a *classification*, not validation. RFC 7983 gives STUN 0-3, DTLS
/// 20-63 and SRTP 128-191, so a single byte separates the three protocols
/// sharing the socket.
fn is_dtls_packet(payload: &[u8]) -> bool {
    payload.len() >= DTLS_RECORD_HEADER_LEN
        && payload[0] >= DTLS_FIRST_BYTE_MIN
        && payload[0] <= DTLS_FIRST_BYTE_MAX
}

impl DtlsOverIceState {
    /// Whether the extension is still exchanging data.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            DtlsOverIceState::RemoteSupportUnknown
                | DtlsOverIceState::RemoteSupportConfirmed
                | DtlsOverIceState::WaitingForAcks
        )
    }
}

impl DtlsAckHash {
    /// The bytes one hash occupies in the acks attribute.
    const ENCODED_LEN: usize = 4;

    /// The hash of a DTLS packet.
    pub fn of_packet(packet: &[u8]) -> Self {
        DtlsAckHash(Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(packet))
    }

    /// Encodes acknowledgements into the attribute's wire format, replacing
    /// whatever `out` held.
    fn encode_attribute(acks: &[DtlsAckHash], out: &mut Vec<u8>) {
        out.clear();
        for ack in acks {
            out.extend_from_slice(&ack.0.to_be_bytes());
        }
    }

    /// Decodes acknowledgement hashes from the attribute's wire format.
    ///
    /// A length that is not a multiple of [`DtlsAckHash::ENCODED_LEN`] is
    /// refused rather than read as a partial value. An empty attribute decodes
    /// to an empty list, which is meaningful: it says the peer supports the
    /// extension but has nothing to acknowledge yet.
    fn decode_attribute(bytes: &[u8]) -> Option<Vec<DtlsAckHash>> {
        if bytes.len() % Self::ENCODED_LEN != 0 {
            return None;
        }
        Some(
            bytes
                .chunks_exact(Self::ENCODED_LEN)
                .map(|chunk| {
                    DtlsAckHash(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                })
                .collect(),
        )
    }
}

/// The bytes an attribute of `attribute_length` occupies on the wire,
/// including its header and padding to a four byte boundary.
fn attribute_size(attribute_length: usize) -> usize {
    /// A STUN attribute's type and length fields.
    const ATTRIBUTE_HEADER: usize = 4;
    ATTRIBUTE_HEADER + attribute_length + (4 - (attribute_length % 4)) % 4
}

/// Whether an attribute of `attribute_length` bytes still fits in a binding
/// message that is currently `message_length` bytes.
///
/// A connectivity check that grew past the path MTU would fragment, and a
/// fragmented check is worse than not carrying DTLS at all.
fn fits_in_ice_check(
    message_length: usize,
    attribute_length: usize,
    max_check_length: usize,
) -> bool {
    message_length + attribute_size(attribute_length) <= max_check_length
}

#[cfg(test)]
mod test {
    use super::*;

    /// A DTLS shaped packet with a distinguishing byte, so hashes differ.
    fn packet(tag: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 22; // handshake
        bytes[5] = tag;
        bytes[13] = 1;
        bytes
    }

    /// A DTLS shaped packet too big for any connectivity check to carry.
    fn oversized_packet() -> Vec<u8> {
        let mut bytes = packet(9);
        bytes.resize(MAX_ICE_CHECK_LENGTH, 0);
        bytes
    }

    /// Encodes with the same code the production path uses, so the round trip
    /// test exercises the real encoder.
    fn encode_acks(acks: &[DtlsAckHash]) -> Vec<u8> {
        let mut out = Vec::new();
        DtlsAckHash::encode_attribute(acks, &mut out);
        out
    }

    /// Hands over what the DTLS engine wanted to send.
    fn send_flight(pb: &mut DtlsOverIce, packets: &[Vec<u8>]) {
        pb.take_dtls_packets_to_send(packets.iter().cloned());
    }

    /// Everything waiting to go out as an ordinary datagram.
    fn datagrams(pb: &mut DtlsOverIce) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| pb.poll_dtls_packet_to_send_not_over_ice()).collect()
    }

    #[test]
    fn acks_round_trip() {
        let acks = vec![
            DtlsAckHash(1),
            DtlsAckHash(0x1122_3344),
            DtlsAckHash(0xFFFF_FFFF),
        ];
        assert_eq!(
            DtlsAckHash::decode_attribute(&encode_acks(&acks)),
            Some(acks)
        );
    }

    #[test]
    fn a_length_that_is_not_a_multiple_of_four_is_refused() {
        assert_eq!(DtlsAckHash::decode_attribute(b"abcde"), None);
        assert_eq!(DtlsAckHash::decode_attribute(&[0u8; 3]), None);
    }

    #[test]
    fn an_empty_ack_list_is_valid_and_meaningful() {
        // Its presence is what tells the peer we support the extension, even
        // with nothing yet to acknowledge.
        assert_eq!(DtlsAckHash::decode_attribute(&[]), Some(Vec::new()));
    }

    #[test]
    fn a_peer_that_echoes_nothing_turns_the_extension_off() {
        let mut pb = DtlsOverIce::new();
        assert_eq!(pb.state(), DtlsOverIceState::RemoteSupportUnknown);

        pb.handle_ice_check_received(None, None);
        assert_eq!(pb.state(), DtlsOverIceState::Disabled);
    }

    #[test]
    fn falling_back_sends_what_it_took_as_datagrams() {
        // These left the DTLS send queue, so this is the only place they still
        // exist. Dropping them would stall the handshake until DTLS
        // retransmitted, which not every DTLS implementation does.
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1), packet(2)]);

        // Only the first one goes out in a check.
        assert_eq!(pb.packets_to_send(0), Some(packet(1).as_slice()));

        pb.handle_ice_check_received(None, None);
        assert_eq!(pb.state(), DtlsOverIceState::Disabled);

        // Checks are no longer a way to reach the peer, so both go out the
        // ordinary way, in the order DTLS produced them. The one a check
        // already carried goes again: the peer ignored the attribute, so it
        // never saw it.
        assert_eq!(datagrams(&mut pb), vec![packet(1), packet(2)]);
    }

    #[test]
    fn nothing_is_sent_as_a_datagram_while_checks_still_carry_it() {
        // Sending it both ways would deliver it twice, and a duplicate
        // handshake packet costs the peer a round trip.
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1)]);
        assert_eq!(pb.packets_to_send(0), Some(packet(1).as_slice()));

        assert!(pb.state().is_active());
        assert_eq!(pb.poll_dtls_packet_to_send_not_over_ice(), None);
    }

    #[test]
    fn one_the_checks_have_not_carried_goes_out_as_a_datagram() {
        // Nothing has delivered it yet, so there is no duplicate to fear and no
        // reason to make it wait for a check.
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1), packet(2)]);
        assert_eq!(pb.packets_to_send(0), Some(packet(1).as_slice()));

        assert!(pb.state().is_active());
        assert_eq!(datagrams(&mut pb), vec![packet(2)]);
    }

    #[test]
    fn acknowledged_packets_are_not_sent_again() {
        // The peer already has these, so sending them as datagrams would be
        // pointless traffic.
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1), packet(2)]);
        assert_eq!(pb.packets_to_send(0), Some(packet(1).as_slice()));
        assert_eq!(pb.packets_to_send(0), Some(packet(2).as_slice()));

        pb.handle_ice_check_received(
            None,
            Some(&encode_acks(&[DtlsAckHash::of_packet(&packet(1))])),
        );

        // Only the unacknowledged one is still offered to the checks.
        assert_eq!(pb.packets_to_send(0), Some(packet(2).as_slice()));
    }

    #[test]
    fn an_empty_ack_alone_confirms_support() {
        // The attribute being present is the signal, not its contents.
        let mut pb = DtlsOverIce::new();
        pb.handle_ice_check_received(None, Some(&[]));
        assert_eq!(pb.state(), DtlsOverIceState::RemoteSupportConfirmed);
    }

    #[test]
    fn data_alone_confirms_support() {
        let mut pb = DtlsOverIce::new();
        pb.handle_ice_check_received(Some(&packet(1)), None);
        assert_eq!(pb.state(), DtlsOverIceState::RemoteSupportConfirmed);
    }

    #[test]
    fn nothing_is_offered_once_the_extension_is_off() {
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1)]);
        pb.handle_ice_check_received(None, None);

        assert_eq!(pb.packets_to_send(0), None);
        assert_eq!(pb.acks_to_send(), None);
    }

    #[test]
    fn a_handshake_runs_to_completion() {
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1)]);
        assert_eq!(pb.packets_to_send(0), Some(packet(1).as_slice()));

        pb.handle_ice_check_received(Some(&packet(2)), Some(&[]));
        assert_eq!(pb.state(), DtlsOverIceState::RemoteSupportConfirmed);

        pb.handle_handshake_completed();
        assert_eq!(pb.state(), DtlsOverIceState::WaitingForAcks);

        // The peer acknowledges what we sent.
        pb.handle_ice_check_received(
            None,
            Some(&encode_acks(&[DtlsAckHash::of_packet(&packet(1))])),
        );
        assert_eq!(pb.state(), DtlsOverIceState::Complete);
    }

    #[test]
    fn a_received_packet_is_returned_for_the_engine() {
        let mut pb = DtlsOverIce::new();
        assert_eq!(
            pb.handle_ice_check_received(Some(&packet(7)), None),
            Some(packet(7))
        );
        assert_eq!(pb.data_received_count, 1);
    }

    #[test]
    fn non_dtls_data_is_dropped() {
        let mut pb = DtlsOverIce::new();
        assert_eq!(
            pb.handle_ice_check_received(Some(b"not a dtls packet at all"), Some(&[])),
            None
        );
        assert_eq!(pb.data_received_count, 0);
        // The attribute was still present, so support is confirmed.
        assert_eq!(pb.state(), DtlsOverIceState::RemoteSupportConfirmed);
    }

    #[test]
    fn a_completed_handshake_after_fallback_stays_off() {
        let mut pb = DtlsOverIce::new();
        pb.handle_ice_check_received(None, None);
        assert_eq!(pb.state(), DtlsOverIceState::Disabled);

        pb.handle_handshake_completed();
        assert_eq!(pb.state(), DtlsOverIceState::Disabled);
    }

    #[test]
    fn a_received_packet_is_acknowledged() {
        let mut pb = DtlsOverIce::new();
        pb.handle_ice_check_received(Some(&packet(1)), None);
        assert_eq!(
            pb.acks_to_send(),
            Some(encode_acks(&[DtlsAckHash::of_packet(&packet(1))]).as_slice())
        );
    }

    #[test]
    fn a_packet_is_acknowledged_only_once() {
        // The same packet can arrive both inside a connectivity check and as a datagram.
        let mut pb = DtlsOverIce::new();
        pb.handle_dtls_packet_received(&packet(1));
        pb.handle_dtls_packet_received(&packet(1));
        pb.handle_ice_check_received(Some(&packet(1)), None);
        assert_eq!(pb.acks_to_send().map(|a| a.len()), Some(4));
    }

    #[test]
    fn the_acknowledgement_list_is_bounded() {
        let mut pb = DtlsOverIce::new();
        for tag in 0..10u8 {
            pb.handle_dtls_packet_received(&packet(tag));
        }
        let acks = DtlsAckHash::decode_attribute(pb.acks_to_send().expect("acks")).expect("decode");
        assert_eq!(acks.len(), MAX_DTLS_ACK_COUNT);
        // The newest survive; the oldest were dropped.
        assert!(acks.contains(&DtlsAckHash::of_packet(&packet(9))));
        assert!(!acks.contains(&DtlsAckHash::of_packet(&packet(0))));
    }

    #[test]
    fn an_ack_list_survives_a_check_that_carried_no_data() {
        // Checks can be reordered, and a peer may need two packets before it
        // can answer. Clearing the list would lose an acknowledgement the peer
        // still needs.
        let mut pb = DtlsOverIce::new();
        pb.handle_ice_check_received(Some(&packet(1)), None);
        assert_eq!(pb.acks_to_send().map(|a| a.len()), Some(4));

        pb.handle_ice_check_received(
            None,
            Some(&encode_acks(&[DtlsAckHash::of_packet(&packet(1))])),
        );
        assert_eq!(pb.acks_to_send().map(|a| a.len()), Some(4));
    }

    #[test]
    fn unacknowledged_packets_cycle_round_robin() {
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1), packet(2), packet(3)]);

        let mut seen = Vec::new();
        for _ in 0..7 {
            seen.push(pb.packets_to_send(0).expect("a packet")[5]);
        }
        assert_eq!(seen, vec![1, 2, 3, 1, 2, 3, 1]);
    }

    #[test]
    fn acknowledged_packets_are_not_resent() {
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1), packet(2)]);
        pb.handle_ice_check_received(
            None,
            Some(&encode_acks(&[DtlsAckHash::of_packet(&packet(1))])),
        );

        for _ in 0..4 {
            assert_eq!(pb.packets_to_send(0).expect("a packet")[5], 2);
        }
    }

    #[test]
    fn a_later_flight_is_added_to_the_earlier_one() {
        // Both are in the DTLS send queue until acknowledged, so both still
        // need to reach the peer.
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1), packet(2)]);
        send_flight(&mut pb, &[packet(1), packet(2), packet(3)]);

        let mut seen = Vec::new();
        for _ in 0..3 {
            seen.push(pb.packets_to_send(0).expect("a packet")[5]);
        }
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn a_non_dtls_packet_is_not_put_in_a_check() {
        // The peer would only drop it again. It still goes out as a datagram,
        // since the DTLS engine handed it over and no longer has it.
        let mut pb = DtlsOverIce::new();
        pb.take_dtls_packets_to_send([b"short".to_vec()]);

        assert_eq!(pb.packets_to_send(0), None);
        assert_eq!(
            pb.poll_dtls_packet_to_send_not_over_ice(),
            Some(b"short".to_vec())
        );
    }

    #[test]
    fn an_empty_queue_leaves_what_is_held_alone() {
        // Polling when the DTLS engine had nothing queued must not throw away
        // packets the peer has yet to acknowledge.
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1)]);
        send_flight(&mut pb, &[]);
        assert_eq!(pb.packets_to_send(0).expect("a packet")[5], 1);
    }

    #[test]
    fn nothing_is_offered_once_complete() {
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[packet(1)]);
        pb.handle_ice_check_received(Some(&packet(2)), Some(&[]));
        pb.handle_handshake_completed();
        pb.handle_ice_check_received(
            None,
            Some(&encode_acks(&[DtlsAckHash::of_packet(&packet(1))])),
        );
        assert_eq!(pb.state(), DtlsOverIceState::Complete);

        assert_eq!(pb.packets_to_send(0), None);
        assert_eq!(pb.acks_to_send(), None);
    }

    #[test]
    fn an_attribute_that_would_overflow_the_check_does_not_fit() {
        assert!(fits_in_ice_check(100, 100, MAX_ICE_CHECK_LENGTH));
        assert!(fits_in_ice_check(
            0,
            MAX_ICE_CHECK_LENGTH - 4,
            MAX_ICE_CHECK_LENGTH
        ));
        assert!(!fits_in_ice_check(
            0,
            MAX_ICE_CHECK_LENGTH - 3,
            MAX_ICE_CHECK_LENGTH
        ));
        assert!(!fits_in_ice_check(
            MAX_ICE_CHECK_LENGTH,
            4,
            MAX_ICE_CHECK_LENGTH
        ));
    }

    #[test]
    fn configured_ice_mtu_limits_attributes() {
        let mut pb = DtlsOverIce::new();
        let mut too_big = packet(1);
        too_big.resize(800, 0);
        send_flight(&mut pb, &[too_big]);

        let attributes = pb.attributes_to_send(120, 900).expect("acks fit");
        assert!(attributes.packet.is_none());
        assert!(attributes.acks.is_empty());
    }

    #[test]
    fn dtls_mtu_reserves_sped_overhead() {
        assert_eq!(dtls_mtu(1150), 1000);
        assert_eq!(dtls_mtu(DATAGRAM_MTU_TARGET_MIN), DATAGRAM_MTU_TARGET_MIN);
    }

    #[test]
    fn a_packet_too_big_for_a_check_is_sent_as_a_datagram() {
        // No check can ever carry this packet, and the DTLS engine has handed
        // it over, so if this does not send it the ordinary way then nobody
        // does. With a peer that supports the extension there is no fallback to
        // rescue it either, and the handshake would stall for good.
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[oversized_packet(), packet(1)]);

        pb.handle_ice_check_received(None, Some(&[]));
        assert_eq!(pb.state(), DtlsOverIceState::RemoteSupportConfirmed);

        // The one that fits rides along in checks, and so is not also sent as a
        // datagram. The oversized one has no other way out.
        assert_eq!(pb.packets_to_send(0), Some(packet(1).as_slice()));

        assert_eq!(
            datagrams(&mut pb),
            vec![oversized_packet()],
            "a packet that cannot ride in a check must be sent as a datagram"
        );
    }

    #[test]
    fn an_oversized_packet_does_not_block_the_others() {
        // It is skipped without being moved, so the smaller ones behind it keep
        // cycling.
        let mut pb = DtlsOverIce::new();
        send_flight(&mut pb, &[oversized_packet(), packet(1), packet(2)]);

        let mut seen = Vec::new();
        for _ in 0..4 {
            seen.push(pb.packets_to_send(0).expect("a packet")[5]);
        }
        assert_eq!(seen, vec![1, 2, 1, 2]);
    }
}
