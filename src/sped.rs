//! Bounded SPED state. ICE authenticates the envelope; DTLS authenticates the peer.
use std::collections::VecDeque;
use std::time::Instant;

use crc::{CRC_32_ISO_HDLC, Crc};

use crate::SendAddr;

const MAX_FLIGHT_PACKETS: usize = 8;
const MAX_ACKS: usize = 4;
const MAX_EARLY_PACKETS: usize = 4;
const MAX_PACKET_BYTES: usize = 1500;

/// Duration-free transport diagnostics; no credentials or peer addresses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpedStats {
    /// The `sped` ICE option was present in both SDP descriptions.
    pub negotiated: bool,
    /// DTLS packets actually embedded in outgoing authenticated ICE checks.
    pub embedded_sent: u64,
    /// Embedded DTLS packets received in authenticated ICE checks.
    pub embedded_received: u64,
    /// Why embedding was stopped before authentication completed.
    pub fallback: Option<SpedFallback>,
}

/// SPED is optional. These conditions leave normal ICE/DTLS available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpedFallback {
    /// The SDP answer did not accept SPED.
    Unsupported,
    /// ICE selected a different path from the one used for early DTLS.
    PathChanged,
    /// A selected pair is available; no embedded response was received.
    NoEmbeddedResponse,
    /// The early DTLS backend rejected a packet or timed out.
    EarlyDtlsFailed,
    /// A bounded flight or embedding budget was exhausted.
    BudgetExhausted,
}

pub(crate) struct EarlyPacket {
    pub path: SendAddr,
    pub ufrag: String,
    pub data: Vec<u8>,
    pub at: Instant,
}

pub(crate) struct Sped {
    pub enabled: bool,
    pub offered: bool,
    pub stats: SpedStats,
    pub early: VecDeque<EarlyPacket>,
    path: Option<SendAddr>,
    selected: bool,
    pending: VecDeque<Vec<u8>>,
    acknowledgements: VecDeque<u32>,
    new_flight: bool,
    generation: u64,
    complete: bool,
}

impl Sped {
    pub fn cancel(&mut self) {
        self.pending.clear();
        self.acknowledgements.clear();
        self.early.clear();
        self.selected = true;
    }
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            offered: false,
            stats: SpedStats::default(),
            early: VecDeque::new(),
            path: None,
            selected: false,
            pending: VecDeque::new(),
            acknowledgements: VecDeque::new(),
            new_flight: true,
            generation: 0,
            complete: false,
        }
    }

    pub fn negotiate(&mut self, remote: bool) {
        self.stats.negotiated = self.enabled && remote;
        if self.enabled && !remote {
            self.stop(SpedFallback::Unsupported);
        }
    }

    pub fn stop(&mut self, reason: SpedFallback) {
        self.pending.clear();
        self.early.clear();
        self.stats.fallback.get_or_insert(reason);
    }

    pub fn restart(&mut self) {
        let enabled = self.enabled;
        *self = Self::new(enabled);
    }

    pub fn finish(&mut self) {
        if !self.complete {
            self.pending.clear();
            self.acknowledgements.clear();
            self.complete = true;
        }
    }

    pub fn select(&mut self, path: SendAddr) {
        if self.path.as_ref().is_some_and(|early| early != &path) {
            self.stop(SpedFallback::PathChanged);
        } else if self.stats.embedded_sent > 0 && self.stats.embedded_received == 0 {
            self.stop(SpedFallback::NoEmbeddedResponse);
        }
        // Direct DTLS must never wait for the next ICE check after selection.
        self.selected = true;
        self.pending.clear();
    }

    pub fn received(&mut self, path: &SendAddr, data: &[u8], embedded: bool) {
        if self.path.as_ref().is_some_and(|early| early != path) {
            self.stop(SpedFallback::PathChanged);
        }
        self.path.get_or_insert_with(|| path.clone());
        self.new_flight = true;
        if embedded {
            self.stats.embedded_received += 1;
        }
        let crc = checksum(data);
        if !self.acknowledgements.contains(&crc) {
            if self.acknowledgements.len() == MAX_ACKS {
                self.acknowledgements.pop_front();
            }
            self.acknowledgements.push_back(crc);
        }
    }

    pub fn acknowledge(&mut self, data: &[u8]) {
        for ack in data.as_chunks::<4>().0.iter().take(MAX_ACKS) {
            let crc = u32::from_be_bytes(*ack);
            self.pending.retain(|packet| checksum(packet) != crc);
        }
    }

    pub fn capture(&mut self, generation: u64, packet: &[u8]) {
        if generation == self.generation {
            return;
        }
        self.generation = generation;
        if !self.stats.negotiated || self.selected || self.complete || self.stats.fallback.is_some()
        {
            return;
        }
        if self.new_flight {
            self.pending.clear();
            self.new_flight = false;
        }
        if self.pending.iter().any(|old| old == packet) {
            return;
        }
        if self.pending.len() == MAX_FLIGHT_PACKETS || packet.len() > MAX_PACKET_BYTES {
            self.stop(SpedFallback::BudgetExhausted);
            return;
        }
        self.pending.push_back(packet.to_vec());
    }

    pub fn outgoing(&mut self, path: &SendAddr) -> (Option<Vec<u8>>, Vec<u8>) {
        if !self.stats.negotiated {
            return (None, vec![]);
        }
        let ack = self
            .acknowledgements
            .iter()
            .flat_map(|crc| crc.to_be_bytes())
            .collect();
        if self.complete {
            self.acknowledgements.clear();
            return (None, ack);
        }
        if self.selected || self.stats.fallback.is_some() {
            return (None, ack);
        }
        if self.path.as_ref().is_some_and(|early| early != path) {
            return (None, ack);
        }
        self.path.get_or_insert_with(|| path.clone());
        if self.stats.embedded_sent >= MAX_FLIGHT_PACKETS as u64 {
            self.stop(SpedFallback::BudgetExhausted);
            return (None, ack);
        }
        let packet = self.pending.pop_front();
        if let Some(packet) = &packet {
            self.pending.push_back(packet.clone());
        }
        (packet, ack)
    }

    pub fn buffer_early(&mut self, packet: EarlyPacket) {
        if self.offered
            && self.early.len() < MAX_EARLY_PACKETS
            && packet.data.len() <= MAX_PACKET_BYTES
        {
            self.early.push_back(packet);
        }
    }
}

fn checksum(data: &[u8]) -> u32 {
    Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(data)
}
