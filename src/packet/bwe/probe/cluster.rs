//! Probe cluster data structures for bandwidth estimation.
//!
//! Probe clusters are short bursts of packets sent at specific bitrates to test
//! network capacity. They replace continuous padding with targeted bandwidth probing.

use std::time::{Duration, Instant};

use crate::rtp_::{Bitrate, DataSize, TwccClusterId};

/// Configuration for a probe cluster (the plan).
///
/// This represents the immutable blueprint for a bandwidth probe: what bitrate
/// to test, for how long, and with what constraints.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProbeClusterConfig {
    /// Unique identifier for this probe cluster
    cluster: TwccClusterId,

    /// Target bitrate to probe at (e.g., 3 Mbps)
    target_bitrate: Bitrate,

    /// How long to sustain the target bitrate (e.g., 15ms)
    target_duration: Duration,

    /// Minimum number of packets to send (e.g., 5)
    /// This ensures statistical validity even for short bursts.
    min_packet_count: usize,
}

impl ProbeClusterConfig {
    /// Create a new probe cluster configuration with standard defaults:
    /// - 15ms duration (enough to get meaningful feedback without excessive delay)
    /// - 5 minimum packets (statistical significance for BWE analysis)
    pub fn new(cluster: TwccClusterId, target_bitrate: Bitrate) -> Self {
        Self {
            cluster,
            target_bitrate,
            // WebRTC defaults
            target_duration: Duration::from_millis(15),
            min_packet_count: 5,
        }
    }

    /// Set a custom target duration for this probe.
    /// WebRTC uses 100ms for initial probes to allow time for media to start.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.target_duration = duration;
        self
    }

    /// Get the probe cluster ID.
    pub fn cluster(&self) -> TwccClusterId {
        self.cluster
    }

    /// Get the target bitrate.
    pub fn target_bitrate(&self) -> Bitrate {
        self.target_bitrate
    }

    /// Get the minimum packet count required for a valid probe.
    pub fn min_packet_count(&self) -> usize {
        self.min_packet_count
    }

    /// Calculate the target bytes for this probe.
    /// This is how much data we expect to send at target_bitrate for target_duration.
    pub fn target_bytes(&self) -> DataSize {
        self.target_bitrate * self.target_duration
    }
}

/// Runtime state of an active probe cluster (the execution).
///
/// This tracks what's actually happening as we send probe packets: how much
/// we've sent, how many packets, and when we started.
#[derive(Debug)]
pub(crate) struct ProbeClusterState {
    /// The immutable plan
    config: ProbeClusterConfig,

    /// Total bytes sent so far in this probe
    bytes_sent: DataSize,

    /// Total packets sent so far in this probe
    packets_sent: usize,

    /// When the first packet was sent
    /// None = probe hasn't started yet (still queued)
    started_at: Option<Instant>,

    /// When the last packet was sent
    /// Used to calculate actual send duration (first to last packet)
    last_packet_at: Option<Instant>,
}

impl ProbeClusterState {
    /// Create a new probe cluster state from a config.
    pub fn new(config: ProbeClusterConfig) -> Self {
        Self {
            config,
            bytes_sent: DataSize::ZERO,
            packets_sent: 0,
            started_at: None,
            last_packet_at: None,
        }
    }

    /// Get the probe configuration.
    pub fn config(&self) -> &ProbeClusterConfig {
        &self.config
    }

    /// Check if the probe cluster is complete.
    ///
    /// A probe is complete when BOTH conditions are met:
    /// 1. Send duration (first to last packet) is at least `target_duration`
    /// 2. We've sent at least `min_packet_count` packets
    pub fn is_complete(&self, _now: Instant) -> bool {
        let Some(started) = self.started_at else {
            return false; // Not started yet
        };

        // Calculate send duration: time from first packet to last packet sent
        // This is what the validator checks, not elapsed time from start to now
        let send_duration = if let Some(last) = self.last_packet_at {
            last - started
        } else {
            Duration::ZERO // No packets sent yet
        };

        let duration_met = send_duration >= self.config.target_duration;
        let packets_met = self.packets_sent >= self.config.min_packet_count;

        duration_met && packets_met
    }

    /// Register a packet sent as part of this probe.
    ///
    /// This should be called each time a packet is sent for this probe cluster.
    pub fn register_packet(&mut self, size: DataSize, now: Instant) {
        // First packet? Mark start time
        if self.started_at.is_none() {
            self.started_at = Some(now);
        }

        // Always update last packet time
        self.last_packet_at = Some(now);

        self.bytes_sent += size;
        self.packets_sent += 1;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn probe_cluster_not_complete_before_start() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3));
        let state = ProbeClusterState::new(config);

        assert!(!state.is_complete(now));
    }

    #[test]
    fn probe_cluster_not_complete_after_duration_but_not_packets() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3));
        let mut state = ProbeClusterState::new(config);

        // Send only 2 packets (need 5)
        state.register_packet(DataSize::bytes(1200), now);
        state.register_packet(DataSize::bytes(1200), now + Duration::from_millis(5));

        // Check after duration has passed
        let later = now + Duration::from_millis(20);
        assert!(!state.is_complete(later)); // Duration met, but not packets
    }

    #[test]
    fn probe_cluster_not_complete_after_packets_but_not_duration() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3));
        let mut state = ProbeClusterState::new(config);

        // Send 5 packets instantly
        for i in 0..5 {
            state.register_packet(DataSize::bytes(1200), now + Duration::from_micros(i));
        }

        // Check immediately (duration not met)
        let slightly_later = now + Duration::from_millis(1);
        assert!(!state.is_complete(slightly_later)); // Packets met, but not duration
    }

    #[test]
    fn probe_cluster_complete_when_both_criteria_met() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3));
        let mut state = ProbeClusterState::new(config);

        // Send 5 packets over time
        for i in 0..5 {
            let packet_time = now + Duration::from_millis(i * 4);
            state.register_packet(DataSize::bytes(1200), packet_time);
        }

        // Check after both criteria met
        let later = now + Duration::from_millis(20);
        assert!(state.is_complete(later)); // Both duration and packets met
    }

    #[test]
    fn probe_cluster_tracks_bytes_and_packets() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3));
        let mut state = ProbeClusterState::new(config);

        state.register_packet(DataSize::bytes(1200), now);
        assert_eq!(state.bytes_sent, DataSize::bytes(1200));
        assert_eq!(state.packets_sent, 1);

        state.register_packet(DataSize::bytes(1000), now + Duration::from_millis(1));
        assert_eq!(state.bytes_sent, DataSize::bytes(2200));
        assert_eq!(state.packets_sent, 2);
    }
}
