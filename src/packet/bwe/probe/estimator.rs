use std::time::{Duration, Instant};

use crate::packet::bwe::ProbeClusterConfig;
use crate::rtp_::{Bitrate, DataSize, TwccClusterId, TwccSendRecord};
use crate::util::not_happening;

/// Minimum ratio of packets we need to receive for a valid probe (80%).
const MIN_RECEIVED_PROBES_RATIO: f64 = 0.80;

/// Minimum ratio of bytes we need to receive for a valid probe (80%).
const MIN_RECEIVED_BYTES_RATIO: f64 = 0.80;

/// Minimum packet count for a valid probe cluster (WebRTC's kMinClusterSize).
const MIN_CLUSTER_SIZE: usize = 4;

/// The maximum valid duration between first and last probe packet on send/receive side.
/// Matches WebRTC's `kMaxProbeInterval` in `probe_bitrate_estimator.cc`.
const MAX_PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// The maximum |receive rate| / |send rate| ratio for a valid estimate.
/// Matches WebRTC's `kMaxValidRatio`.
const MAX_VALID_RATIO: f64 = 2.0;

/// Minimum |receive rate| / |send rate| ratio to consider the link unsaturated.
/// Matches WebRTC's `kMinRatioForUnsaturatedLink`.
const MIN_RATIO_FOR_UNSATURATED_LINK: f64 = 0.9;

/// Target utilization when we believe we've found the true capacity.
/// Matches WebRTC's `kTargetUtilizationFraction`.
const TARGET_UTILIZATION_FRACTION: f64 = 0.95;

/// Analyzes probe cluster results from TWCC feedback.
///
/// This component takes packets tagged with a `TwccClusterId` and calculates the
/// achieved bitrate for each probe cluster.
///
/// **Important:** This follows WebRTC's `ProbeBitrateEstimator` semantics:
/// only packets with a known remote receive timestamp are included in the probe
/// result. Probe packets reported as lost (no remote receive timestamp) are ignored.
///
/// ## Bitrate Calculation
///
/// WebRTC computes:
/// - send_rate using `total_bytes - size_last_send` over `last_send - first_send`
/// - recv_rate using `total_bytes - size_first_receive` over `last_recv - first_recv`
/// and returns `min(send_rate, recv_rate)` with extra validation and a small
/// down-adjustment if the receive rate is significantly lower than the send rate.
///
/// ## Lifecycle:
/// 1. `probe_start(cluster_id)` - Pacer starts sending probe
/// 2. `update(records)` - Continuous TWCC feedback collection
/// 3. `end_probe(now)` - Pacer finishes, wait for remaining feedback
/// 4. `handle_timeout(now)` - Calculate final bitrate after hangover period
#[derive(Debug)]
pub(crate) struct ProbeEstimator {
    /// Configuration of the active probe (targets for validation).
    active_config: Option<ProbeClusterConfig>,

    /// When to finalize the probe and calculate bitrate.
    finalize_at: Instant,

    /// First (earliest) send time among packets included in this probe.
    first_send_time: Option<Instant>,
    /// Last (latest) send time among packets included in this probe.
    last_send_time: Option<Instant>,
    /// Size of the packet with the last send time (excluded from send-rate calculation).
    size_last_send: DataSize,

    /// First (earliest) receive time among packets included in this probe.
    first_recv_time: Option<Instant>,
    /// Last (latest) receive time among packets included in this probe.
    last_recv_time: Option<Instant>,
    /// Size of the packet with the first receive time (excluded from receive-rate calculation).
    size_first_receive: DataSize,

    /// Total bytes for packets included in this probe (received packets only).
    total_bytes: DataSize,
    /// Number of packets included in this probe (received packets only).
    packet_count: usize,
}

impl ProbeEstimator {
    pub fn new() -> Self {
        Self {
            active_config: None,
            finalize_at: not_happening(),
            first_send_time: None,
            last_send_time: None,
            size_last_send: DataSize::ZERO,
            first_recv_time: None,
            last_recv_time: None,
            size_first_receive: DataSize::ZERO,
            total_bytes: DataSize::ZERO,
            packet_count: 0,
        }
    }

    /// Start analyzing a new probe cluster.
    ///
    /// Resets all accumulated state and begins watching for packets with the
    /// given cluster ID.
    pub fn probe_start(&mut self, config: ProbeClusterConfig) {
        self.reset();
        self.active_config = Some(config);
    }

    /// Process TWCC feedback records.
    ///
    /// Only accumulates packets that match the active cluster ID. All other
    /// packets are ignored.
    pub fn update<'t>(&mut self, records: impl Iterator<Item = &'t TwccSendRecord>) {
        let Some(active_id) = self.cluster() else {
            return; // No active probe
        };

        for record in records {
            // Only process packets from our active cluster
            if record.cluster() != Some(active_id) {
                continue;
            }

            // IMPORTANT: Match WebRTC ProbeBitrateEstimator semantics:
            // Only packets with a known remote receive time participate in probe estimation.
            let Some(recv_time) = record.remote_recv_time() else {
                continue; // lost/unreceived packet -> ignore for probe result
            };

            let packet_size = DataSize::from(record.size());
            let send_time = record.local_send_time();

            // Track min/max send time among included packets.
            match self.first_send_time {
                None => self.first_send_time = Some(send_time),
                Some(prev) => self.first_send_time = Some(prev.min(send_time)),
            }

            match self.last_send_time {
                None => {
                    self.last_send_time = Some(send_time);
                    self.size_last_send = packet_size;
                }
                Some(prev) => {
                    if send_time > prev {
                        self.last_send_time = Some(send_time);
                        self.size_last_send = packet_size;
                    }
                }
            }

            // Track min/max receive time among included packets.
            match self.first_recv_time {
                None => {
                    self.first_recv_time = Some(recv_time);
                    self.size_first_receive = packet_size;
                }
                Some(prev) => {
                    if recv_time < prev {
                        self.first_recv_time = Some(recv_time);
                        self.size_first_receive = packet_size;
                    }
                }
            }
            match self.last_recv_time {
                None => self.last_recv_time = Some(recv_time),
                Some(prev) => self.last_recv_time = Some(prev.max(recv_time)),
            }

            self.total_bytes += packet_size;
            self.packet_count += 1;
        }
    }

    /// Mark the probe as ended.
    ///
    /// The probe will continue collecting feedback for some hangover
    /// duratin after the probe is finished. This duration must be
    /// shorter than the time between probe clusters.
    pub fn end_probe(&mut self, now: Instant) {
        if self.active_config.is_some() {
            self.finalize_at = now + Duration::from_secs(1);
        }
    }

    pub fn poll_timeout(&self) -> Instant {
        self.finalize_at
    }

    /// Finalize the probe and return the estimated bitrate.
    ///
    /// This calculates the achieved bitrate based on accumulated packets,
    /// validates the result, and resets all state.
    pub fn handle_timeout(&mut self, now: Instant) -> Option<Bitrate> {
        if now < self.finalize_at {
            return None;
        }

        let result = self.calculate_bitrate();
        self.reset();
        result
    }

    fn calculate_bitrate(&self) -> Option<Bitrate> {
        let config = self.active_config?;

        // WebRTC requires at least kMinClusterSize (4) packets
        if self.packet_count < MIN_CLUSTER_SIZE {
            return None;
        }

        // Also check we received enough of what was sent
        let min_packets = (config.min_packet_count() as f64 * MIN_RECEIVED_PROBES_RATIO) as usize;
        let min_bytes = DataSize::bytes(
            (config.target_bytes().as_bytes_usize() as f64 * MIN_RECEIVED_BYTES_RATIO) as u64,
        );

        if self.packet_count < min_packets {
            return None;
        }
        if self.total_bytes < min_bytes {
            return None;
        }

        // Get timing bounds
        let first_send = self.first_send_time?;
        let last_send = self.last_send_time?;
        let send_interval = last_send.saturating_duration_since(first_send);

        let first_recv = self.first_recv_time?;
        let last_recv = self.last_recv_time?;
        let recv_interval = last_recv.saturating_duration_since(first_recv);

        // Intervals must be positive and within bounds.
        if send_interval == Duration::ZERO || send_interval > MAX_PROBE_INTERVAL {
            return None;
        }
        if recv_interval == Duration::ZERO || recv_interval > MAX_PROBE_INTERVAL {
            return None;
        }

        // WebRTC boundary exclusions:
        // - exclude the last sent packet size when computing send rate
        // - exclude the first received packet size when computing receive rate
        let send_size = self.total_bytes.saturating_sub(self.size_last_send);
        let recv_size = self.total_bytes.saturating_sub(self.size_first_receive);
        if send_size <= DataSize::ZERO || recv_size <= DataSize::ZERO {
            return None;
        }

        let send_rate = send_size / send_interval;
        let recv_rate = recv_size / recv_interval;

        // Validate receive/send ratio.
        let ratio = recv_rate.as_f64() / send_rate.as_f64();
        if ratio > MAX_VALID_RATIO {
            return None;
        }

        let mut res = send_rate.min(recv_rate);

        // If receiving at significantly lower rate than sending, bias slightly lower to
        // avoid immediately overusing after the probe.
        if recv_rate.as_f64() < MIN_RATIO_FOR_UNSATURATED_LINK * send_rate.as_f64() {
            res = recv_rate * TARGET_UTILIZATION_FRACTION;
        }

        Some(res)
    }

    fn reset(&mut self) {
        self.active_config = None;
        self.finalize_at = not_happening();
        self.first_send_time = None;
        self.last_send_time = None;
        self.size_last_send = DataSize::ZERO;
        self.first_recv_time = None;
        self.last_recv_time = None;
        self.size_first_receive = DataSize::ZERO;
        self.total_bytes = DataSize::ZERO;
        self.packet_count = 0;
    }

    fn cluster(&self) -> Option<TwccClusterId> {
        self.active_config.map(|c| c.cluster())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::rtp_::{TwccPacketId, TwccSeq};

    #[test]
    fn probe_estimator_starts_with_no_active_probe() {
        let estimator = ProbeEstimator::new();
        assert_eq!(estimator.cluster(), None);
        assert_eq!(estimator.finalize_at, not_happening());
    }

    #[test]
    fn probe_estimator_resets_on_start() {
        let mut estimator = ProbeEstimator::new();

        // Manually set some state
        estimator.packet_count = 10;
        estimator.total_bytes = DataSize::bytes(1000);

        // Start new probe should reset
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(2));
        estimator.probe_start(config);

        assert_eq!(estimator.cluster(), Some(1.into()));
        assert_eq!(estimator.packet_count, 0);
        assert_eq!(estimator.total_bytes, DataSize::ZERO);
        assert_eq!(estimator.finalize_at, not_happening());
    }

    #[test]
    fn probe_estimator_lifecycle() {
        let mut estimator = ProbeEstimator::new();
        let now = Instant::now();

        // Start probe
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(2));
        estimator.probe_start(config);
        assert_eq!(estimator.poll_timeout(), not_happening());

        // End probe with 1 second hangover
        estimator.end_probe(now);
        assert_eq!(estimator.poll_timeout(), now + Duration::from_secs(1));

        // Handle timeout resets everything
        estimator.handle_timeout(now + Duration::from_secs(1));
        assert_eq!(estimator.cluster(), None);
        assert_eq!(estimator.poll_timeout(), not_happening());
    }

    #[test]
    fn lost_probe_packets_do_not_affect_estimate() {
        let mut estimator = ProbeEstimator::new();
        let cluster: TwccClusterId = 7.into();
        let config = ProbeClusterConfig::new(cluster, Bitrate::mbps(2));

        let base = Instant::now();
        let received = (0..5).map(|i| {
            let seq: TwccSeq = (1000 + i).into();
            let pid = TwccPacketId::with_cluster(seq, cluster);
            // send spaced 4ms, recv spaced 4ms (same ordering)
            crate::rtp_::TwccSendRecord::test_new(
                pid,
                base + Duration::from_millis(i as u64 * 4),
                1200,
                base + Duration::from_millis(i as u64 * 4 + 1),
                Some(base + Duration::from_millis(i as u64 * 4 + 2)),
            )
        });

        // Add extra lost probe packets with later send times. These should not change the result.
        let lost = (0..20).map(|i| {
            let seq: TwccSeq = (2000 + i).into();
            let pid = TwccPacketId::with_cluster(seq, cluster);
            crate::rtp_::TwccSendRecord::test_new(
                pid,
                base + Duration::from_millis(100 + i as u64),
                1200,
                base + Duration::from_millis(150 + i as u64),
                None, // lost
            )
        });

        // First run: only received packets
        estimator.probe_start(config);
        let recv_vec: Vec<_> = received.collect();
        estimator.update(recv_vec.iter());
        estimator.end_probe(base);
        let estimate_only_received = estimator
            .handle_timeout(base + Duration::from_secs(1))
            .expect("expected a probe estimate");

        // Second run: received + lost
        estimator.probe_start(config);
        let mut all_vec = recv_vec;
        all_vec.extend(lost);
        estimator.update(all_vec.iter());
        estimator.end_probe(base);
        let estimate_with_lost = estimator
            .handle_timeout(base + Duration::from_secs(1))
            .expect("expected a probe estimate");

        assert_eq!(
            estimate_only_received, estimate_with_lost,
            "lost packets must not change probe estimate"
        );
    }

    #[test]
    fn invalid_receive_send_ratio_is_rejected() {
        let mut estimator = ProbeEstimator::new();
        let cluster: TwccClusterId = 9.into();
        let config = ProbeClusterConfig::new(cluster, Bitrate::mbps(2));

        let base = Instant::now();
        // Make send times span 200ms, but receive times span only 1ms.
        // This yields receive_rate >> send_rate and should be rejected by ratio check.
        let records: Vec<_> = (0..5)
            .map(|i| {
                let seq: TwccSeq = (3000 + i).into();
                let pid = TwccPacketId::with_cluster(seq, cluster);
                crate::rtp_::TwccSendRecord::test_new(
                    pid,
                    base + Duration::from_millis(i as u64 * 50),
                    1200,
                    base + Duration::from_millis(250 + i as u64),
                    Some(base + Duration::from_millis(300 + (i as u64 % 2))), // ~0-1ms spread
                )
            })
            .collect();

        estimator.probe_start(config);
        estimator.update(records.iter());
        estimator.end_probe(base);
        let estimate = estimator.handle_timeout(base + Duration::from_secs(1));
        assert!(estimate.is_none(), "invalid ratio must be rejected");
    }
}
