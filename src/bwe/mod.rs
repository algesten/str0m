//! Google Congestion Control (GoogCC) Bandwidth Estimation based on TWCC feedback.
//!
//! This implementation is ported from libWebRTC's GoogCC and goes beyond the simplified
//! IETF draft (<https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02>) to include
//! WebRTC's production features:
//!
//! - Delay-based control (trendline estimator with AIMD rate control)
//! - Loss-based control (with inherent loss rate estimation)
//! - Probe controller with state machine and multi-stage probing strategy
//! - ALR (Application Limited Region) detection and periodic probing
//! - Link capacity estimation from ALR probes
//!
//! The probe controller in particular closely matches WebRTC's `ProbeController` behavior
//! and default constants, enabling compatible bandwidth discovery with WebRTC endpoints.

use std::cmp::Ordering;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp_::{Bitrate, DataSize, TwccClusterId, TwccSendRecord, TwccSeq};

mod acked_bitrate_estimator;
mod alr_detector;
pub(crate) mod api;
mod delay;
mod link_capacity_estimator;
mod loss_controller;
mod macros;
mod probe;
mod time;

use acked_bitrate_estimator::AckedBitrateEstimator;
use alr_detector::AlrDetector;
use delay::DelayController;
use link_capacity_estimator::LinkCapacityEstimator;
use loss_controller::{LossController, LossControllerState};
use macros::log_loss;

pub(crate) use macros::{log_pacer_media_debt, log_pacer_padding_debt};
pub(crate) use probe::{BandwidthLimitedCause, ProbeEstimator};
pub(crate) use probe::{ProbeClusterConfig, ProbeClusterState, ProbeControl};

const INITIAL_BITRATE_WINDOW: Duration = Duration::from_millis(500);
const BITRATE_WINDOW: Duration = Duration::from_millis(150);
const STARTUP_PAHSE: Duration = Duration::from_secs(2);

/// Amount of deviation needed to emit a new BWE value. This is to reduce
/// the total number BWE events to only fire when there is a substantial change.
const ESTIMATE_TOLERANCE: f64 = 0.05;

pub struct Bwe {
    bwe: SendSideBandwithEstimator,
    desired_bitrate: Bitrate,
    current_bitrate: Bitrate,
    last_emitted_estimate: Bitrate,
}

impl Bwe {
    pub fn new(initial: Bitrate) -> Self {
        let send_side_bwe = SendSideBandwithEstimator::new(initial);
        Bwe {
            bwe: send_side_bwe,
            desired_bitrate: Bitrate::ZERO,
            current_bitrate: initial,
            last_emitted_estimate: Bitrate::ZERO,
        }
    }

    pub fn handle_timeout(&mut self, now: Instant, do_probe: bool) -> Option<ProbeClusterConfig> {
        self.bwe.handle_timeout(self.desired_bitrate, do_probe, now)
    }

    pub fn start_probe(&mut self, config: ProbeClusterConfig) {
        self.bwe.start_probe(config);
    }

    pub fn end_probe(&mut self, now: Instant, cluster_id: TwccClusterId) {
        self.bwe.end_probe(now, cluster_id);
    }

    pub fn reset(&mut self, init_bitrate: Bitrate) {
        self.bwe.reset(init_bitrate);
    }

    pub fn update<'t>(
        &mut self,
        records: impl Iterator<Item = &'t crate::rtp_::TwccSendRecord>,
        now: Instant,
    ) {
        self.bwe.update(records, now);
    }

    pub fn poll_estimate(&mut self) -> Option<Bitrate> {
        let estimate = self.bwe.last_estimate()?;

        let min = self.last_emitted_estimate * (1.0 - ESTIMATE_TOLERANCE);
        let max = self.last_emitted_estimate * (1.0 + ESTIMATE_TOLERANCE);

        if estimate < min || estimate > max {
            self.last_emitted_estimate = estimate;
            Some(estimate)
        } else {
            // Estimate is within tolerances.
            None
        }
    }

    pub fn poll_timeout(&self) -> Instant {
        self.bwe.poll_timeout()
    }

    pub fn last_estimate(&self) -> Option<Bitrate> {
        self.bwe.last_estimate()
    }

    pub fn on_media_sent(&mut self, payload_size: DataSize, is_padding: bool, now: Instant) {
        if !is_padding {
            // Update ALR detector with media bytes sent
            self.bwe.on_media_sent(payload_size, now);
        }
    }

    pub fn is_overusing(&self) -> bool {
        self.bwe.is_overusing()
    }

    pub fn set_current_bitrate(&mut self, v: Bitrate) {
        self.current_bitrate = v;
    }

    pub fn current_bitrate(&self) -> Bitrate {
        self.current_bitrate
    }

    pub fn set_desired_bitrate(&mut self, v: Bitrate) {
        self.desired_bitrate = v;
    }
}

struct SendSideBandwithEstimator {
    delay_controller: DelayController,
    loss_controller: LossController,
    acked_bitrate_estimator: AckedBitrateEstimator,
    probe_control: ProbeControl,
    probe_estimator: ProbeEstimator,
    started_at: Option<Instant>,
    alr_detector: AlrDetector,
    link_capacity_estimator: LinkCapacityEstimator,
}

impl SendSideBandwithEstimator {
    pub fn new(initial_bitrate: Bitrate) -> Self {
        let mut alr_detector = AlrDetector::new();
        alr_detector.set_estimated_bitrate(initial_bitrate);

        let mut loss_controller = LossController::new();
        loss_controller.set_bandwidth_estimate(initial_bitrate);

        Self {
            delay_controller: DelayController::new(initial_bitrate),
            loss_controller,
            acked_bitrate_estimator: AckedBitrateEstimator::new(
                INITIAL_BITRATE_WINDOW,
                BITRATE_WINDOW,
            ),
            probe_control: ProbeControl::new(),
            probe_estimator: ProbeEstimator::new(),
            started_at: None,
            alr_detector,
            link_capacity_estimator: LinkCapacityEstimator::new(),
        }
    }

    /// Whether the delay-based detector currently signals overuse.
    ///
    /// This is useful for gating behaviors (like padding/probing) that would otherwise
    /// re-excite the system while we're already congested.
    pub fn is_overusing(&self) -> bool {
        self.delay_controller.is_overusing()
    }

    /// Update ALR detector with actual bytes sent.
    ///
    /// Should be called for media packets (not padding/probes).
    /// This is typically called from the session's packet sending logic.
    pub fn on_media_sent(&mut self, bytes: DataSize, now: Instant) {
        self.alr_detector.on_bytes_sent(bytes, now);
    }

    /// Record a packet from a TWCC report.
    pub fn update<'t>(&mut self, records: impl Iterator<Item = &'t TwccSendRecord>, now: Instant) {
        let _ = self.started_at.get_or_insert(now);

        let send_records: Vec<_> = records.collect();

        // Feed records to probe estimator for analysis and process any new probe results
        let mut latest_probe_result = None;
        for (config, bitrate) in self.probe_estimator.update(send_records.iter().copied()) {
            latest_probe_result = Some(bitrate);

            // Update link capacity estimator for every successful ALR probe, not just the latest.
            // The estimator internally takes the max of all probe results, building up knowledge
            // of proven link capacity. This differs from the delay controller, which only receives
            // the latest probe result (matching WebRTC's FetchAndResetLastEstimatedBitrate behavior).
            if config.is_alr_probe() {
                self.link_capacity_estimator.update_from_probe(bitrate, now);
            }
        }

        let mut acked_packets = vec![];

        let mut max_rtt = None;
        let mut count = 0;
        let mut lost = 0;
        for record in send_records.iter() {
            count += 1;
            let Ok(acked_packet) = (*record).try_into() else {
                lost += 1;
                continue;
            };
            acked_packets.push(acked_packet);
            max_rtt = max_rtt.max(record.rtt());
        }
        acked_packets.sort_by(AckedPacket::order_by_receive_time);

        for acked_packet in acked_packets.iter() {
            self.acked_bitrate_estimator
                .update(acked_packet.remote_recv_time, acked_packet.size);
        }

        let acked_bitrate = self.acked_bitrate_estimator.current_estimate();

        // Use the latest probe result from this update, if any
        let probe_result = latest_probe_result;

        let is_probe_result = probe_result.is_some();

        // Update delay controller with the latest probe result
        let maybe_estimate =
            self.delay_controller
                .update(&acked_packets, acked_bitrate, probe_result, now);

        let Some(delay_estimate) = maybe_estimate else {
            return;
        };

        let loss = if count == 0 {
            0.0
        } else {
            lost as f64 / count as f64
        };
        log_loss!(loss);

        // During startup with no loss, use delay-based estimate directly
        if in_startup_phase(self.started_at, now) && loss <= 0.001 {
            self.loss_controller.set_bandwidth_estimate(delay_estimate);
            return;
        }

        // When probe succeeds, set bandwidth directly
        if is_probe_result {
            self.loss_controller.set_bandwidth_estimate(delay_estimate);
        }

        if let Some(acked_bitrate) = acked_bitrate {
            self.loss_controller.set_acknowledged_bitrate(acked_bitrate);
        }

        // This corresponds to UpdateLossBasedEstimator + UpdateEstimate
        self.loss_controller
            .update_bandwidth_estimate(&send_records, delay_estimate);

        // Loss-based result is capped by delay_based_limit
        let loss_result = self.loss_controller.get_loss_based_result();
        if let Some(loss_estimate) = loss_result.bandwidth_estimate {
            if loss_estimate > delay_estimate {
                // Loss controller produced higher estimate than delay controller
                // Cap it at delay estimate (delay controller is the upper limit)
                self.loss_controller.set_bandwidth_estimate(delay_estimate);
            }
        }

        // Feed the (possibly combined) estimate into the probe controller, matching WebRTC's
        // `SetEstimatedBitrate` entrypoint.
        if let Some(estimate) = self.last_estimate() {
            let cause = self.bandwidth_limited_cause();
            self.probe_control
                .set_estimated_bitrate(estimate, cause, now);
        }
    }

    pub fn poll_timeout(&self) -> Instant {
        let delay_timeout = self.delay_controller.poll_timeout();
        let probe_timeout = self.probe_control.poll_timeout();
        let probe_estimator_timeout = self.probe_estimator.poll_timeout();
        delay_timeout
            .min(probe_timeout)
            .min(probe_estimator_timeout)
    }

    /// Handle periodic timeout for BWE components.
    pub fn handle_timeout(
        &mut self,
        desired_bitrate: Bitrate,
        do_probe: bool,
        now: Instant,
    ) -> Option<ProbeClusterConfig> {
        self.delay_controller
            .handle_timeout(self.acked_bitrate_estimator.current_estimate(), now);

        // Update probe control with desired bitrate.
        self.probe_control.set_max_bitrate(desired_bitrate);

        // Get ALR state and forward to both probe control and loss controller
        let alr_start_time = self.alr_detector.alr_start_time();
        self.probe_control.set_alr_start_time(alr_start_time, now);

        self.loss_controller.set_alr_start_time(alr_start_time);

        // Get link capacity estimate and forward to loss controller.
        let link_capacity = self.link_capacity_estimator.get_capacity_estimate(now);
        self.loss_controller
            .set_link_capacity_estimate(link_capacity);

        // Clean up expired probe cluster state
        self.probe_estimator.handle_timeout(now);

        // Feed the current estimate into the probe controller (also updates large-drop tracking
        // and "probe further" logic).
        if let Some(estimate) = self.last_estimate() {
            let cause = self.bandwidth_limited_cause();
            self.probe_control
                .set_estimated_bitrate(estimate, cause, now);
        }

        // str0m trigger: probing becomes active once we have started sending media.
        if do_probe {
            if let Some(estimate) = self.last_estimate() {
                self.probe_control.on_bwe_active(estimate);
            }
        }

        // Timer-driven probe logic (WebRTC `Process()` equivalent).
        self.probe_control.handle_timeout(now);

        // Check if we should initiate a probe cluster now.
        // The first probe isn't sent until we started sending RTP media.
        if do_probe {
            self.maybe_create_probe()
        } else {
            None
        }
    }

    fn bandwidth_limited_cause(&self) -> BandwidthLimitedCause {
        if self.delay_controller.is_overusing() {
            return BandwidthLimitedCause::DelayBasedLimitedDelayIncreased;
        }

        match self.loss_controller.get_loss_based_result().state {
            LossControllerState::DelayBased => BandwidthLimitedCause::DelayBasedLimited,
            LossControllerState::Increasing => BandwidthLimitedCause::LossLimitedBweIncreasing,
            LossControllerState::Decreasing => BandwidthLimitedCause::LossLimitedBwe,
        }
    }

    /// Get the latest estimate.
    pub fn last_estimate(&self) -> Option<Bitrate> {
        let delay_estimate = self.delay_controller.last_estimate();

        let loss_result = self.loss_controller.get_loss_based_result();

        // Only apply loss-based limiting when actively in a loss-limiting state
        match loss_result.state {
            LossControllerState::DelayBased => {
                // Loss controller defers to delay-based estimate
                delay_estimate
            }
            LossControllerState::Decreasing | LossControllerState::Increasing => {
                // Loss controller is actively limiting or recovering
                match (delay_estimate, loss_result.bandwidth_estimate) {
                    (Some(de), Some(le)) => Some(de.min(le)),
                    (None, le @ Some(_)) => le,
                    (de @ Some(_), None) => de,
                    (None, None) => None,
                }
            }
        }
    }

    /// Check if we should initiate a probe cluster now.
    ///
    /// This should be called periodically (e.g., on each poll) to allow the ProbeControl
    /// to decide if it's time to probe for more bandwidth.
    ///
    /// Returns a configured probe cluster if one should be initiated, or None otherwise.
    pub fn maybe_create_probe(&mut self) -> Option<ProbeClusterConfig> {
        let estimate = self.last_estimate()?;

        // Update ALR detector with current estimate
        self.alr_detector.set_estimated_bitrate(estimate);

        self.probe_control.maybe_create_probe()
    }

    /// Start analyzing a probe cluster.
    ///
    /// This should be called when the pacer starts sending a probe cluster,
    /// to tell the estimator which cluster to watch for in TWCC feedback.
    pub fn start_probe(&mut self, config: ProbeClusterConfig) {
        self.probe_estimator.probe_start(config);
    }

    /// End a probe cluster and mark it for cleanup.
    ///
    /// This should be called when the pacer finishes sending a probe cluster.
    /// The estimator will continue collecting feedback for a cluster history period
    /// to allow late-arriving TWCC reports to refine the estimate.
    pub fn end_probe(&mut self, now: Instant, cluster_id: TwccClusterId) {
        self.probe_estimator.end_probe(now, cluster_id);
    }

    pub fn reset(&mut self, init_bitrate: Bitrate) {
        *self = Self::new(init_bitrate);
    }
}

/// A RTP packet that has been sent and acknowledged by the receiver in a TWCC report.
#[derive(Debug, Copy, Clone)]
pub struct AckedPacket {
    /// The TWCC sequence number
    seq_no: TwccSeq,
    /// The size of the packets in bytes.
    size: DataSize,
    /// When we sent the packet
    local_send_time: Instant,
    /// When the packet was received at the remote, note this Instant is only usable with other
    /// instants of the same type i.e. those that represent a TWCC reported receive time for this
    /// session.
    remote_recv_time: Instant,
    /// The local time when received confirmation that the other side received the seq i.e. when we
    /// received the TWCC report for this packet.
    local_recv_time: Instant,
}

impl AckedPacket {
    fn rtt(&self) -> Duration {
        self.local_recv_time - self.local_send_time
    }

    fn order_by_receive_time(lhs: &Self, rhs: &Self) -> Ordering {
        if lhs.remote_recv_time != rhs.remote_recv_time {
            lhs.remote_recv_time.cmp(&rhs.remote_recv_time)
        } else if lhs.local_send_time != rhs.local_send_time {
            lhs.local_send_time.cmp(&rhs.local_send_time)
        } else {
            lhs.seq_no.cmp(&rhs.seq_no)
        }
    }
}

// NB: Extracted for lifetime reasons
fn in_startup_phase(started_at: Option<Instant>, now: Instant) -> bool {
    started_at
        .map(|s| now.duration_since(s) <= STARTUP_PAHSE)
        .unwrap_or(false)
}

impl TryFrom<&TwccSendRecord> for AckedPacket {
    type Error = ();

    fn try_from(value: &TwccSendRecord) -> Result<Self, Self::Error> {
        let Some(remote_recv_time) = value.remote_recv_time() else {
            return Err(());
        };
        let Some(local_recv_time) = value.local_recv_time() else {
            return Err(());
        };

        Ok(Self {
            seq_no: value.seq(),
            size: value.size().into(),
            local_send_time: value.local_send_time(),
            remote_recv_time,
            local_recv_time,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BandwidthUsage {
    Overuse,
    Normal,
    Underuse,
}

impl fmt::Display for BandwidthUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BandwidthUsage::Overuse => write!(f, "overuse"),
            BandwidthUsage::Normal => write!(f, "normal"),
            BandwidthUsage::Underuse => write!(f, "underuse"),
        }
    }
}
