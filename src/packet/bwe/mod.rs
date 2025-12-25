//! Googcc Bandwidth Estimation based on TWCC feedback as described in
//! <https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02> and implemented in libWebRTC.
//!
//! Much of this code has been ported from the libWebRTC implementations. The complete system has
//! not been ported, only a smaller part that corresponds roughly to the IETF draft is implemented.

use std::cmp::Ordering;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp_::{Bitrate, DataSize, TwccSendRecord, TwccSeq};

mod acked_bitrate_estimator;
mod arrival_group;
mod delay_controller;
mod loss_controller;
mod macros;
mod probe;
mod rate_control;
mod time;
mod trendline_estimator;

use acked_bitrate_estimator::AckedBitrateEstimator;
use arrival_group::InterGroupDelayDelta;
use delay_controller::DelayController;
use loss_controller::LossController;
use macros::log_loss;

pub(crate) use macros::{log_pacer_media_debt, log_pacer_padding_debt};
pub(crate) use probe::{ProbeClusterConfig, ProbeClusterState, ProbeControl, ProbeEstimator};

/// Ratio for treating the current estimate as "near desired".
///
/// Used by:
/// - `ProbeControl`: stop bursty probe clusters when close enough.
/// - `PacerControl`: allow a small, controlled padding "creep" in the same regime.
pub(crate) const NEAR_DESIRED_RATIO: f64 = 0.95;

const INITIAL_BITRATE_WINDOW: Duration = Duration::from_millis(500);
const BITRATE_WINDOW: Duration = Duration::from_millis(150);
const STARTUP_PAHSE: Duration = Duration::from_secs(2);

/// Main entry point for the Googcc inspired BWE implementation.
///
/// This takes as input packet statuses recorded at send time and enriched by TWCC reports
/// and produces as its output a periodic estimate of the available send bitrate.
pub struct SendSideBandwithEstimator {
    delay_controller: DelayController,
    loss_controller: Option<LossController>,
    acked_bitrate_estimator: AckedBitrateEstimator,
    probe_control: ProbeControl,
    probe_estimator: ProbeEstimator,
    /// Latest probe result waiting to be consumed by update()
    pending_probe_result: Option<Bitrate>,
    started_at: Option<Instant>,
}

impl SendSideBandwithEstimator {
    pub fn new(initial_bitrate: Bitrate, enable_loss_controller: bool) -> Self {
        Self {
            delay_controller: DelayController::new(initial_bitrate),
            loss_controller: enable_loss_controller
                .then(LossController::new)
                .map(|mut l| {
                    l.set_bandwidth_estimate(initial_bitrate);
                    l
                }),
            acked_bitrate_estimator: AckedBitrateEstimator::new(
                INITIAL_BITRATE_WINDOW,
                BITRATE_WINDOW,
            ),
            probe_control: ProbeControl::new(),
            probe_estimator: ProbeEstimator::new(),
            pending_probe_result: None,
            started_at: None,
        }
    }

    /// Get the actual measured send rate (based on acked packets)
    pub(crate) fn acked_bitrate(&self) -> Bitrate {
        self.acked_bitrate_estimator
            .current_estimate()
            .unwrap_or(Bitrate::ZERO)
    }

    /// Record a packet from a TWCC report.
    pub(crate) fn update<'t>(
        &mut self,
        records: impl Iterator<Item = &'t TwccSendRecord>,
        now: Instant,
    ) {
        let _ = self.started_at.get_or_insert(now);

        let send_records: Vec<_> = records.collect();

        // Feed records to probe estimator for analysis
        self.probe_estimator.update(send_records.iter().map(|r| *r));

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

        // Consume pending probe result if available
        let probe_result = self.pending_probe_result.take();

        let Some(delay_estimate) =
            self.delay_controller
                .update(&acked_packets, acked_bitrate, probe_result, now)
        else {
            return;
        };

        let Some(loss_controller) = &mut self.loss_controller else {
            return;
        };

        let loss = if count == 0 {
            0.0
        } else {
            lost as f64 / count as f64
        };
        log_loss!(loss);

        // In start up with no loss, let delay controller be in charge
        if in_startup_phase(self.started_at, now) && loss <= 0.001 {
            loss_controller.set_bandwidth_estimate(delay_estimate);
            return;
        }

        if let Some(acked_bitrate) = acked_bitrate {
            loss_controller.set_acknowledged_bitrate(acked_bitrate);
        }
        loss_controller.update_bandwidth_estimate(&send_records, delay_estimate);
    }

    pub(crate) fn poll_timeout(&self) -> Instant {
        let delay_timeout = self.delay_controller.poll_timeout();
        let probe_timeout = self.probe_control.poll_timeout();
        let probe_estimator_timeout = self.probe_estimator.poll_timeout();
        delay_timeout
            .min(probe_timeout)
            .min(probe_estimator_timeout)
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        self.delay_controller
            .handle_timeout(self.acked_bitrate_estimator.current_estimate(), now);

        // Check if probe estimation is ready.
        //
        // When a probe cluster completes, the ProbeEstimator calculates the achieved
        // bitrate. We store this result so it can be consumed by the next update()
        // call, where it's passed to the DelayController as an additional input signal.
        if let Some(probe_estimate) = self.probe_estimator.handle_timeout(now) {
            // Store the result to be consumed in the next update() call
            self.pending_probe_result = Some(probe_estimate);
        }
    }

    /// Get the latest estimate.
    pub(crate) fn last_estimate(&self) -> Option<Bitrate> {
        let delay_estimate = self.delay_controller.last_estimate();

        let Some(loss_estimate) = self
            .loss_controller
            .as_ref()
            .map(|l| l.get_loss_based_result().bandwidth_estimate)
        else {
            return delay_estimate;
        };

        match (delay_estimate, loss_estimate) {
            (Some(de), Some(le)) => Some(de.min(le)),
            (None, le @ Some(_)) => le,
            (de @ Some(_), None) => de,
            (None, None) => None,
        }
    }

    /// Check if we should initiate a probe cluster now.
    ///
    /// This should be called periodically (e.g., on each poll) to allow the ProbeControl
    /// to decide if it's time to probe for more bandwidth.
    ///
    /// Returns a configured probe cluster if one should be initiated, or None otherwise.
    pub(crate) fn maybe_create_probe(
        &mut self,
        desired_bitrate: Bitrate,
        now: Instant,
    ) -> Option<ProbeClusterConfig> {
        let current_estimate = self.last_estimate()?;
        self.probe_control
            .maybe_create_probe(current_estimate, desired_bitrate, now)
    }

    /// Start analyzing a probe cluster.
    ///
    /// This should be called when the pacer starts sending a probe cluster,
    /// to tell the estimator which cluster to watch for in TWCC feedback.
    pub(crate) fn start_probe(&mut self, config: ProbeClusterConfig) {
        self.probe_estimator.probe_start(config);
    }

    /// End a probe cluster and begin hangover period.
    ///
    /// This should be called when the pacer finishes sending a probe cluster.
    /// The estimator will continue collecting feedback some duration after to
    /// due to RTT of the packets in flight.
    pub(crate) fn end_probe(&mut self, now: Instant) {
        self.probe_estimator.end_probe(now);
    }

    pub(crate) fn reset(&mut self, init_bitrate: Bitrate) {
        *self = Self::new(init_bitrate, self.loss_controller.is_some());
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
