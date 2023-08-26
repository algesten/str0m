//! Googcc Bandwidth Estimation based on TWCC feedback as described in
//! <https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02> and implemented in libWebRTC.
//!
//! Much of this code has been ported from the libWebRTC implementations. The complete system has
//! not been ported, only a smaller part that corresponds roughly to the IETF draft is implemented.

mod acked_bitrate_estimator;
mod arrival_group;
pub(crate) mod macros;
mod rate_control;
mod trendline_estimator;

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp_::{Bitrate, DataSize, SeqNo, TwccSendRecord};
use crate::util::already_happened;

use acked_bitrate_estimator::AckedBitrateEstimator;
use arrival_group::{ArrivalGroupAccumulator, InterGroupDelayDelta};
use rate_control::RateControl;
use trendline_estimator::TrendlineEstimator;

const MAX_RTT_HISTORY_WINDOW: usize = 32;
const INITIAL_BITRATE_WINDOW: Duration = Duration::from_millis(500);
const BITRATE_WINDOW: Duration = Duration::from_millis(150);
const UPDATE_INTERVAL: Duration = Duration::from_millis(25);
/// The maximum time we keep updating our estimate without receiving a TWCC report.
const MAX_TWCC_GAP: Duration = Duration::from_millis(500);

/// Main entry point for the Googcc inspired BWE implementation.
///
/// This takes as input packet statuses recorded at send time and enriched by TWCC reports and produces as its output a periodic
/// estimate of the available send bitrate.
pub struct SendSideBandwithEstimator {
    arrival_group_accumulator: ArrivalGroupAccumulator,
    trendline_estimator: TrendlineEstimator,
    rate_control: RateControl,
    acked_bitrate_estimator: AckedBitrateEstimator,
    /// Last estimate produced, unlike [`next_estimate`] this will always have a value after the
    /// first estimate.
    last_estimate: Option<Bitrate>,
    /// History of the max RTT derived for each TWCC report.
    max_rtt_history: VecDeque<Duration>,
    /// Calculated mean of max_rtt_history.
    mean_max_rtt: Option<Duration>,

    /// The next time we should poll.
    next_timeout: Instant,
    /// The last time we ingested a TWCC report.
    last_twcc_report: Instant,
}

impl SendSideBandwithEstimator {
    pub fn new(initial_bitrate: Bitrate) -> Self {
        Self {
            arrival_group_accumulator: ArrivalGroupAccumulator::default(),
            trendline_estimator: TrendlineEstimator::new(20),
            acked_bitrate_estimator: AckedBitrateEstimator::new(
                INITIAL_BITRATE_WINDOW,
                BITRATE_WINDOW,
            ),
            rate_control: RateControl::new(initial_bitrate, Bitrate::kbps(40), Bitrate::gbps(10)),
            last_estimate: None,
            max_rtt_history: VecDeque::default(),
            mean_max_rtt: None,
            next_timeout: already_happened(),
            last_twcc_report: already_happened(),
        }
    }

    /// Record a packet from a TWCC report.
    pub(crate) fn update<'t>(
        &mut self,
        records: impl Iterator<Item = &'t TwccSendRecord>,
        now: Instant,
    ) {
        let mut acked: Vec<AckedPacket> = Vec::new();

        let mut max_rtt = None;
        for record in records {
            let Ok(acked_packet) = record.try_into() else {
                continue;
            };
            acked.push(acked_packet);
            max_rtt = max_rtt.max(record.rtt());
        }
        acked.sort_by(AckedPacket::order_by_receive_time);

        for acked_packet in acked {
            self.acked_bitrate_estimator
                .update(acked_packet.remote_recv_time, acked_packet.size);

            if let Some(delay_variation) = self
                .arrival_group_accumulator
                .accumulate_packet(acked_packet)
            {
                crate::packet::bwe::macros::log_delay_variation!(delay_variation.delay_delta);

                // Got a new delay variation, add it to the trendline
                self.trendline_estimator
                    .add_delay_observation(delay_variation, now);
            }
        }

        if let Some(rtt) = max_rtt {
            self.add_max_rtt(rtt);
        }

        let new_hypothesis = self.trendline_estimator.hypothesis();

        self.update_estimate(
            new_hypothesis,
            self.acked_bitrate_estimator.current_estimate(),
            self.mean_max_rtt,
            now,
        );
        self.last_twcc_report = now;
    }

    pub(crate) fn poll_timeout(&self) -> Instant {
        self.next_timeout
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        if !self.trendline_hypothesis_valid(now) {
            // We haven't received a TWCC report in a while. The trendline hypothesis can
            // no longer be considered valid. We need another TWCC report before we can update
            // estimates.
            let next_timeout_in = self
                .mean_max_rtt
                .unwrap_or(MAX_TWCC_GAP)
                .min(UPDATE_INTERVAL);

            // Set this even if we didn't update, otherwise we get stuck in a poll -> handle loop
            // that starves the run loop.
            self.next_timeout = now + next_timeout_in;
            return;
        }

        self.update_estimate(
            self.trendline_estimator.hypothesis(),
            self.acked_bitrate_estimator.current_estimate(),
            self.mean_max_rtt,
            now,
        );
    }

    /// Get the latest estimate.
    pub(crate) fn last_estimate(&self) -> Option<Bitrate> {
        self.last_estimate
    }

    fn add_max_rtt(&mut self, max_rtt: Duration) {
        while self.max_rtt_history.len() > MAX_RTT_HISTORY_WINDOW {
            self.max_rtt_history.pop_front();
        }
        self.max_rtt_history.push_back(max_rtt);

        let sum = self
            .max_rtt_history
            .iter()
            .fold(Duration::ZERO, |acc, rtt| acc + *rtt);

        self.mean_max_rtt = Some(sum / self.max_rtt_history.len() as u32);
    }

    fn update_estimate(
        &mut self,
        hypothesis: BandwithUsage,
        observed_bitrate: Option<Bitrate>,
        mean_max_rtt: Option<Duration>,
        now: Instant,
    ) {
        if let Some(observed_bitrate) = observed_bitrate {
            self.rate_control
                .update(hypothesis.into(), observed_bitrate, mean_max_rtt, now);
            let estimated_rate = self.rate_control.estimated_bitrate();

            crate::packet::bwe::macros::log_bitrate_estimate!(estimated_rate.as_f64());
            self.last_estimate = Some(estimated_rate);
        }

        // Set this even if we didn't update, otherwise we get stuck in a poll -> handle loop
        // that starves the run loop.
        self.next_timeout = now + UPDATE_INTERVAL;
    }

    /// Whether the current trendline hypothesis is valid i.e. not too old.
    fn trendline_hypothesis_valid(&self, now: Instant) -> bool {
        now.duration_since(self.last_twcc_report)
            <= self
                .mean_max_rtt
                .map(|rtt| rtt * 2)
                .unwrap_or(MAX_TWCC_GAP)
                .min(UPDATE_INTERVAL * 2)
    }
}

/// A RTP packet that has been sent and acknowledged by the receiver in a TWCC report.
#[derive(Debug, Copy, Clone)]
pub struct AckedPacket {
    /// The TWCC sequence number
    seq_no: SeqNo,
    /// The size of the packets in bytes.
    size: DataSize,
    /// When we sent the packet
    local_send_time: Instant,
    /// When the packet was received at the remote, note this Instant is only usable with other
    /// instants of the same type i.e. those that represent a TWCC reported receive time for this
    /// session.
    remote_recv_time: Instant,
}

impl AckedPacket {
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

impl TryFrom<&TwccSendRecord> for AckedPacket {
    type Error = ();

    fn try_from(value: &TwccSendRecord) -> Result<Self, Self::Error> {
        let Some(remote_recv_time) = value.remote_recv_time() else {
            return Err(());
        };

        Ok(Self {
            seq_no: value.seq(),
            size: value.size().into(),
            local_send_time: value.local_send_time(),
            remote_recv_time,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BandwithUsage {
    Overuse,
    Normal,
    Underuse,
}

impl fmt::Display for BandwithUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BandwithUsage::Overuse => write!(f, "overuse"),
            BandwithUsage::Normal => write!(f, "normal"),
            BandwithUsage::Underuse => write!(f, "underuse"),
        }
    }
}
