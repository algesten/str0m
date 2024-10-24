//! Googcc Bandwidth Estimation based on TWCC feedback as described in
//! <https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02> and implemented in libWebRTC.
//!
//! Much of this code has been ported from the libWebRTC implementations. The complete system has
//! not been ported, only a smaller part that corresponds roughly to the IETF draft is implemented.

use std::cmp::Ordering;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp_::{Bitrate, DataSize, SeqNo, TwccSendRecord};

mod acked_bitrate_estimator;
mod arrival_group;
mod delay_controller;
mod loss_controller;
pub(crate) mod macros;
mod rate_control;
mod super_instant;
mod trendline_estimator;

use acked_bitrate_estimator::AckedBitrateEstimator;
use arrival_group::InterGroupDelayDelta;
use delay_controller::DelayController;
use loss_controller::LossController;

const INITIAL_BITRATE_WINDOW: Duration = Duration::from_millis(500);
const BITRATE_WINDOW: Duration = Duration::from_millis(150);

/// Main entry point for the Googcc inspired BWE implementation.
///
/// This takes as input packet statuses recorded at send time and enriched by TWCC reports and produces as its output a periodic
/// estimate of the available send bitrate.
pub struct SendSideBandwithEstimator {
    delay_controller: DelayController,
    loss_controller: Option<LossController>,
    acked_bitrate_estimator: AckedBitrateEstimator,

    /// Scratch space for `update`, retains allocations between calls to avoid allocation churn.
    scratch: Scratch,
}

impl SendSideBandwithEstimator {
    pub fn new(initial_bitrate: Bitrate, enable_loss_controller: bool) -> Self {
        Self {
            delay_controller: DelayController::new(initial_bitrate),
            loss_controller: enable_loss_controller.then(LossController::new),
            acked_bitrate_estimator: AckedBitrateEstimator::new(
                INITIAL_BITRATE_WINDOW,
                BITRATE_WINDOW,
            ),
            scratch: Scratch::default(),
        }
    }

    /// Record a packet from a TWCC report.
    pub(crate) fn update<'t>(
        &mut self,
        records: impl Iterator<Item = &'t TwccSendRecord>,
        now: Instant,
    ) {
        let scratch = self.scratch.borrow();
        scratch.send_records.extend(records.copied());

        let mut max_rtt = None;
        for record in scratch.send_records.iter() {
            let Ok(acked_packet) = (&*record).try_into() else {
                continue;
            };
            scratch.acked_packets.push(acked_packet);
            max_rtt = max_rtt.max(record.rtt());
        }
        scratch
            .acked_packets
            .sort_by(AckedPacket::order_by_receive_time);

        for acked_packet in scratch.acked_packets.iter() {
            self.acked_bitrate_estimator
                .update(acked_packet.remote_recv_time, acked_packet.size);
        }

        let delay_estimate = self.delay_controller.update(
            &scratch.acked_packets,
            self.acked_bitrate_estimator.current_estimate(),
            now,
        );

        match (delay_estimate, &mut self.loss_controller) {
            (Some(e), Some(loss_controller)) => {
                loss_controller.update_bandwidth_estimate(scratch.send_records, e.bitrate, e.usage);
            }
            _ => {}
        }
    }

    pub(crate) fn poll_timeout(&self) -> Instant {
        self.delay_controller.poll_timeout()
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        self.delay_controller
            .handle_timeout(self.acked_bitrate_estimator.current_estimate(), now);
    }

    /// Get the latest estimate.
    pub(crate) fn last_estimate(&self) -> Option<Bitrate> {
        self.delay_controller.last_estimate()
    }

    pub(crate) fn reset(&mut self, init_bitrate: Bitrate) {
        *self = Self::new(init_bitrate, self.loss_controller.is_some());
    }
}

#[derive(Default)]
struct Scratch {
    /// Saved allocation for TwccSendRecord accumulation in `update`.
    send_records: Vec<TwccSendRecord>,
    /// Saved allocation for AckedPacket accumulation in `update`.
    acked_packets: Vec<AckedPacket>,
}

struct ScratchBorrow<'s> {
    /// Saved allocation for TwccSendRecord accumulation in `update`.
    send_records: &'s mut Vec<TwccSendRecord>,
    /// Saved allocation for AckedPacket accumulation in `update`.
    acked_packets: &'s mut Vec<AckedPacket>,
}

impl Scratch {
    fn borrow(&mut self) -> ScratchBorrow<'_> {
        assert!(self.send_records.is_empty());
        assert!(self.acked_packets.is_empty());

        ScratchBorrow {
            send_records: &mut self.send_records,
            acked_packets: &mut self.acked_packets,
        }
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

impl<'s> Drop for ScratchBorrow<'s> {
    fn drop(&mut self) {
        self.send_records.clear();
        self.acked_packets.clear();
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
