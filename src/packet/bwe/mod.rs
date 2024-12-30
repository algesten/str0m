//! Googcc Bandwidth Estimation based on TWCC feedback as described in
//! <https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02> and implemented in libWebRTC.
//!
//! Much of this code has been ported from the libWebRTC implementations. The complete system has
//! not been ported, only a smaller part that corresponds roughly to the IETF draft is implemented.

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Deref, RangeInclusive};
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
use macros::log_loss;

const INITIAL_BITRATE_WINDOW: Duration = Duration::from_millis(500);
const BITRATE_WINDOW: Duration = Duration::from_millis(150);
const STARTUP_PAHSE: Duration = Duration::from_secs(2);

/// Main entry point for the Googcc inspired BWE implementation.
///
/// This takes as input packet statuses recorded at send time and enriched by TWCC reports and produces as its output a periodic
/// estimate of the available send bitrate.
pub struct SendSideBandwithEstimator {
    delay_controller: DelayController,
    loss_controller: Option<LossController>,
    acked_bitrate_estimator: AckedBitrateEstimator,
    started_at: Option<Instant>,
    acked_packets_deduper: HandledPacketsTracker<64>,
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
            started_at: None,
            acked_packets_deduper: HandledPacketsTracker::default(),
        }
    }

    /// Record a packet from a TWCC report.
    pub(crate) fn update<'t>(
        &mut self,
        records: impl Iterator<Item = &'t TwccSendRecord>,
        now: Instant,
    ) {
        let _ = self.started_at.get_or_insert(now);

        let send_records: Vec<_> = records
            .filter(|r| {
                // Skip acked packets that have already been processed before.
                !self.acked_packets_deduper.contains(r.seq())
            })
            .collect();
        let mut acked_packets = Vec::with_capacity(send_records.len());

        let mut max_rtt = None;
        let mut count = 0;
        let mut lost = 0;
        for record in send_records.iter() {
            count += 1;
            let Ok(acked_packet) = AckedPacket::try_from(*record) else {
                lost += 1;
                continue;
            };
            acked_packets.push(acked_packet);
            self.acked_packets_deduper.add(acked_packet.seq_no);
            max_rtt = max_rtt.max(record.rtt());
        }
        acked_packets.sort_by(AckedPacket::order_by_receive_time);

        for acked_packet in acked_packets.iter() {
            self.acked_bitrate_estimator
                .update(acked_packet.remote_recv_time, acked_packet.size);
        }

        let acked_bitrate = self.acked_bitrate_estimator.current_estimate();
        let Some(delay_estimate) = self
            .delay_controller
            .update(&acked_packets, acked_bitrate, now)
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
        self.delay_controller.poll_timeout()
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        self.delay_controller
            .handle_timeout(self.acked_bitrate_estimator.current_estimate(), now);
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

    pub(crate) fn reset(&mut self, init_bitrate: Bitrate) {
        *self = Self::new(init_bitrate, self.loss_controller.is_some());
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

/// Sliding window [`SeqNo`]s tracker.
///
/// [`SIZE`] is the number of bytes in underling bitvector, so the actual window
/// size is [`SIZE`] * 8.
struct HandledPacketsTracker<const SIZE: usize> {
    /// Range of currently tracked [`SeqNo`]s.
    window: RangeInclusive<SeqNo>,

    /// Bit vector of recently added packets.
    history: [u8; SIZE],
}

impl<const SIZE: usize> HandledPacketsTracker<SIZE> {
    /// Tracked [`SeqNo`]s window size.
    const WINDOW_SIZE: usize = SIZE * 8;

    /// Remembers the give [`SeqNo`].
    ///
    /// Expects somewhat sequential data since window always advances to hold
    /// latest added value forgetting older ones.
    pub fn add(&mut self, seq: SeqNo) {
        self.maybe_advance_window(seq);

        let (byte_idx, bit_idx) = self.pos_of_seq(seq);
        self.history[byte_idx] |= 1 << bit_idx;
    }

    /// Checks if the provided [`SeqNo`] has been seen in the window.
    pub fn contains(&self, seq: SeqNo) -> bool {
        if self.window.contains(&seq) {
            let (byte_idx, bit_idx) = self.pos_of_seq(seq);
            (self.history[byte_idx] & (1 << bit_idx)) != 0
        } else {
            false
        }
    }

    /// Advances the window to include the given [`SeqNo`].
    fn maybe_advance_window(&mut self, new_max_seq: SeqNo) {
        if new_max_seq <= *self.window.end() {
            return;
        }
        // Clear newly included bits
        for i in **self.window.end() + 1..*new_max_seq {
            let (byte_idx, bit_idx) = self.pos_of_seq(&i);
            self.history[byte_idx] &= !(1 << bit_idx);
        }
        let new_start = new_max_seq.saturating_sub(Self::WINDOW_SIZE as u64);
        self.window = RangeInclusive::new(SeqNo::from(new_start), new_max_seq);
    }

    /// Maps a given sequence number to its position in the bit vector.
    fn pos_of_seq(&self, seq: impl Deref<Target = u64>) -> (usize, u8) {
        let byte_idx = (*seq / 8) as usize % self.history.len();
        let bit_idx = (*seq % 8) as u8;

        (byte_idx, bit_idx)
    }
}

impl<const SIZE: usize> Default for HandledPacketsTracker<SIZE> {
    fn default() -> Self {
        Self {
            window: RangeInclusive::new(SeqNo::from(0), SeqNo::from(Self::WINDOW_SIZE as u64)),
            history: [0; SIZE],
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::rtp_::{TwccRecvRegister, TwccSendRegister};

    use super::AckedPacket;

    #[test]
    fn libwebrtc_captured() {
        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 1, send_time_ms = 41013423
        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 2, send_time_ms = 41013443
        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 3, send_time_ms = 41013464
        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 4, send_time_ms = 41013484
        // (rtp_transport_controller_send.cc:652): RtpTransportControllerSend::OnTransportFeedback: new TWCC received: base_seq = 1, status_count = 4, feedback_seq = 0, received_packets = [1, 2, 4], receive_time = 41013500160
        // (acknowledged_bitrate_estimator.cc:69): AcknowledgedBitrateEstimator::IncomingPacketFeedbackVector: received_packets = [{ seq = 1, recv_time = 41013547, send_time = 41013423}, { seq = 2, recv_time = 41013568, send_time = 41013443}, { seq = 4, recv_time = 41013608, send_time = 41013484}]

        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 5, send_time_ms = 41013504
        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 6, send_time_ms = 41013524
        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 7, send_time_ms = 41013544
        // (rtp_transport_controller_send.cc:652): RtpTransportControllerSend::OnTransportFeedback: new TWCC received: base_seq = 3, status_count = 5, feedback_seq = 1, received_packets = [3, 4, 7], receive_time = 41013562660
        // (acknowledged_bitrate_estimator.cc:69): AcknowledgedBitrateEstimator::IncomingPacketFeedbackVector: received_packets = [{ seq = 3, recv_time = 41013638, send_time = 41013464}, { seq = 7, recv_time = 41013669, send_time = 41013544}]

        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 8, send_time_ms = 41013565
        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 9, send_time_ms = 41013585
        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 10, send_time_ms = 41013605
        // (transport_feedback_adapter.cc:115): ProcessSentPacket packet_id = 11, send_time_ms = 41013625
        // (rtp_transport_controller_send.cc:652): RtpTransportControllerSend::OnTransportFeedback: new TWCC received: base_seq = 5, status_count = 6, feedback_seq = 2, received_packets = [5, 6, 7, 8, 9, 10], receive_time = 41013639138
        // (acknowledged_bitrate_estimator.cc:69): AcknowledgedBitrateEstimator::IncomingPacketFeedbackVector: received_packets = [{ seq = 5, recv_time = 41013705, send_time = 41013504}, { seq = 9, recv_time = 41013716, send_time = 41013585}, { seq = 6, recv_time = 41013722, send_time = 41013524}, { seq = 8, recv_time = 41013729, send_time = 41013565}, { seq = 10, recv_time = 41013729, send_time = 41013605}]

        let now = Instant::now();
        let mut twcc_gen = TwccRecvRegister::new(1000);
        let mut twcc_handler = TwccSendRegister::new(1000);

        twcc_handler.register_seq(1.into(), now + Duration::from_millis(41013423), 0);
        twcc_handler.register_seq(2.into(), now + Duration::from_millis(41013443), 0);
        twcc_handler.register_seq(3.into(), now + Duration::from_millis(41013464), 0);
        twcc_handler.register_seq(4.into(), now + Duration::from_millis(41013484), 0);

        {
            let range = twcc_handler
                .apply_report(
                    {
                        twcc_gen.update_seq(1.into(), now + Duration::from_millis(41013423));
                        twcc_gen.update_seq(2.into(), now + Duration::from_millis(41013568));
                        twcc_gen.update_seq(4.into(), now + Duration::from_millis(41013608));
                        twcc_gen.build_report(10_000).unwrap()
                    },
                    now + Duration::from_micros(41013500160),
                )
                .unwrap();

            let mut acked_packets = twcc_handler
                .send_records(range)
                .unwrap()
                .filter_map(|r| AckedPacket::try_from(r).ok())
                .collect::<Vec<_>>();
            acked_packets.sort_by(AckedPacket::order_by_receive_time);
            let acked_packets: Vec<_> = acked_packets
                .into_iter()
                .map(|p| p.seq_no.as_u16())
                .collect();
            assert_eq!(acked_packets, [1, 2, 4]);
        }

        twcc_handler.register_seq(5.into(), now + Duration::from_millis(41013504), 0);
        twcc_handler.register_seq(6.into(), now + Duration::from_millis(41013524), 0);
        twcc_handler.register_seq(7.into(), now + Duration::from_millis(41013544), 0);

        {
            let range = twcc_handler
                .apply_report(
                    {
                        twcc_gen.update_seq(3.into(), now + Duration::from_millis(41013638));
                        twcc_gen.update_seq(7.into(), now + Duration::from_millis(41013669));
                        twcc_gen.build_report(10_000).unwrap()
                    },
                    now + Duration::from_micros(41013562660),
                )
                .unwrap();

            let mut acked_packets = twcc_handler
                .send_records(range)
                .unwrap()
                .filter_map(|r| AckedPacket::try_from(r).ok())
                .collect::<Vec<_>>();
            acked_packets.sort_by(AckedPacket::order_by_receive_time);
            let acked_packets: Vec<_> = acked_packets
                .into_iter()
                .map(|p| p.seq_no.as_u16())
                .collect();
            assert_eq!(acked_packets, [3, 7]);
        }
    }
}
