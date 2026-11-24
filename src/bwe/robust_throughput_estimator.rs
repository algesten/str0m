//! Port of libWebRTC's RobustThroughputEstimator with its default settings.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::AckedPacket;
use crate::Bitrate;
use crate::rtp_::DataSize;

#[derive(Default)]
pub(super) struct RobustThroughputEstimator {
    window: VecDeque<AckedPacket>,
    latest_discarded_send_time: Option<Instant>,
    estimate: Option<Bitrate>,
}

impl RobustThroughputEstimator {
    pub(super) fn update(&mut self, packets: &[AckedPacket]) {
        if packets.is_empty() {
            return;
        }

        for packet in packets {
            self.insert_packet(*packet);
        }
        self.trim_window();
        self.estimate = self.estimate_window();
    }

    fn insert_packet(&mut self, packet: AckedPacket) {
        let receive_time = packet.remote_recv_time;
        let Some(last) = self.window.back() else {
            self.window.push_back(packet);
            return;
        };
        if receive_time >= last.remote_recv_time {
            self.window.push_back(packet);
            return;
        }

        const MAX_REORDERING: Duration = Duration::from_secs(1);
        let reordering = last.remote_recv_time - receive_time;
        if reordering > MAX_REORDERING {
            self.window.clear();
            self.latest_discarded_send_time = None;
            return;
        }

        let index = self
            .window
            .partition_point(|p| p.remote_recv_time <= receive_time);
        self.window.insert(index, packet);
    }

    fn trim_window(&mut self) {
        const MAX_WINDOW_PACKETS: usize = 500;
        const MAX_WINDOW_DURATION: Duration = Duration::from_secs(5);
        const WINDOW_PACKETS: usize = 20;
        const MIN_WINDOW_DURATION: Duration = Duration::from_secs(1);

        while let (Some(first), Some(last)) = (self.window.front(), self.window.back()) {
            let duration = last.remote_recv_time - first.remote_recv_time;
            let exceeds_hard_limit =
                self.window.len() > MAX_WINDOW_PACKETS || duration > MAX_WINDOW_DURATION;
            let exceeds_target_window =
                self.window.len() > WINDOW_PACKETS && duration > MIN_WINDOW_DURATION;
            if !(exceeds_hard_limit || exceeds_target_window) {
                break;
            }
            self.latest_discarded_send_time = self
                .latest_discarded_send_time
                .max(Some(first.local_send_time));
            self.window.pop_front();
        }
    }

    fn estimate_window(&self) -> Option<Bitrate> {
        const REQUIRED_PACKETS: usize = 10;

        if self.window.len() < REQUIRED_PACKETS {
            return None;
        }
        let first = self.window.front()?;
        let mut previous_receive = first.remote_recv_time;
        let mut largest_gap = Duration::ZERO;
        let mut second_gap = Duration::ZERO;
        let mut received = DataSize::ZERO;
        let mut sent = DataSize::ZERO;
        let mut send_count = 0;
        let mut first_send = None;
        let mut last_sent: Option<&AckedPacket> = None;

        for packet in &self.window {
            let gap = packet.remote_recv_time - previous_receive;
            previous_receive = packet.remote_recv_time;
            if gap > largest_gap {
                second_gap = largest_gap;
                largest_gap = gap;
            } else {
                second_gap = second_gap.max(gap);
            }
            received += packet.size;

            // Reordered packets older than an evicted send time distort the send span.
            if Some(packet.local_send_time) < self.latest_discarded_send_time {
                continue;
            }
            first_send = Some(first_send.map_or(packet.local_send_time, |t: Instant| {
                t.min(packet.local_send_time)
            }));
            let is_latest_send =
                last_sent.is_none_or(|p| packet.local_send_time > p.local_send_time);
            if is_latest_send {
                last_sent = Some(packet);
            }
            sent += packet.size;
            send_count += 1;
        }

        // Replace a single delay spike with the next largest gap. The receive
        // span excludes the first packet's serialization, the send span the last's.
        let receive_span = previous_receive - first.remote_recv_time - largest_gap + second_gap;
        let receive_rate = Self::rate(received - first.size, receive_span);
        if send_count < REQUIRED_PACKETS {
            return Some(receive_rate);
        }
        let last = last_sent?;
        let send_rate = Self::rate(sent - last.size, last.local_send_time - first_send?);
        Some(receive_rate.min(send_rate))
    }

    // libWebRTC divides integer microbits by microseconds, with a 1 ms minimum span.
    fn rate(size: DataSize, duration: Duration) -> Bitrate {
        let microbits = size.as_bytes_i64() as u64 * 8_000_000;
        let micros = (duration.as_micros() as u64).max(1000);
        Bitrate::bps(microbits / micros)
    }

    pub(super) fn current_estimate(&self) -> Option<Bitrate> {
        self.estimate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_estimate_and_rate_caps() {
        let start = Instant::now();
        for (send_ms, recv_ms, kbps) in [(10, 10, 800), (10, 40, 200), (20, 10, 400)] {
            let mut estimator = RobustThroughputEstimator::default();
            let batch = packets(start, 20, send_ms, recv_ms);
            estimator.update(&batch[..9]);
            assert_eq!(estimator.current_estimate(), None);
            estimator.update(&batch[9..10]);
            assert_eq!(estimator.current_estimate(), Some(Bitrate::kbps(kbps)));
            estimator.update(&batch[10..]);
            assert_eq!(estimator.current_estimate(), Some(Bitrate::kbps(kbps)));
        }
    }

    fn packets(start: Instant, count: u64, send_ms: u64, recv_ms: u64) -> Vec<AckedPacket> {
        (0..count)
            .map(|i| AckedPacket {
                seq_no: i.into(),
                size: DataSize::bytes(1000),
                local_send_time: start + Duration::from_millis(i * send_ms),
                remote_recv_time: start + Duration::from_millis((i + 1) * recv_ms),
                local_recv_time: start + Duration::from_secs(5),
            })
            .collect()
    }

    #[test]
    fn delay_spike_and_deep_reordering() {
        let start = Instant::now();
        let mut batch = packets(start, 200, 10, 10);
        let mut estimator = RobustThroughputEstimator::default();
        estimator.update(&batch[..20]);
        // Deliver 30 packets in 50 ms after a 250 ms pause.
        let last_receive = batch[19].remote_recv_time;
        for (i, packet) in batch[20..50].iter_mut().enumerate() {
            packet.remote_recv_time = last_receive
                + Duration::from_millis(250)
                + Duration::from_micros((i as u64 + 1) * 1666);
            estimator.update(std::slice::from_ref(packet));
            assert_eq!(estimator.current_estimate(), Some(Bitrate::kbps(800)));
        }
        estimator.update(&batch[50..]);

        let mut delayed = batch[0];
        delayed.remote_recv_time = batch[199].remote_recv_time;
        estimator.update(&[delayed]);
        assert_eq!(estimator.current_estimate(), Some(Bitrate::kbps(800)));
    }

    #[test]
    fn high_loss() {
        let received: Vec<_> = packets(Instant::now(), 20, 10, 10)
            .into_iter()
            .step_by(2)
            .collect();
        let mut estimator = RobustThroughputEstimator::default();
        estimator.update(&received);
        assert_eq!(estimator.current_estimate(), Some(Bitrate::kbps(400)));
    }

    #[test]
    fn reordered_feedback() {
        let batch = packets(Instant::now(), 40, 10, 10);
        let mut estimator = RobustThroughputEstimator::default();
        estimator.update(&batch[..20]);
        estimator.update(&batch[30..]);
        assert!(estimator.current_estimate().unwrap() < Bitrate::kbps(800));
        estimator.update(&batch[20..30]);
        assert_eq!(estimator.current_estimate(), Some(Bitrate::kbps(800)));
    }

    #[test]
    fn pause_and_receive_clock_reset() {
        let start = Instant::now();
        let mut estimator = RobustThroughputEstimator::default();
        estimator.update(&packets(start, 20, 10, 10));
        let resumed = packets(start + Duration::from_secs(60), 20, 10, 10);
        estimator.update(&resumed[..5]);
        assert_eq!(estimator.current_estimate(), None);
        estimator.update(&resumed[5..]);
        assert_eq!(estimator.current_estimate(), Some(Bitrate::kbps(800)));

        let mut reset = packets(start + Duration::from_secs(61), 20, 5, 5);
        for packet in &mut reset {
            packet.remote_recv_time -= Duration::from_secs(2);
        }
        estimator.update(&reset);
        assert_eq!(estimator.current_estimate(), Some(Bitrate::kbps(1600)));
    }
}
