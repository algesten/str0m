use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arrayvec::ArrayVec;

use super::{ExtensionValues, Frequency, MediaTime, Pt, Rid, TelephoneEventPayload, ToPayload};

const END_PACKET_REPEATS: usize = 3;
const PACKET_INTERVAL: Duration = Duration::from_millis(20);
const MIN_TONE_GAP: Duration = Duration::from_millis(70);
const NANOS_PER_SECOND: u128 = 1_000_000_000;

fn samples_from_duration(duration: Duration, clock_rate: Frequency) -> u64 {
    ((duration.as_nanos() * clock_rate.get() as u128) / NANOS_PER_SECOND).min(u64::MAX as u128)
        as u64
}

fn duration_from_samples(samples: u64, clock_rate: Frequency) -> Duration {
    let nanos = (samples as u128 * NANOS_PER_SECOND).div_ceil(clock_rate.get() as u128);
    Duration::new(
        (nanos / NANOS_PER_SECOND) as u64,
        (nanos % NANOS_PER_SECOND) as u32,
    )
}

#[derive(Debug)]
pub(super) struct DtmfTone {
    pub pt: Pt,
    pub rid: Option<Rid>,
    pub rtp_time: MediaTime,
    pub wallclock: Instant,
    pub event: u8,
    pub volume: u8,
    pub duration: Duration,
    pub clock_rate: Frequency,
    pub ext_vals: ExtensionValues,
}

#[derive(Debug)]
struct QueuedTone {
    pt: Pt,
    rid: Option<Rid>,
    event: u8,
    volume: u8,
    total_samples: u64,
    rtp_time: MediaTime,
    start: Instant,
    clock_rate: Frequency,
    ext_vals: ExtensionValues,
}

impl QueuedTone {
    fn end_at(&self) -> Option<Instant> {
        self.start
            .checked_add(duration_from_samples(self.total_samples, self.clock_rate))
    }

    fn end_rtp_time(&self) -> MediaTime {
        self.rtp_time + MediaTime::new(self.total_samples, self.clock_rate)
    }

    fn first_report_at(&self, not_before: Option<Instant>) -> Instant {
        let step = samples_from_duration(PACKET_INTERVAL, self.clock_rate).max(1);
        let start = not_before.map_or(self.start, |time| self.start.max(time));
        start + duration_from_samples(step.min(self.total_samples), self.clock_rate)
    }

    fn delay_until(&mut self, not_before: Option<Instant>) {
        if let Some(time) = not_before {
            if time > self.start {
                let delay = samples_from_duration(time - self.start, self.clock_rate);
                self.rtp_time += MediaTime::new(delay, self.clock_rate);
                self.start = time;
            }
        }
    }
}

#[derive(Debug)]
struct ActiveTone {
    tone: QueuedTone,
    first: bool,
    segment_start: u64,
    next_at: Instant,
}

#[derive(Debug, Default)]
pub(super) struct DtmfSender {
    queue: VecDeque<QueuedTone>,
    active: Option<ActiveTone>,
    next_tone_at: Option<Instant>,
}

impl DtmfSender {
    pub fn push(&mut self, tone: DtmfTone) {
        let DtmfTone {
            pt,
            rid,
            rtp_time,
            wallclock,
            event,
            volume,
            duration,
            clock_rate,
            ext_vals,
        } = tone;
        let mut rtp_time = rtp_time.rebase(clock_rate);
        let total_samples = samples_from_duration(duration, clock_rate).max(1);
        let mut start = wallclock;
        let previous = self
            .queue
            .back()
            .or_else(|| self.active.as_ref().map(|active| &active.tone));
        if let Some(previous) = previous {
            if let Some(previous_end) = previous.end_at() {
                // Preserve larger caller-supplied gaps and separate repeated digits.
                start = start.max(previous_end + MIN_TONE_GAP);
                let gap = samples_from_duration(
                    start.saturating_duration_since(previous_end),
                    clock_rate,
                );
                let earliest_rtp_time =
                    previous.end_rtp_time().rebase(clock_rate) + MediaTime::new(gap, clock_rate);
                rtp_time = rtp_time.max(earliest_rtp_time);
            }
        } else if let Some(not_before) = self.next_tone_at {
            if not_before > start {
                let delay = samples_from_duration(not_before - start, clock_rate);
                rtp_time += MediaTime::new(delay, clock_rate);
                start = not_before;
            }
        }

        self.queue.push_back(QueuedTone {
            pt,
            rid,
            event,
            volume,
            total_samples,
            rtp_time,
            start,
            clock_rate,
            ext_vals,
        });
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        if let Some(active) = &self.active {
            return Some(active.next_at);
        }
        self.queue
            .front()
            .map(|tone| tone.first_report_at(self.next_tone_at))
    }

    pub fn retain(&mut self, mut permitted: impl FnMut(Pt, u8) -> bool) -> usize {
        let queued = self.queue.len();
        self.queue.retain(|tone| permitted(tone.pt, tone.event));
        let mut cancelled = queued - self.queue.len();
        if self
            .active
            .as_ref()
            .is_some_and(|active| !permitted(active.tone.pt, active.tone.event))
        {
            self.active = None;
            cancelled += 1;
        }
        cancelled
    }

    pub fn poll(&mut self, now: Instant) -> Option<ArrayVec<ToPayload, END_PACKET_REPEATS>> {
        if self.active.is_none() {
            let mut tone = self.queue.pop_front()?;
            tone.delay_until(self.next_tone_at);
            let next_at = tone.first_report_at(None);
            self.active = Some(ActiveTone {
                tone,
                first: true,
                segment_start: 0,
                next_at,
            });
        }

        let active = self.active.as_mut().unwrap();
        if now < active.next_at {
            return None;
        }

        let segment_target =
            (active.tone.total_samples - active.segment_start).min(u16::MAX as u64);
        let final_segment = active.segment_start + segment_target == active.tone.total_samples;
        let elapsed_samples = samples_from_duration(
            now.saturating_duration_since(active.tone.start),
            active.tone.clock_rate,
        )
        .min(active.tone.total_samples);
        let duration = elapsed_samples
            .saturating_sub(active.segment_start)
            .min(segment_target);
        let segment_complete = duration == segment_target;

        // Intermediate long-tone segments repeat 0xffff with E clear.
        let report = TelephoneEventPayload {
            event: active.tone.event,
            end: final_segment && segment_complete,
            volume: active.tone.volume,
            duration: duration as u16,
        };
        let segment_offset = MediaTime::new(active.segment_start, active.tone.clock_rate);
        let data: Arc<[u8]> = Arc::from(report.to_bytes().as_slice());
        let repeats = if segment_complete {
            END_PACKET_REPEATS
        } else {
            1
        };
        let mut packets = ArrayVec::new();
        for repeat in 0..repeats {
            packets.push(ToPayload {
                pt: active.tone.pt,
                rid: active.tone.rid,
                wallclock: active.tone.start + segment_offset,
                rtp_time: active.tone.rtp_time + segment_offset,
                start_of_talk_spurt: active.first && repeat == 0,
                data: data.clone(),
                ext_vals: active.tone.ext_vals.clone(),
            });
        }
        active.first = false;
        active.next_at = now + PACKET_INTERVAL;
        self.next_tone_at = Some(now + MIN_TONE_GAP);

        if segment_complete {
            if final_segment {
                self.active = None;
            } else {
                active.segment_start += segment_target;
                // A continuation is not another digit: do not apply the tone gap.
                active.next_at = if elapsed_samples > active.segment_start {
                    now
                } else {
                    let step =
                        samples_from_duration(PACKET_INTERVAL, active.tone.clock_rate).max(1);
                    let remaining = active.tone.total_samples - active.segment_start;
                    now + duration_from_samples(step.min(remaining), active.tone.clock_rate)
                };
            }
        }
        Some(packets)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn tone(start: Instant, duration: Duration, clock_rate: Frequency) -> DtmfTone {
        DtmfTone {
            pt: 126.into(),
            rid: Some("audio".into()),
            rtp_time: MediaTime::from_secs(1),
            wallclock: start,
            event: 5,
            volume: 10,
            duration,
            clock_rate,
            ext_vals: ExtensionValues {
                audio_level: Some(-30),
                ..Default::default()
            },
        }
    }

    fn drain(sender: &mut DtmfSender, mut now: Instant) -> Vec<(Instant, ToPayload)> {
        let mut packets = vec![];
        for _ in 0..1000 {
            let Some(deadline) = sender.poll_timeout() else {
                return packets;
            };
            now = now.max(deadline);
            packets.extend(
                sender
                    .poll(now)
                    .expect("packet is due")
                    .into_iter()
                    .map(|packet| (now, packet)),
            );
        }
        panic!("tone sender did not finish");
    }

    #[test]
    fn normal_tones_have_clock_correct_reports_and_final_repeats() {
        for (clock, step, total) in [
            (Frequency::EIGHT_KHZ, 160, 800),
            (Frequency::SIXTEEN_KHZ, 320, 1600),
            (Frequency::FORTY_EIGHT_KHZ, 960, 4800),
        ] {
            let start = Instant::now();
            let mut sender = DtmfSender::default();
            sender.push(tone(start, Duration::from_millis(100), clock));
            assert_eq!(
                sender.poll_timeout(),
                Some(start + Duration::from_millis(20))
            );
            assert!(sender.poll(start).is_none());
            let packets = drain(&mut sender, start);
            assert_eq!(packets.len(), 7);
            for (index, (sent_at, packet)) in packets.iter().enumerate() {
                assert_eq!(
                    *sent_at,
                    start + Duration::from_millis(((index as u64 + 1) * 20).min(100))
                );
                assert_eq!(packet.rtp_time, MediaTime::new(clock.get() as u64, clock));
                assert_eq!(packet.rtp_time.frequency(), clock);
                assert_eq!(packet.wallclock, start);
                assert_eq!(packet.start_of_talk_spurt, index == 0);
                assert_eq!(packet.rid, Some("audio".into()));
                assert_eq!(packet.ext_vals.audio_level, Some(-30));
                let report = TelephoneEventPayload::parse(&packet.data).unwrap();
                assert_eq!(report.duration, ((index as u16 + 1) * step).min(total));
                assert_eq!(report.end, index >= 4);
            }
        }
    }

    #[test]
    fn short_tones_finish_before_the_packet_interval() {
        for (duration, expected_samples) in [
            (Duration::ZERO, 1),
            (Duration::from_millis(1), 8),
            (Duration::from_millis(5), 40),
        ] {
            let start = Instant::now();
            let mut sender = DtmfSender::default();
            sender.push(tone(start, duration, Frequency::EIGHT_KHZ));
            let packets = drain(&mut sender, start);
            assert_eq!(packets.len(), 3);
            assert_eq!(
                packets[0].0 - start,
                duration.max(Duration::from_micros(125))
            );
            let sent_at = packets[0].0;
            for (time, packet) in packets {
                assert_eq!(time, sent_at);
                let report = TelephoneEventPayload::parse(&packet.data).unwrap();
                assert!(report.end);
                assert_eq!(report.duration, expected_samples);
            }
        }
    }

    #[test]
    fn queued_tones_preserve_gaps_and_do_not_overlap() {
        let start = Instant::now();
        let mut sender = DtmfSender::default();
        for (event, delay) in [(1, 0), (2, 0), (3, 500)] {
            let mut tone = tone(
                start + Duration::from_millis(delay),
                Duration::from_millis(100),
                Frequency::EIGHT_KHZ,
            );
            tone.event = event;
            sender.push(tone);
        }
        let packets = drain(&mut sender, start);
        for (event, offset, rtp_time) in [(1, 0, 8000), (2, 170, 9360), (3, 500, 12000)] {
            let reports: Vec<_> = packets
                .iter()
                .filter(|(_, packet)| packet.data[0] == event)
                .collect();
            assert!(!reports.is_empty());
            assert_eq!(
                reports
                    .iter()
                    .filter(|(_, packet)| packet.start_of_talk_spurt)
                    .count(),
                1
            );
            assert_eq!(
                reports
                    .iter()
                    .filter(|(_, packet)| TelephoneEventPayload::parse(&packet.data).unwrap().end)
                    .count(),
                3
            );
            for (_, packet) in reports {
                assert_eq!(packet.wallclock, start + Duration::from_millis(offset));
                assert_eq!(packet.rtp_time.numer(), rtp_time);
            }
        }
    }

    #[test]
    fn long_tones_keep_segment_timestamps_sample_exact() {
        let start = Instant::now();
        let mut sender = DtmfSender::default();
        sender.push(tone(
            start,
            Duration::from_secs(3),
            Frequency::FORTY_EIGHT_KHZ,
        ));
        let packets = drain(&mut sender, start);
        assert_eq!(
            packets
                .iter()
                .filter(|(_, packet)| packet.start_of_talk_spurt)
                .count(),
            1
        );
        for (segment, duration, end) in [(0, 65535, false), (1, 65535, false), (2, 12930, true)] {
            let timestamp = 48000 + segment * 65535;
            let reports: Vec<_> = packets
                .iter()
                .filter(|(_, packet)| packet.rtp_time.numer() == timestamp)
                .collect();
            assert!(!reports.is_empty());
            let final_reports: Vec<_> = reports
                .iter()
                .filter_map(|(_, packet)| {
                    let report = TelephoneEventPayload::parse(&packet.data).unwrap();
                    assert_eq!(packet.rtp_time.frequency(), Frequency::FORTY_EIGHT_KHZ);
                    assert_eq!(
                        packet.wallclock,
                        start + MediaTime::new(segment * 65535, Frequency::FORTY_EIGHT_KHZ)
                    );
                    (report.duration == duration).then_some(report)
                })
                .collect();
            assert_eq!(final_reports.len(), 3);
            assert!(final_reports.iter().all(|report| report.end == end));
        }
    }

    #[test]
    fn late_poll_uses_elapsed_duration() {
        let start = Instant::now();
        let mut sender = DtmfSender::default();
        sender.push(tone(
            start,
            Duration::from_millis(100),
            Frequency::EIGHT_KHZ,
        ));
        let packet = sender
            .poll(start + Duration::from_millis(60))
            .unwrap()
            .pop()
            .unwrap();
        let report = TelephoneEventPayload::parse(&packet.data).unwrap();
        assert_eq!(report.duration, 480);
        assert!(!report.end);
        assert!(packet.start_of_talk_spurt);
        assert_eq!(
            sender.poll_timeout(),
            Some(start + Duration::from_millis(80))
        );
    }

    #[test]
    fn late_completion_preserves_the_minimum_gap_and_timestamp_mapping() {
        let start = Instant::now();
        let mut sender = DtmfSender::default();
        sender.push(tone(
            start,
            Duration::from_millis(100),
            Frequency::EIGHT_KHZ,
        ));
        sender.push(tone(
            start,
            Duration::from_millis(100),
            Frequency::EIGHT_KHZ,
        ));
        let final_reports = sender.poll(start + Duration::from_millis(200)).unwrap();
        assert_eq!(final_reports.len(), 3);
        assert!(
            final_reports
                .iter()
                .all(|packet| TelephoneEventPayload::parse(&packet.data).unwrap().end)
        );
        assert_eq!(
            sender.poll_timeout(),
            Some(start + Duration::from_millis(290))
        );
        assert!(sender.poll(start + Duration::from_millis(289)).is_none());
        let next = sender.poll(start + Duration::from_millis(290)).unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].wallclock, start + Duration::from_millis(270));
        assert_eq!(
            next[0].rtp_time,
            MediaTime::new(10160, Frequency::EIGHT_KHZ)
        );
    }

    #[test]
    fn a_new_request_after_completion_still_observes_the_tone_gap() {
        let start = Instant::now();
        let mut sender = DtmfSender::default();
        sender.push(tone(
            start,
            Duration::from_millis(100),
            Frequency::EIGHT_KHZ,
        ));
        let packets = drain(&mut sender, start);
        assert_eq!(
            packets.last().unwrap().0,
            start + Duration::from_millis(100)
        );
        let mut next = tone(
            start + Duration::from_millis(110),
            Duration::from_millis(100),
            Frequency::EIGHT_KHZ,
        );
        next.rtp_time = MediaTime::new(8880, Frequency::EIGHT_KHZ);
        sender.push(next);
        assert_eq!(
            sender.poll_timeout(),
            Some(start + Duration::from_millis(190))
        );
        let packets = sender.poll(start + Duration::from_millis(190)).unwrap();
        assert_eq!(packets[0].wallclock, start + Duration::from_millis(170));
        assert_eq!(
            packets[0].rtp_time,
            MediaTime::new(9360, Frequency::EIGHT_KHZ)
        );
    }

    #[test]
    fn exact_segment_boundary_does_not_emit_zero_duration_or_insert_a_tone_gap() {
        let start = Instant::now();
        let mut sender = DtmfSender::default();
        sender.push(tone(start, Duration::from_secs(9), Frequency::EIGHT_KHZ));
        let boundary = start + Duration::from_micros(8_191_875);
        let reports = sender.poll(boundary).unwrap();
        assert_eq!(reports.len(), 3);
        for packet in reports {
            let report = TelephoneEventPayload::parse(&packet.data).unwrap();
            assert_eq!(report.duration, u16::MAX);
            assert!(!report.end);
        }
        assert!(sender.poll(boundary).is_none());
        assert_eq!(
            sender.poll_timeout(),
            Some(boundary + Duration::from_millis(20))
        );
        let reports = sender.poll(boundary + Duration::from_millis(20)).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].rtp_time,
            MediaTime::new(73535, Frequency::EIGHT_KHZ)
        );
        assert!(!reports[0].start_of_talk_spurt);
        assert_eq!(
            TelephoneEventPayload::parse(&reports[0].data)
                .unwrap()
                .duration,
            160
        );
    }

    #[test]
    fn a_late_poll_can_cross_multiple_segments_without_truncation() {
        let start = Instant::now();
        let mut sender = DtmfSender::default();
        sender.push(tone(
            start,
            Duration::from_secs(3),
            Frequency::FORTY_EIGHT_KHZ,
        ));
        let now = start + Duration::from_secs(3);
        for (timestamp, duration, end) in [
            (48000, 65535, false),
            (113535, 65535, false),
            (179070, 12930, true),
        ] {
            let reports = sender.poll(now).unwrap();
            assert_eq!(reports.len(), 3);
            for packet in reports {
                assert_eq!(packet.rtp_time.numer(), timestamp);
                let report = TelephoneEventPayload::parse(&packet.data).unwrap();
                assert_eq!(report.duration, duration);
                assert_eq!(report.end, end);
            }
        }
        assert!(sender.poll_timeout().is_none());
    }
}
