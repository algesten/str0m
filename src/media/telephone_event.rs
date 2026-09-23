//! Sends queued telephone events (RFC 4733) like libwebrtc, see `Writer::write_telephone_event`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::RtcError;

use super::{ExtensionValues, Frequency, MediaTime, Pt, Rid, TelephoneEventPayload, ToPayload};

const UPDATE_INTERVAL: Duration = Duration::from_millis(20);
const MIN_PAUSE: Duration = Duration::from_millis(50);
const MIN_DURATION: Duration = Duration::from_millis(40);
const MAX_DURATION: Duration = Duration::from_millis(6000);

/// The most the 16-bit duration field holds. Longer events are sent in segments
/// (RFC 4733 Section 2.5.1.3).
const MAX_SEGMENT: u64 = u16::MAX as u64;

/// A telephone event to send, from `Writer::write_telephone_event`.
#[derive(Debug)]
pub(crate) struct TelephoneEvent {
    pub pt: Pt,
    pub rid: Option<Rid>,
    pub event: u8,
    pub volume: u8,
    pub duration: Duration,
    /// When the event starts.
    pub wallclock: Instant,
    /// The RTP time at `wallclock`, in the clock rate of `pt`.
    pub rtp_time: MediaTime,
    pub ext_vals: ExtensionValues,
}

/// The telephone events to send, and the progress of the first one.
#[derive(Debug, Default)]
pub(crate) struct TelephoneEventQueue {
    events: VecDeque<TelephoneEvent>,
    /// When the last queued event ends.
    last_end: Option<Instant>,
    /// How many update intervals the first event had lasted at its last report.
    ticks: u32,
    /// Where the current segment of the first event starts, in RTP time from the event start.
    segment: u64,
}

impl TelephoneEventQueue {
    pub(crate) fn push(&mut self, mut event: TelephoneEvent) -> Result<(), RtcError> {
        // The volume field has 6 bits (RFC 4733 Section 2.3.4).
        if event.volume > 63 {
            return Err(RtcError::InvalidTelephoneEventVolume(event.volume));
        }
        if !(MIN_DURATION..=MAX_DURATION).contains(&event.duration) {
            return Err(RtcError::InvalidTelephoneEventDuration(event.duration));
        }

        // Waiting for the previous event moves the start in wallclock and RTP time alike.
        let pause_end = self.last_end.map(|end| end + MIN_PAUSE);
        if let Some(start) = pause_end.filter(|start| *start > event.wallclock) {
            let clock_rate = event.rtp_time.frequency();
            let delay = to_units(start - event.wallclock, clock_rate);
            event.rtp_time = MediaTime::new(event.rtp_time.numer() + delay, clock_rate);
            event.wallclock = start;
        }

        self.last_end = Some(event.wallclock + event.duration);
        self.events.push_back(event);
        Ok(())
    }

    /// When the next report is due: on the 20 ms grid from the start of the event, or at its end.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        let event = self.events.front()?;
        let update = event.wallclock + UPDATE_INTERVAL * (self.ticks + 1);
        Some(update.min(event.wallclock + event.duration))
    }

    /// The reports that are due at `now`.
    pub(crate) fn poll(&mut self, now: Instant) -> Vec<ToPayload> {
        let mut reports = vec![];

        while self.poll_timeout().is_some_and(|due| due <= now) {
            let Some(event) = self.events.front() else {
                warn!("Telephone event queue is empty despite a due report");
                break;
            };
            let end = event.wallclock + event.duration;
            let elapsed = to_units(now.min(end) - event.wallclock, event.rtp_time.frequency());
            let mut marker = self.ticks == 0;

            // The first report past the duration limit also ends the segment. The next segment
            // starts where it ended (RFC 4733 Section 2.5.1.3).
            while elapsed - self.segment > MAX_SEGMENT {
                reports.push(event.report(self.segment, MAX_SEGMENT, false, marker));
                self.segment += MAX_SEGMENT;
                marker = false;
            }

            let duration = elapsed - self.segment;
            if now < end {
                let ticks = (now - event.wallclock).as_nanos() / UPDATE_INTERVAL.as_nanos();
                let Ok(ticks) = u32::try_from(ticks) else {
                    warn!("Telephone event tick count out of range: {}", ticks);
                    return reports;
                };
                reports.push(event.report(self.segment, duration, false, marker));
                self.ticks = ticks;
            } else {
                // Send the final report three times in a row (RFC 4733 Section 2.5.1.4).
                for marker in [marker, false, false] {
                    reports.push(event.report(self.segment, duration, true, marker));
                }
                self.events.pop_front();
                self.ticks = 0;
                self.segment = 0;
            }
        }

        reports
    }
}

impl TelephoneEvent {
    /// A report on the segment that starts `segment` into the event, in RTP time.
    fn report(&self, segment: u64, duration: u64, end: bool, marker: bool) -> ToPayload {
        let clock_rate = self.rtp_time.frequency();
        let report = TelephoneEventPayload {
            event: self.event,
            end,
            volume: self.volume,
            duration: duration as u16,
        };
        ToPayload {
            pt: self.pt,
            rid: self.rid,
            // Reports carry the RTP time their segment starts, with the matching wallclock.
            wallclock: self.wallclock + Duration::from(MediaTime::new(segment, clock_rate)),
            rtp_time: MediaTime::new(self.rtp_time.numer() + segment, clock_rate),
            start_of_talk_spurt: marker,
            data: report.to_bytes().into(),
            ext_vals: self.ext_vals.clone(),
        }
    }
}

/// Converts a duration to RTP time in `clock_rate` units.
fn to_units(duration: Duration, clock_rate: Frequency) -> u64 {
    MediaTime::from(duration).rebase(clock_rate).numer()
}

#[cfg(test)]
mod test {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// A report as (time since the start of the test, RTP time, marker, report).
    type Sent = (Duration, u64, bool, TelephoneEventPayload);

    fn event(wallclock: Instant, duration: Duration, clock_rate: Frequency) -> TelephoneEvent {
        TelephoneEvent {
            pt: 101.into(),
            rid: None,
            event: 5,
            volume: 10,
            duration,
            wallclock,
            rtp_time: MediaTime::new(1000, clock_rate),
            ext_vals: ExtensionValues::default(),
        }
    }

    fn report(duration: u16, end: bool) -> TelephoneEventPayload {
        TelephoneEventPayload {
            event: 5,
            end,
            volume: 10,
            duration,
        }
    }

    fn poll_at(queue: &mut TelephoneEventQueue, base: Instant, now: Instant) -> Vec<Sent> {
        let sent = |p: ToPayload| {
            let report = TelephoneEventPayload::parse(&p.data).unwrap();
            (
                now - base,
                p.rtp_time.numer(),
                p.start_of_talk_spurt,
                report,
            )
        };
        queue.poll(now).into_iter().map(sent).collect()
    }

    /// Polls every report when it is due, like the session does.
    fn drain(queue: &mut TelephoneEventQueue, base: Instant) -> Vec<Sent> {
        let mut reports = vec![];
        while let Some(now) = queue.poll_timeout() {
            reports.extend(poll_at(queue, base, now));
            assert!(reports.len() < 1000, "the queue does not drain");
        }
        reports
    }

    #[test]
    fn events_start_at_least_50ms_after_the_previous_one() {
        let base = Instant::now();
        let mut queue = TelephoneEventQueue::default();
        queue
            .push(event(base, 100 * MS, Frequency::EIGHT_KHZ))
            .unwrap();
        assert_eq!(drain(&mut queue, base).len(), 7);

        // Written in the pause after the first event, the next one starts when the pause ends,
        // 30 ms or 240 units later.
        let next = event(base + 120 * MS, 100 * MS, Frequency::EIGHT_KHZ);
        queue.push(next).unwrap();
        let first = (170 * MS, 1240, true, report(160, false));
        assert_eq!(drain(&mut queue, base)[0], first);

        // Written after the pause, the next one keeps its start.
        let next = event(base + 500 * MS, 100 * MS, Frequency::EIGHT_KHZ);
        queue.push(next).unwrap();
        let first = (520 * MS, 1000, true, report(160, false));
        assert_eq!(drain(&mut queue, base)[0], first);
    }

    #[test]
    fn late_poll_reports_the_elapsed_duration_and_keeps_the_grid() {
        let base = Instant::now();
        let mut queue = TelephoneEventQueue::default();
        queue
            .push(event(base, 200 * MS, Frequency::EIGHT_KHZ))
            .unwrap();

        let first = (63 * MS, 1000, true, report(504, false));
        assert_eq!(poll_at(&mut queue, base, base + 63 * MS), [first]);
        assert_eq!(queue.poll_timeout(), Some(base + 80 * MS));

        // Polled past its end, the event reports its full duration.
        let last = (500 * MS, 1000, false, report(1600, true));
        assert_eq!(poll_at(&mut queue, base, base + 500 * MS), [last; 3]);
        assert_eq!(queue.poll_timeout(), None);
    }

    #[test]
    fn maximum_duration_bounds_ticks() {
        let base = Instant::now();
        let mut queue = TelephoneEventQueue::default();
        queue
            .push(event(base, MAX_DURATION, Frequency::EIGHT_KHZ))
            .unwrap();

        let end = base + MAX_DURATION;
        assert_eq!(queue.poll(end - Duration::from_nanos(1)).len(), 1);
        assert_eq!(queue.ticks, 299);
        assert_eq!(queue.poll_timeout(), Some(end));
        assert_eq!(queue.poll(end).len(), 3);
        assert_eq!(queue.ticks, 0);
        assert_eq!(queue.poll_timeout(), None);
    }

    #[test]
    fn long_event_is_sent_in_segments() {
        let base = Instant::now();
        let mut queue = TelephoneEventQueue::default();
        let long = || event(base, 3000 * MS, Frequency::FORTY_EIGHT_KHZ);
        queue.push(long()).unwrap();
        let reports = drain(&mut queue, base);

        // Updates at 20 to 2980 ms, two segment ends and the final report three times.
        assert_eq!(reports.len(), 149 + 2 + 3);
        assert_eq!(reports.iter().filter(|s| s.2).count(), 1);

        // The first update past 65535 units ends the segment with that duration, and the next
        // segment starts where it ended. 1380 ms is 66240 units in.
        let at = |ms: u32| -> Vec<_> {
            let sent = reports.iter().filter(|s| s.0 == ms * MS);
            sent.map(|s| (s.1, s.3)).collect()
        };
        let segment_end = report(u16::MAX, false);
        assert_eq!(at(1380), [(1000, segment_end), (66535, report(705, false))]);
        assert_eq!(
            at(2740),
            [(66535, segment_end), (132070, report(450, false))]
        );
        assert_eq!(at(3000), [(132070, report(12930, true)); 3]);

        // Reports carry the wallclock of their segment start, 65535 units in.
        let mut queue = TelephoneEventQueue::default();
        queue.push(long()).unwrap();
        let reports = queue.poll(base + 1380 * MS);
        assert_eq!(
            reports[1].wallclock - base,
            Duration::from_micros(1_365_312)
        );
    }
}
