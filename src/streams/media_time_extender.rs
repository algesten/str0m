use std::time::Instant;

use crate::rtp_::{Frequency, MediaTime};

/// Extends the 32-bit RTP timestamps of one SSRC to 64 bits.
#[derive(Debug, Default)]
pub(crate) struct MediaTimeExtender {
    reference: Option<MediaTimeReference>,
}

/// The extended time of the newest observed timestamp, and when it arrived.
#[derive(Debug, Clone, Copy)]
struct MediaTimeReference {
    time: MediaTime,
    arrived_at: Instant,
}

impl MediaTimeExtender {
    /// Extend `timestamp` against the newest observed one.
    pub fn extend(&self, now: Instant, timestamp: u32, clock_rate: Frequency) -> MediaTime {
        let Some(reference) = self.reference else {
            return MediaTime::new(timestamp as u64, clock_rate);
        };

        // While nothing arrived, the sender's clock either stopped or kept running.
        let since_arrival = now.saturating_duration_since(reference.arrived_at);
        let elapsed = MediaTime::from(since_arrival).rebase(clock_rate);
        let stopped = reference.time.numer();
        let running = stopped.saturating_add(elapsed.numer());

        let if_stopped = nearest_extended_time(stopped, timestamp);
        let if_running = nearest_extended_time(running, timestamp);

        let time = if if_running.abs_diff(running) < if_stopped.abs_diff(stopped) {
            if_running
        } else {
            if_stopped
        };

        MediaTime::new(time, clock_rate)
    }

    /// Extend later timestamps against `timestamp`, if it is the newest so far.
    pub fn observe(&mut self, now: Instant, timestamp: u32, clock_rate: Frequency) {
        let time = self.extend(now, timestamp, clock_rate);

        // Padding and resends repeat an old timestamp, which says nothing of the sender's clock.
        if self.reference.is_none_or(|reference| time > reference.time) {
            self.reference = Some(MediaTimeReference {
                time,
                arrived_at: now,
            });
        }
    }
}

/// The time closest to `expected` that has `timestamp` as its lower 32 bits.
///
/// Time does not go below zero: a timestamp that would is placed in the first cycle.
fn nearest_extended_time(expected: u64, timestamp: u32) -> u64 {
    let step = timestamp.wrapping_sub(expected as u32) as i32;
    expected
        .checked_add_signed(step as i64)
        .unwrap_or(timestamp as u64)
}
