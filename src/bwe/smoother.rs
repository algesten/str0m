use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::rtp_::Bitrate;

/// Changes within tolerance are held back until older estimates age out of this window.
const ESTIMATE_WINDOW: Duration = Duration::from_secs(3);

type TimeBitrate = (Instant, Bitrate);

const TOLERANCE: f64 = 0.05;

/// Emits the latest BWE estimate once it moves outside the tolerance of the last emitted one.
pub struct EstimateSmoother {
    estimates: VecDeque<TimeBitrate>,
    maybe_emit: bool,
    emitted: Option<Bitrate>,
}

impl EstimateSmoother {
    pub fn new() -> Self {
        Self {
            estimates: VecDeque::new(),
            maybe_emit: false,
            emitted: None,
        }
    }

    /// Record a new estimate.
    pub fn record(&mut self, now: Instant, estimate: Bitrate) {
        // Did value change from previous?
        let do_update = self.estimates.back().map(|b| b.1) != Some(estimate);

        if do_update {
            self.maybe_emit = true;
            self.estimates.push_back((now, estimate));
        }

        // Remove entries older than the window.
        while let Some((time, _)) = self.estimates.front() {
            if now.duration_since(*time) > ESTIMATE_WINDOW {
                // Keep last entry
                if self.estimates.len() == 1 {
                    break;
                }

                self.maybe_emit = true;
                self.estimates.pop_front();
            } else {
                break;
            }
        }
    }

    /// Poll for an estimate to emit. Returns Some only when there's a new value to emit.
    pub fn poll(&mut self) -> Option<Bitrate> {
        if !self.maybe_emit {
            return None;
        }

        let &(_, rate) = self.estimates.back()?;

        // This forces emitting if we have the first ever value, or a last
        // where the rest of the window is gone (estimates stop coming).
        let force = self.estimates.len() == 1 && self.emitted != Some(rate);

        // Emit if we deviate enough from previously emitted.
        let deviate = if let Some(emitted) = self.emitted {
            !in_tolerance(emitted, rate)
        } else {
            true
        };

        self.maybe_emit = false;

        // Are we not to emit?
        if !force && !deviate {
            return None;
        }

        self.emitted = Some(rate);
        Some(rate)
    }
}

fn in_tolerance(b1: Bitrate, b2: Bitrate) -> bool {
    let min = b1 * (1.0 - TOLERANCE);
    let max = b1 * (1.0 + TOLERANCE);
    b2 > min && b2 < max
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn emits_a_rise_without_waiting_for_the_window() {
        let mut smoother = EstimateSmoother::new();
        let now = Instant::now();

        smoother.record(now, Bitrate::kbps(500));
        assert_eq!(smoother.poll(), Some(Bitrate::kbps(500)));

        smoother.record(now + Duration::from_secs(2), Bitrate::kbps(1700));
        assert_eq!(smoother.poll(), Some(Bitrate::kbps(1700)));
    }

    #[test]
    fn holds_back_changes_within_tolerance() {
        let mut smoother = EstimateSmoother::new();
        let now = Instant::now();

        smoother.record(now, Bitrate::kbps(1000));
        assert_eq!(smoother.poll(), Some(Bitrate::kbps(1000)));

        smoother.record(now + Duration::from_millis(100), Bitrate::kbps(1040));
        assert_eq!(smoother.poll(), None);
    }
}
