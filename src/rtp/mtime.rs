#![allow(missing_docs)]

use std::cmp::Ordering;
use std::ops::{Add, Sub};
use std::time::Duration;

/// Microseconds in a second.
const MICROS: i64 = 1_000_000;

/// Milliseconds in a second.
const MILLIS: i64 = 1_000;

/// Media time represented by a numerator / denominator.
///
/// The numerator is typically the packet time of an Rtp header. The denominator is the
/// clock frequency of the media source (typically 90kHz for video and 48kHz for audio).
#[derive(Debug, Clone, Copy)]
pub struct MediaTime(i64, i64);

impl MediaTime {
    pub const ZERO: MediaTime = MediaTime(0, 1);

    pub const fn new(numer: i64, denom: i64) -> MediaTime {
        MediaTime(numer, denom)
    }

    #[inline(always)]
    pub const fn numer(&self) -> i64 {
        self.0
    }

    #[inline(always)]
    pub const fn denom(&self) -> i64 {
        self.1
    }

    #[inline(always)]
    pub const fn from_micros(v: i64) -> MediaTime {
        MediaTime(v, MICROS)
    }

    #[inline(always)]
    pub const fn from_millis(v: i64) -> MediaTime {
        MediaTime(v, MILLIS)
    }

    #[inline(always)]
    pub fn from_seconds(v: impl Into<f64>) -> MediaTime {
        Self::from_micros((v.into() * 1_000_000.0_f64) as i64)
    }

    #[inline(always)]
    pub fn as_seconds(&self) -> f64 {
        self.0 as f64 / self.1 as f64
    }

    pub const fn as_micros(&self) -> i64 {
        self.rebase(MICROS).numer()
    }

    #[inline(always)]
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub const fn abs(mut self) -> MediaTime {
        if self.0 < 0 {
            self.0 = -self.0;
        }
        self
    }

    #[inline(always)]
    pub const fn rebase(self, denom: i64) -> MediaTime {
        if denom == self.1 {
            self
        } else {
            let numer = self.0 as i128 * denom as i128 / self.1 as i128;
            MediaTime::new(numer as i64, denom)
        }
    }

    #[inline(always)]
    fn same_base(t0: MediaTime, t1: MediaTime) -> (MediaTime, MediaTime) {
        let max = t0.1.max(t1.1);
        (t0.rebase(max), t1.rebase(max))
    }
}

impl PartialEq for MediaTime {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        let (t0, t1) = MediaTime::same_base(*self, *other);
        t0.0 == t1.0
    }
}
impl Eq for MediaTime {}

impl PartialOrd for MediaTime {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MediaTime {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        let (t0, t1) = MediaTime::same_base(*self, *other);
        if t0 == t1 {
            Ordering::Equal
        } else if t0.0 < t1.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl Sub for MediaTime {
    type Output = MediaTime;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        let (t0, t1) = MediaTime::same_base(self, rhs);
        MediaTime::new(t0.0 - t1.0, t0.1)
    }
}

impl Add for MediaTime {
    type Output = MediaTime;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        let (t0, t1) = MediaTime::same_base(self, rhs);
        MediaTime::new(t0.0 + t1.0, t0.1)
    }
}

impl From<MediaTime> for Duration {
    fn from(val: MediaTime) -> Self {
        let m = val.rebase(MICROS);
        Duration::from_micros(m.0 as u64)
    }
}

impl From<Duration> for MediaTime {
    fn from(v: Duration) -> Self {
        MediaTime::new(v.as_micros() as i64, MICROS)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ts_rebase() {
        let t1 = MediaTime::from_seconds(10.0);
        let t2 = t1.rebase(90_000);
        assert_eq!(t2.numer(), 90_000 * 10);
        assert_eq!(t2.denom(), 90_000);

        println!("{}", (10.0234_f64).fract());
    }
}
