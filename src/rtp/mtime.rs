use std::cmp::Ordering;
use std::fmt::Display;
use std::num::{NonZeroU32, TryFromIntError};
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Media timeline frequency as represented by a non-zero unsigned integer.
///
/// The frequency can be found in the negotiated payload parameters for a
/// media writer.
///
/// ```no_run
/// # use str0m::Rtc;
/// # use str0m::media::{Mid, MediaTime};
/// # let rtc: Rtc = todo!();
/// #
/// // Obtain mid from Event::MediaAdded
/// let mid: Mid = todo!();
///
/// // Create a media writer for the mid.
/// let writer = rtc.writer(mid).unwrap();
///
/// // Get the payload type (pt) for the wanted codec.
/// let params = writer.payload_params().nth(0).unwrap();
///
/// // Obtain the frequency for the selected codec.
/// let freq = params.spec().clock_rate;
///
/// let mtime = MediaTime::new(2000, freq);
/// ```
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Frequency(NonZeroU32);

impl Frequency {
    /// Microseconds in a second.
    pub const MICROS: Self = Self::make(1_000_000);

    /// 1 / 2 ^ 18 seconds in a second.
    pub const FIXED_POINT_6_18: Frequency = Self::make(2u32.pow(18)); // 262_144

    /// Cycles in a second of a 90 kHz signal.
    pub const NINETY_KHZ: Frequency = Self::make(90_000);

    /// Cycles in a second of a 48 kHz signal.
    pub const FORTY_EIGHT_KHZ: Frequency = Self::make(48_000);

    /// Milliseconds in a second.
    pub const MILLIS: Frequency = Self::make(1_000);

    /// Hundredths in a second.
    pub const HUNDREDTHS: Frequency = Self::make(100);

    /// Seconds in a second.
    pub const SECONDS: Frequency = Self::make(1);

    /// Private unconditional non-zero constructor for use with constants.
    const fn make(v: u32) -> Frequency {
        match NonZeroU32::new(v) {
            Some(v) => Self(v),
            None => panic!("assured non-zero value is zero"),
        }
    }

    /// Any non-zero u32 is a valid media timeline frequency.
    pub const fn from_nonzero(v: NonZeroU32) -> Self {
        Self(v)
    }

    /// Every u32 is a valid media timeline frequency except zero.
    pub fn new(v: u32) -> Option<Self> {
        NonZeroU32::new(v).map(Self)
    }

    /// The frequency as a u32.
    pub const fn get(&self) -> u32 {
        self.0.get()
    }

    /// The frequency as a [`std::num::NonZeroU32`] i.e. including a positivity proof.
    pub const fn nonzero(&self) -> NonZeroU32 {
        self.0
    }
}

impl PartialEq for Frequency {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Frequency {}

impl From<Frequency> for NonZeroU32 {
    fn from(value: Frequency) -> Self {
        value.0
    }
}

impl From<NonZeroU32> for Frequency {
    fn from(value: NonZeroU32) -> Self {
        Self(value)
    }
}

impl FromStr for Frequency {
    type Err = <NonZeroU32 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NonZeroU32::from_str(s).map(Self)
    }
}

impl Display for Frequency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'de> Deserialize<'de> for Frequency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NonZeroU32::deserialize(deserializer).map(Self)
    }
}

/// Media timeline offset represented by a count (numerator) /
/// frequency (denominator) in seconds.
///
/// The numerator is typically the packet time of an Rtp header. The
/// denominator is the clock frequency of the media source (typically
/// 90kHz for video and 48kHz for audio). The denominator is
/// guaranteed to be a positive integer while the numerator could be
/// positive, negative, or zero.
///
/// The frequency can be found in the negotiated payload parameters for a
/// media writer.
///
/// ```no_run
/// # use str0m::Rtc;
/// # use str0m::media::{Mid, MediaTime};
/// # let rtc: Rtc = todo!();
/// #
/// // Obtain mid from Event::MediaAdded
/// let mid: Mid = todo!();
///
/// // Create a media writer for the mid.
/// let writer = rtc.writer(mid).unwrap();
///
/// // Get the payload type (pt) for the wanted codec.
/// let params = writer.payload_params().nth(0).unwrap();
///
/// // Obtain the frequency for the selected codec.
/// let freq = params.spec().clock_rate;
///
/// let mtime = MediaTime::new(2000, freq);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct MediaTime(i64, Frequency);

impl MediaTime {
    /// The additive identity: 0/1.
    pub const ZERO: MediaTime = MediaTime::from_secs(0);

    /// Construct a [`MediaTime`] from a guaranteed non-zero [`Frequency`].
    pub const fn new(numer: i64, denom: Frequency) -> Self {
        Self(numer, denom)
    }

    /// The numerator of the offset time.
    #[inline(always)]
    pub const fn numer(&self) -> i64 {
        self.0
    }

    /// The denominator of the offset time.
    #[inline(always)]
    pub const fn denom(&self) -> u32 {
        self.1.get()
    }

    /// The [`Frequency`] of the offset time.
    #[inline(always)]
    pub const fn frequency(&self) -> Frequency {
        self.1
    }

    /// Convenience constructor for numbers of microseconds (v/1_000_000).
    #[inline(always)]
    pub const fn from_micros(v: i64) -> MediaTime {
        MediaTime(v, Frequency::MICROS)
    }

    /// Convenience constructor for numbers of 24-bit 6.18 fixed point units (v/2^18).
    #[inline(always)]
    pub const fn from_fixed_point_6_18(v: i64) -> MediaTime {
        MediaTime(v, Frequency::FIXED_POINT_6_18)
    }

    /// Convenience constructor for numbers of 90kHz units (v/90_000).
    #[inline(always)]
    pub const fn from_90khz(v: i64) -> MediaTime {
        MediaTime(v, Frequency::NINETY_KHZ)
    }

    /// Convenience constructor for numbers of milliseconds (v/1000).
    #[inline(always)]
    pub const fn from_millis(v: i64) -> MediaTime {
        MediaTime(v, Frequency::MILLIS)
    }

    /// Convenience constructor for numbers of hundredths of seconds (v/100).
    #[inline(always)]
    pub const fn from_hundredths(v: i64) -> MediaTime {
        MediaTime(v, Frequency::HUNDREDTHS)
    }

    /// Convenience constructor for numbers of seconds (v/1).
    #[inline(always)]
    pub const fn from_secs(v: i64) -> MediaTime {
        MediaTime(v, Frequency::SECONDS)
    }

    /// Convenience constructor for floating point fractions of seconds as microsecond units.
    #[inline(always)]
    pub fn from_seconds(v: impl Into<f64>) -> MediaTime {
        Self::from_micros((v.into() * 1_000_000.0_f64) as i64)
    }

    /// A floating point fraction second representation.
    #[inline(always)]
    pub fn as_seconds(&self) -> f64 {
        let denom: f64 = self.1.get().into();
        self.0 as f64 / denom
    }

    /// A microsecond representation.
    pub const fn as_micros(&self) -> i64 {
        self.rebase(Frequency::MICROS).numer()
    }

    /// Predicate for checking that the numerator is 0.
    #[inline(always)]
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// The absolute value of the offset time.
    #[inline(always)]
    pub const fn abs(mut self) -> MediaTime {
        if self.0 < 0 {
            self.0 = -self.0;
        }
        self
    }

    /// Convert this offset time to have a different denominator
    /// (frequency). This conversion may lose precision and, after
    /// arithmetic operations with other times of higher frequencies,
    /// may have a higher frequency.
    #[inline(always)]
    pub const fn rebase(self, denom: Frequency) -> MediaTime {
        if denom.get() == self.1.get() {
            self
        } else {
            let numer = self.0 as i128 * denom.get() as i128 / self.1.get() as i128;
            MediaTime::new(numer as i64, denom)
        }
    }

    #[inline(always)]
    fn same_base(t0: MediaTime, t1: MediaTime) -> (MediaTime, MediaTime) {
        let max = Frequency(t0.1 .0.max(t1.1 .0));
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

impl SubAssign for MediaTime {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Sub<MediaTime> for Instant {
    type Output = Instant;

    fn sub(self, rhs: MediaTime) -> Self::Output {
        if rhs.numer() < 0 {
            // abs(numer < 0) => positive i64 which can always fit in u64
            self + Duration::try_from(rhs.abs()).unwrap()
        } else {
            // numer >= 0 => positive i64 which can always fit in u64
            self - Duration::try_from(rhs).unwrap()
        }
    }
}

impl SubAssign<MediaTime> for Instant {
    fn sub_assign(&mut self, rhs: MediaTime) {
        *self = *self - rhs;
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

impl AddAssign for MediaTime {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Add<MediaTime> for Instant {
    type Output = Instant;

    fn add(self, rhs: MediaTime) -> Self::Output {
        if rhs.numer() < 0 {
            // abs(numer < 0) => positive i64 which can always fit in u64
            self - Duration::try_from(rhs.abs()).unwrap()
        } else {
            // numer >= 0 => positive i64 which can always fit in u64
            self + Duration::try_from(rhs).unwrap()
        }
    }
}

impl AddAssign<MediaTime> for Instant {
    fn add_assign(&mut self, rhs: MediaTime) {
        *self = *self + rhs;
    }
}

impl TryFrom<MediaTime> for Duration {
    type Error = TryFromIntError;

    fn try_from(value: MediaTime) -> Result<Self, Self::Error> {
        value
            .rebase(Frequency::MICROS)
            .numer()
            .try_into()
            .map(Duration::from_micros)
    }
}

impl From<Duration> for MediaTime {
    fn from(v: Duration) -> Self {
        MediaTime::new(v.as_micros() as i64, Frequency::MICROS)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ts_rebase() {
        let t1 = MediaTime::from_seconds(10.0);
        let t2 = t1.rebase(Frequency::NINETY_KHZ);
        assert_eq!(t2.numer(), 90_000 * 10);
        assert_eq!(t2.denom(), 90_000);

        println!("{}", (10.0234_f64).fract());
    }

    #[test]
    fn ts_negative_duration() {
        let t = MediaTime::new(-1, Frequency::make(1));
        let t_dur: Result<Duration, TryFromIntError> = t.try_into();
        if let Ok(dur) = t_dur {
            panic!("expected conversion of negative MediaTime to fail but got {dur:?}")
        }
    }
}
