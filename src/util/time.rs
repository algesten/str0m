use once_cell::sync::Lazy;
use std::cmp::Ordering;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Div, Mul, Neg as _, Sub, SubAssign};
use std::time as std_time;
use std::time::SystemTime;

// RTP spec "wallclock" uses NTP time, which starts at 1900-01-01.
//
// https://tools.ietf.org/html/rfc868
//
// 365 days * 70 years + 17 leap year days
// (365 * 70 + 17) * 86400 = 2208988800
const SECS_1900: u64 = 2_208_988_800;
const MICROS_1900: u64 = SECS_1900 * 1_000_000;

/// 2^32 as float.
const F32: f64 = 4_294_967_296.0;

// The goal here is to make a constant "beginning of time" in both Instant and SystemTime
// that we can use as relative values for the rest of str0m.
// This is indeed a bit dodgy, but we want str0m's internal idea of time to be completely
// driven from the external API using `Instant`. What works against us is that Instant can't
// represent things like UNIX EPOCH (but SystemTime can).
static BEGINNING_OF_TIME: Lazy<(std_time::Instant, SystemTime)> = Lazy::new(|| {
    // These two should be "frozen" the same instant. Hopefully they are not differing too much.
    let now = std_time::Instant::now();
    let now_sys = SystemTime::now();

    // Find an Instant in the past which is up to an hour back.
    let beginning_of_time = {
        let mut secs = 3600;
        loop {
            let dur = std_time::Duration::from_secs(secs);
            if let Some(v) = now.checked_sub(dur) {
                break v;
            }
            secs -= 1;
            if secs == 0 {
                panic!("Failed to find a beginning of time instant");
            }
        }
    };

    // This might be less than 1 hour if the machine uptime is less.
    let since_beginning_of_time = std_time::Instant::now() - beginning_of_time;

    let beginning_of_time_sys = now_sys - since_beginning_of_time;

    // This pair represents our "beginning of time" for the same moment.
    (beginning_of_time, beginning_of_time_sys)
});

pub(crate) fn epoch_to_beginning() -> Duration {
    BEGINNING_OF_TIME
        .1
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("beginning of time to be after epoch")
        .into()
}

/// Wrapper for [`time::Instant`] that provides additional time points in the past or future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Instant {
    /// A time in the past that already happened.
    DistantPast,

    /// An exact instant.
    Exact(std_time::Instant),

    /// A time in the future that will never happen.
    DistantFuture,
}

/// Wrapper for [`time::Duration`] that provides a duration to a distant future or past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Duration {
    /// Time delta to some event in distant past that already happened.
    MinusInf,

    /// An exact duration.
    Negative(std_time::Duration),

    /// An exact duration.
    Positive(std_time::Duration),

    /// Time delta to some event in distant future that will never happen.
    PlusInf,
}

impl Duration {
    pub(crate) const ZERO: Self = Self::Positive(std_time::Duration::ZERO);

    pub(crate) fn as_std(&self) -> Option<std_time::Duration> {
        match self {
            Duration::Positive(d) => Some(*d),
            _ => None,
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    /// Creates a [`Duration`] from milliseconds.
    pub(crate) const fn from_millis(millis: u64) -> Self {
        Self::Positive(std_time::Duration::from_millis(millis))
    }

    /// Creates a [`Duration`] from milliseconds.
    pub(crate) const fn from_micros(millis: u64) -> Self {
        Self::Positive(std_time::Duration::from_micros(millis))
    }

    /// Creates a [`Duration`] from seconds.
    pub(crate) const fn from_secs(secs: u64) -> Duration {
        Self::Positive(std_time::Duration::from_secs(secs))
    }

    pub(crate) fn as_secs(&self) -> i128 {
        match self {
            Duration::MinusInf => i128::MIN,
            Duration::Negative(d) => i128::from(d.as_secs()).neg(),
            Duration::Positive(d) => i128::from(d.as_secs()),
            Duration::PlusInf => i128::MAX,
        }
    }

    /// Returns the number of seconds contained by this [`Duration`] as `f64`.
    pub(crate) fn as_secs_f64(&self) -> f64 {
        match self {
            Self::Negative(d) => d.as_secs_f64().neg(),
            Self::Positive(d) => d.as_secs_f64(),
            Self::PlusInf => f64::INFINITY,
            Self::MinusInf => f64::NEG_INFINITY,
        }
    }

    pub fn as_micros(&self) -> i128 {
        match self {
            Duration::Negative(d) => i128::try_from(d.as_micros()).unwrap().neg(),
            Duration::Positive(d) => d.as_micros().try_into().unwrap(),
            Duration::PlusInf => i128::MAX,
            Duration::MinusInf => i128::MIN,
        }
    }

    pub fn as_millis(&self) -> i128 {
        match self {
            Duration::Negative(d) => i128::try_from(d.as_millis()).unwrap().neg(),
            Duration::Positive(d) => i128::try_from(d.as_millis()).unwrap(),
            Duration::PlusInf => i128::MAX,
            Duration::MinusInf => i128::MIN,
        }
    }

    pub(crate) fn subsec_nanos(&self) -> u32 {
        match self {
            Duration::PlusInf | Duration::MinusInf => 999999999,
            Duration::Positive(d) | Duration::Negative(d) => d.subsec_nanos(),
        }
    }

    pub(crate) fn saturating_sub(&self, other: Duration) -> Duration {
        let delta = *self - other;
        if delta >= Self::ZERO {
            delta
        } else {
            Self::ZERO
        }
    }
}

#[cfg(test)]
impl Duration {
    pub(crate) fn from_secs_f64(secs: f64) -> Duration {
        if secs == f64::INFINITY {
            Duration::PlusInf
        } else if secs == f64::NEG_INFINITY {
            Duration::MinusInf
        } else if secs >= 0.0 {
            Duration::Positive(std_time::Duration::from_secs_f64(secs))
        } else {
            Duration::Negative(std_time::Duration::from_secs_f64(-secs))
        }
    }
}

impl Instant {
    pub(crate) fn as_exact(&self) -> Self {
        Self::from(self.as_std())
    }

    pub(crate) fn now() -> Self {
        Self::from(std_time::Instant::now())
    }

    pub(crate) fn duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    pub(crate) fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        match (self, earlier) {
            (Instant::Exact(this), Instant::Exact(that)) => {
                this.checked_duration_since(that).map(Into::into)
            }
            _ => None,
        }
    }

    pub(crate) fn saturating_duration_since(&self, earlier: Self) -> Duration {
        let delta = *self - earlier;
        if delta >= Duration::ZERO {
            delta
        } else {
            Duration::ZERO
        }
    }

    pub(crate) fn as_std(&self) -> std_time::Instant {
        match self {
            Instant::DistantPast => BEGINNING_OF_TIME.0,
            Instant::Exact(exact) => *exact,
            Instant::DistantFuture => {
                const YEARS_100: std_time::Duration =
                    std_time::Duration::from_secs(60 * 60 * 24 * 365 * 100);
                static FUTURE: Lazy<std_time::Instant> =
                    Lazy::new(|| std_time::Instant::now() + YEARS_100);
                *FUTURE
            }
        }
    }

    pub(crate) const fn is_finite(&self) -> bool {
        matches!(self, Self::Exact(_))
    }

    pub(crate) const fn is_not_finite(&self) -> bool {
        !self.is_finite()
    }

    pub fn to_unix_duration(self) -> Duration {
        // This is a bit fishy. We "freeze" a moment in time for Instant and SystemTime,
        // so we can make relative comparisons of Instant - Instant and translate that to
        // SystemTime - unix epoch. Hopefully the error is quite small.
        let time_0 = Self::from(BEGINNING_OF_TIME.0);

        if self < time_0 {
            warn!("Time went backwards from beginning_of_time Instant");
        }

        let duration_since_time_0 = self.duration_since(time_0);
        let system_time = BEGINNING_OF_TIME.1 + duration_since_time_0.as_std().unwrap_or_default();

        system_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock to go forwards from unix epoch")
            .into()
    }

    pub fn to_ntp_duration(self) -> Duration {
        self.to_unix_duration() + Duration::from_micros(MICROS_1900)
    }

    pub fn from_ntp_64(v: u64) -> Self {
        // https://tools.ietf.org/html/rfc3550#section-4
        // Wallclock time (absolute date and time) is represented using the
        // timestamp format of the Network Time Protocol (NTP), which is in
        // seconds relative to 0h UTC on 1 January 1900 [4]. The full
        // resolution NTP timestamp is a 64-bit unsigned fixed-point number with
        // the integer part in the first 32 bits and the fractional part in the
        // last 32 bits.
        let secs_ntp = (v as f64) / F32;

        // Shift to UNIX EPOCH
        let secs_epoch = secs_ntp - SECS_1900 as f64;

        // Duration not allowed to be negative
        let secs_dur = if secs_epoch <= 0.0 {
            std_time::Duration::ZERO
        } else {
            std_time::Duration::from_secs_f64(secs_epoch)
        };

        // Time in SystemTime
        let sys = SystemTime::UNIX_EPOCH + secs_dur;

        // Relative duration from our beginning of time.
        let since_beginning_of_time = sys
            .duration_since(BEGINNING_OF_TIME.1)
            .unwrap_or(std_time::Duration::ZERO);

        // Translate relative to Instant
        (BEGINNING_OF_TIME.0 + since_beginning_of_time).into()
    }

    pub fn as_ntp_64(&self) -> u64 {
        let since_beginning_of_time = self.duration_since(BEGINNING_OF_TIME.0.into());

        let since_epoch = since_beginning_of_time + epoch_to_beginning();
        let secs_epoch = since_epoch.as_secs_f64();

        let secs_ntp = secs_epoch + SECS_1900 as f64;

        (secs_ntp * F32) as u64
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        match (self, rhs) {
            (Self::DistantFuture, _) | (_, Duration::PlusInf) => Self::DistantFuture,
            (Self::DistantPast, _) | (_, Duration::MinusInf) => Self::DistantPast,
            (Self::Exact(i), Duration::Negative(d)) => Self::Exact(i - d),
            (Self::Exact(i), Duration::Positive(d)) => Self::Exact(i + d),
        }
    }
}

impl Sub<Duration> for Instant {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        match (self, rhs) {
            (Self::DistantFuture, _) | (_, Duration::MinusInf) => Self::DistantFuture,
            (Self::DistantPast, _) | (_, Duration::PlusInf) => Self::DistantPast,
            (Self::Exact(i), Duration::Negative(d)) => Self::Exact(i + d),
            (Self::Exact(i), Duration::Positive(d)) => Self::Exact(i - d),
        }
    }
}

impl Sub<Self> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::DistantFuture, _) | (_, Self::DistantPast) => Duration::PlusInf,
            (Self::DistantPast, _) | (_, Self::DistantFuture) => Duration::MinusInf,
            (Self::Exact(this), Self::Exact(that)) => match this.cmp(&that) {
                Ordering::Less => Duration::Negative(that - this),
                Ordering::Equal => Duration::ZERO,
                Ordering::Greater => Duration::Positive(this - that),
            },
        }
    }
}

impl Sub<std_time::Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: std_time::Instant) -> Self::Output {
        self.sub(Self::from(rhs))
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl PartialOrd for Instant {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Self::cmp(self, other))
    }
}

impl Ord for Instant {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::DistantPast, Self::DistantPast) => Ordering::Equal,
            (Self::DistantPast, _) => Ordering::Less,
            (_, Self::DistantPast) => Ordering::Greater,
            (Self::DistantFuture, Self::DistantFuture) => Ordering::Equal,
            (Self::DistantFuture, _) => Ordering::Greater,
            (_, Self::DistantFuture) => Ordering::Less,
            (Self::Exact(v1), Self::Exact(v2)) => v1.cmp(v2),
        }
    }
}

impl From<std_time::Instant> for Instant {
    fn from(value: std_time::Instant) -> Self {
        Self::Exact(value)
    }
}

impl Add<Self> for Duration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::PlusInf, _) | (_, Self::PlusInf) => Self::PlusInf,
            (Self::MinusInf, _) | (_, Self::MinusInf) => Self::MinusInf,
            (Self::Negative(this), Self::Negative(that)) => Self::Negative(this + that),
            (Self::Positive(this), Self::Positive(that)) => Self::Positive(this + that),
            (Self::Positive(this), Self::Negative(that)) => match this.cmp(&that) {
                Ordering::Less => Self::Negative(that - this),
                Ordering::Equal => Self::ZERO,
                Ordering::Greater => Self::Positive(this - that),
            },
            (Self::Negative(this), Self::Positive(that)) => match this.cmp(&that) {
                Ordering::Less => Self::Positive(that - this),
                Ordering::Equal => Self::ZERO,
                Ordering::Greater => Self::Negative(this - that),
            },
        }
    }
}

impl Sub<Self> for Duration {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::PlusInf, _) | (_, Self::MinusInf) => Self::PlusInf,
            (Self::MinusInf, _) | (_, Self::PlusInf) => Self::MinusInf,
            (Self::Positive(this), Self::Negative(that)) => Self::Positive(this + that),
            (Self::Negative(this), Self::Positive(that)) => Self::Negative(this + that),
            (Self::Positive(this), Self::Positive(that)) => match this.cmp(&that) {
                Ordering::Less => Self::Negative(that - this),
                Ordering::Equal => Self::ZERO,
                Ordering::Greater => Self::Positive(this - that),
            },
            (Self::Negative(this), Self::Negative(that)) => match this.cmp(&that) {
                Ordering::Less => Self::Positive(that - this),
                Ordering::Equal => Self::ZERO,
                Ordering::Greater => Self::Negative(this - that),
            },
        }
    }
}

impl PartialOrd for Duration {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Self::cmp(self, other))
    }
}

impl Ord for Duration {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::MinusInf, Self::MinusInf) => Ordering::Equal,
            (Self::MinusInf, _) => Ordering::Less,
            (_, Self::MinusInf) => Ordering::Greater,
            (Self::PlusInf, Self::PlusInf) => Ordering::Equal,
            (Self::PlusInf, _) => Ordering::Greater,
            (_, Self::PlusInf) => Ordering::Less,
            (Self::Negative(_), Self::Positive(_)) => Ordering::Less,
            (Self::Positive(_), Self::Negative(_)) => Ordering::Greater,
            (Self::Positive(this), Self::Positive(that)) => this.cmp(that),
            (Self::Negative(this), Self::Negative(that)) => that.cmp(this),
        }
    }
}

impl SubAssign<Self> for Duration {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl AddAssign<Self> for Duration {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Div<u32> for Duration {
    type Output = Self;

    #[inline]
    fn div(self, rhs: u32) -> Self {
        match self {
            Self::Negative(duration) => Self::Negative(duration / rhs),
            Self::Positive(duration) => Self::Positive(duration / rhs),
            Self::MinusInf | Self::PlusInf => self,
        }
    }
}

impl Mul<u32> for Duration {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: u32) -> Self {
        match self {
            Self::Negative(duration) => Self::Negative(duration * rhs),
            Self::Positive(duration) => Self::Positive(duration * rhs),
            Self::MinusInf | Self::PlusInf => self,
        }
    }
}

impl Mul<Duration> for u32 {
    type Output = Duration;

    #[inline]
    fn mul(self, rhs: Duration) -> Duration {
        rhs * self
    }
}

impl Sum for Duration {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|a, b| a + b).unwrap_or_default()
    }
}

impl Default for Duration {
    fn default() -> Self {
        Duration::ZERO
    }
}

impl From<std_time::Duration> for Duration {
    fn from(value: std_time::Duration) -> Self {
        Self::Positive(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn dur_secs(secs: i64) -> Duration {
        if secs >= 0 {
            Duration::Positive(std_time::Duration::from_secs(secs as u64))
        } else {
            Duration::Negative(std_time::Duration::from_secs(-secs as u64))
        }
    }

    #[test]
    fn instant_add_duration() {
        let now = Instant::now();

        assert_eq!(now + dur_secs(5), now + dur_secs(5));
        assert_eq!(now + dur_secs(-5), now - dur_secs(5));
        assert_eq!(now + Duration::MinusInf, Instant::DistantPast);
        assert_eq!(now + Duration::PlusInf, Instant::DistantFuture);

        assert_eq!(Instant::DistantPast + dur_secs(5), Instant::DistantPast);
        assert_eq!(Instant::DistantPast + dur_secs(-5), Instant::DistantPast);
        assert_eq!(
            Instant::DistantPast + Duration::MinusInf,
            Instant::DistantPast
        );
        assert_eq!(
            Instant::DistantPast + Duration::PlusInf,
            Instant::DistantFuture
        );

        assert_eq!(Instant::DistantFuture + dur_secs(5), Instant::DistantFuture);
        assert_eq!(
            Instant::DistantFuture + dur_secs(-5),
            Instant::DistantFuture
        );
        assert_eq!(
            Instant::DistantFuture + Duration::MinusInf,
            Instant::DistantFuture
        );
        assert_eq!(
            Instant::DistantFuture + Duration::PlusInf,
            Instant::DistantFuture
        );
    }

    #[test]
    fn instant_sub_duration() {
        let now = Instant::now();

        assert_eq!(now - dur_secs(5), now - dur_secs(5));
        assert_eq!(now - dur_secs(-5), now + dur_secs(5));
        assert_eq!(now - Duration::MinusInf, Instant::DistantFuture);
        assert_eq!(now - Duration::PlusInf, Instant::DistantPast);

        assert_eq!(Instant::DistantPast - dur_secs(5), Instant::DistantPast);
        assert_eq!(Instant::DistantPast - dur_secs(-5), Instant::DistantPast);
        assert_eq!(
            Instant::DistantPast - Duration::MinusInf,
            Instant::DistantFuture
        );
        assert_eq!(
            Instant::DistantPast - Duration::PlusInf,
            Instant::DistantPast
        );

        assert_eq!(Instant::DistantFuture - dur_secs(5), Instant::DistantFuture);
        assert_eq!(
            Instant::DistantFuture - dur_secs(-5),
            Instant::DistantFuture
        );
        assert_eq!(
            Instant::DistantFuture - Duration::MinusInf,
            Instant::DistantFuture
        );
        assert_eq!(
            Instant::DistantFuture - Duration::PlusInf,
            Instant::DistantFuture
        );
    }

    #[test]
    fn instant_sub_instant() {
        let now = Instant::now();

        assert_eq!(now - now, Duration::ZERO);
        assert_eq!(now - (now - dur_secs(5)), dur_secs(5));
        assert_eq!(now - (now + dur_secs(5)), dur_secs(-5));
        assert_eq!(now - Instant::DistantPast, Duration::PlusInf);
        assert_eq!(now - Instant::DistantFuture, Duration::MinusInf);

        assert_eq!(Instant::DistantPast - now, Duration::MinusInf);
        assert_eq!(
            Instant::DistantPast - (now - dur_secs(5)),
            Duration::MinusInf
        );
        assert_eq!(
            Instant::DistantPast - (now + dur_secs(5)),
            Duration::MinusInf
        );
        assert_eq!(
            Instant::DistantPast - Instant::DistantPast,
            Duration::PlusInf
        );
        assert_eq!(
            Instant::DistantPast - Instant::DistantFuture,
            Duration::MinusInf
        );

        assert_eq!(Instant::DistantFuture - now, Duration::PlusInf);
        assert_eq!(
            Instant::DistantFuture - (now - dur_secs(5)),
            Duration::PlusInf
        );
        assert_eq!(
            Instant::DistantFuture - (now + dur_secs(5)),
            Duration::PlusInf
        );
        assert_eq!(
            Instant::DistantFuture - Instant::DistantPast,
            Duration::PlusInf
        );
        assert_eq!(
            Instant::DistantFuture - Instant::DistantFuture,
            Duration::PlusInf
        );
    }

    #[test]
    fn instant_ord() {
        let now = Instant::now();
        let now_minus_1 = now - dur_secs(1);
        let now_plus_1 = now + dur_secs(1);

        assert!(Instant::DistantFuture > now_plus_1);
        assert!(Instant::DistantFuture > now_minus_1);
        assert!(Instant::DistantFuture > Instant::DistantPast);

        assert!(now_plus_1 > now_minus_1);
        assert!(now_plus_1 > Instant::DistantPast);

        assert!(now_minus_1 > Instant::DistantPast);
    }

    #[test]
    fn duration_ord() {
        assert!(Duration::PlusInf > dur_secs(-2));
        assert!(Duration::PlusInf > dur_secs(2));
        assert!(Duration::PlusInf > Duration::MinusInf);

        assert!(dur_secs(2) > dur_secs(1));
        assert!(dur_secs(2) > dur_secs(-1));
        assert!(dur_secs(2) > dur_secs(-2));
        assert!(dur_secs(2) > Duration::MinusInf);

        assert!(dur_secs(1) > dur_secs(-1));
        assert!(dur_secs(1) > dur_secs(-2));
        assert!(dur_secs(1) > Duration::MinusInf);

        assert!(dur_secs(-1) > dur_secs(-2));
        assert!(dur_secs(-1) > Duration::MinusInf);

        assert!(dur_secs(-2) > Duration::MinusInf);
    }

    #[test]
    fn duration_add() {
        assert_eq!(Duration::PlusInf + Duration::PlusInf, Duration::PlusInf);
        assert_eq!(Duration::PlusInf + Duration::MinusInf, Duration::PlusInf);
        assert_eq!(Duration::PlusInf + dur_secs(-2), Duration::PlusInf);
        assert_eq!(Duration::PlusInf + dur_secs(2), Duration::PlusInf);

        assert_eq!(Duration::MinusInf + Duration::PlusInf, Duration::PlusInf);
        assert_eq!(Duration::MinusInf + Duration::MinusInf, Duration::MinusInf);
        assert_eq!(Duration::MinusInf + dur_secs(-2), Duration::MinusInf);
        assert_eq!(Duration::MinusInf + dur_secs(2), Duration::MinusInf);

        assert_eq!(dur_secs(1) + Duration::PlusInf, Duration::PlusInf);
        assert_eq!(dur_secs(1) + Duration::MinusInf, Duration::MinusInf);
        assert_eq!(dur_secs(1) + dur_secs(-1), Duration::ZERO);
        assert_eq!(dur_secs(1) + dur_secs(-2), dur_secs(-1));
        assert_eq!(dur_secs(1) + dur_secs(2), dur_secs(3));

        assert_eq!(dur_secs(-1) + Duration::PlusInf, Duration::PlusInf);
        assert_eq!(dur_secs(-1) + Duration::MinusInf, Duration::MinusInf);
        assert_eq!(dur_secs(-1) + dur_secs(1), Duration::ZERO);
        assert_eq!(dur_secs(-1) + dur_secs(-2), dur_secs(-3));
        assert_eq!(dur_secs(-1) + dur_secs(2), dur_secs(1));
    }

    #[test]
    fn duration_sub() {
        assert_eq!(Duration::PlusInf - Duration::PlusInf, Duration::PlusInf);
        assert_eq!(Duration::PlusInf - Duration::MinusInf, Duration::PlusInf);
        assert_eq!(Duration::PlusInf - dur_secs(-2), Duration::PlusInf);
        assert_eq!(Duration::PlusInf - dur_secs(2), Duration::PlusInf);

        assert_eq!(Duration::MinusInf - Duration::MinusInf, Duration::PlusInf);
        assert_eq!(Duration::MinusInf - Duration::PlusInf, Duration::MinusInf);
        assert_eq!(Duration::MinusInf - dur_secs(-2), Duration::MinusInf);
        assert_eq!(Duration::MinusInf - dur_secs(2), Duration::MinusInf);

        assert_eq!(dur_secs(1) - Duration::MinusInf, Duration::PlusInf);
        assert_eq!(dur_secs(1) - Duration::PlusInf, Duration::MinusInf);
        assert_eq!(dur_secs(1) - dur_secs(1), Duration::ZERO);
        assert_eq!(dur_secs(1) - dur_secs(-1), dur_secs(2));
        assert_eq!(dur_secs(1) - dur_secs(2), dur_secs(-1));

        assert_eq!(dur_secs(-1) - Duration::MinusInf, Duration::PlusInf);
        assert_eq!(dur_secs(-1) - Duration::PlusInf, Duration::MinusInf);
        assert_eq!(dur_secs(-1) - dur_secs(-1), Duration::ZERO);
        assert_eq!(dur_secs(-1) - dur_secs(1), dur_secs(-2));
        assert_eq!(dur_secs(-1) - dur_secs(2), dur_secs(-3));
    }

    #[test]
    fn super_instant_test() {
        let mut past = Instant::DistantPast;
        let mut future = Instant::DistantFuture;
        let now = Instant::now();
        assert!(past < now);
        assert!(now > past);

        assert!(now < future);
        assert!(future > now);

        assert!(past < future);
        assert!(future > past);

        assert!(now == now);
        assert!(past == past);
        assert!(future == future);

        assert!(now != past);
        assert!(now != future);
        assert!(future != past);

        assert!(past - dur_secs(1) == past);
        past -= dur_secs(1);
        assert!(past == past);
        past += dur_secs(1);
        assert!(past == past);

        assert!(future + dur_secs(1) == future);
        assert!(future - dur_secs(1) == future);
        future -= dur_secs(1);
        assert!(future == future);
        future += dur_secs(1);
        assert!(future == future);
    }

    #[test]
    fn not_happening_works() {
        assert_eq!(Instant::DistantFuture, Instant::DistantFuture);
        assert!(Instant::now() < Instant::DistantFuture);
    }

    #[test]
    fn already_happened_works() {
        assert_eq!(Instant::DistantPast, Instant::DistantPast);
        assert!(Instant::now() > Instant::DistantPast);
    }

    #[test]
    fn already_happened_ne() {
        assert_ne!(Instant::DistantFuture, Instant::DistantPast)
    }

    #[test]
    fn ntp_64_from_to() {
        let now = Instant::now();
        let ntp = now.as_ntp_64();
        let now2 = Instant::from_ntp_64(ntp);
        let abs = if now > now2 { now - now2 } else { now2 - now };
        assert!(abs < Duration::from_millis(1));
    }

    #[test]
    fn from_ntp_64() {
        Instant::from_ntp_64(0);
    }
}
