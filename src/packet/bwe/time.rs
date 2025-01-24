use std::cmp::Ordering;
use std::ops::{Add, AddAssign, Div, Neg as _, Sub, SubAssign};
use std::time::{Duration, Instant};

use crate::bwe::Bitrate;
use crate::rtp_::DataSize;

/// Wrapper for [`Instant`] that provides additional time points in the past or future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SuperInstant {
    /// A time in the past that already happened.
    DistantPast,

    /// An exact instant.
    Exact(Instant),

    /// A time in the future that will never happen.
    DistantFuture,
}

/// Wrapper for [`Duration`] that can be negative and provides a duration to a
/// distant future or past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TimeDelta {
    /// Time delta to some event in distant past that already happened.
    MinusInf,

    /// An exact negative duration.
    Negative(Duration),

    /// An exact positive duration.
    Positive(Duration),

    /// Time delta to some event in distant future that will never happen.
    PlusInf,
}

impl TimeDelta {
    pub(super) const ZERO: Self = Self::Positive(Duration::ZERO);

    /// Returns the number of seconds contained by this [`TimeDelta`] as `f64`.
    pub fn as_secs_f64(&self) -> f64 {
        match self {
            Self::Negative(d) => d.as_secs_f64().neg(),
            Self::Positive(d) => d.as_secs_f64(),
            Self::PlusInf => f64::INFINITY,
            Self::MinusInf => f64::NEG_INFINITY,
        }
    }
}

#[cfg(test)]
impl TimeDelta {
    /// Creates a [`TimeDelta`] from seconds.
    pub const fn from_secs(secs: i64) -> TimeDelta {
        if secs >= 0 {
            Self::Positive(Duration::from_secs(secs as u64))
        } else {
            Self::Negative(Duration::from_secs(-secs as u64))
        }
    }

    /// Creates a [`TimeDelta`] from milliseconds.
    pub const fn from_millis(millis: i64) -> Self {
        if millis >= 0 {
            Self::Positive(Duration::from_millis(millis as u64))
        } else {
            Self::Negative(Duration::from_millis(-millis as u64))
        }
    }
}

impl SuperInstant {
    /// Indicates whether this [`SuperInstant`] is [`SuperInstant::Exact`].
    pub const fn is_finite(&self) -> bool {
        matches!(self, Self::Exact(_))
    }

    /// Indicates whether this [`SuperInstant`] is [`SuperInstant::DistantPast`]
    /// or [`SuperInstant::DistantFuture`].
    pub const fn is_not_finite(&self) -> bool {
        !self.is_finite()
    }
}

impl Add<TimeDelta> for SuperInstant {
    type Output = Self;

    fn add(self, rhs: TimeDelta) -> Self::Output {
        match (self, rhs) {
            (Self::DistantFuture, _) | (_, TimeDelta::PlusInf) => Self::DistantFuture,
            (Self::DistantPast, _) | (_, TimeDelta::MinusInf) => Self::DistantPast,
            (Self::Exact(i), TimeDelta::Negative(d)) => Self::Exact(i - d),
            (Self::Exact(i), TimeDelta::Positive(d)) => Self::Exact(i + d),
        }
    }
}

impl Sub<TimeDelta> for SuperInstant {
    type Output = Self;

    fn sub(self, rhs: TimeDelta) -> Self::Output {
        match (self, rhs) {
            (Self::DistantFuture, _) | (_, TimeDelta::MinusInf) => Self::DistantFuture,
            (Self::DistantPast, _) | (_, TimeDelta::PlusInf) => Self::DistantPast,
            (Self::Exact(i), TimeDelta::Negative(d)) => Self::Exact(i + d),
            (Self::Exact(i), TimeDelta::Positive(d)) => Self::Exact(i - d),
        }
    }
}

impl Sub<Self> for SuperInstant {
    type Output = TimeDelta;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::DistantFuture, _) | (_, Self::DistantPast) => TimeDelta::PlusInf,
            (Self::DistantPast, _) | (_, Self::DistantFuture) => TimeDelta::MinusInf,
            (Self::Exact(this), Self::Exact(that)) => match this.cmp(&that) {
                Ordering::Less => TimeDelta::Negative(that - this),
                Ordering::Equal => TimeDelta::ZERO,
                Ordering::Greater => TimeDelta::Positive(this - that),
            },
        }
    }
}

impl Add<Duration> for SuperInstant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        self + TimeDelta::from(rhs)
    }
}

impl Sub<Duration> for SuperInstant {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        self - TimeDelta::from(rhs)
    }
}

impl Sub<Instant> for SuperInstant {
    type Output = TimeDelta;

    fn sub(self, rhs: Instant) -> Self::Output {
        self.sub(Self::from(rhs))
    }
}

impl SubAssign<TimeDelta> for SuperInstant {
    fn sub_assign(&mut self, rhs: TimeDelta) {
        *self = *self - rhs;
    }
}

impl AddAssign<TimeDelta> for SuperInstant {
    fn add_assign(&mut self, rhs: TimeDelta) {
        *self = *self + rhs;
    }
}

impl SubAssign<Duration> for SuperInstant {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl AddAssign<Duration> for SuperInstant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl PartialOrd for SuperInstant {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Self::cmp(self, other))
    }
}

impl Ord for SuperInstant {
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

impl From<Instant> for SuperInstant {
    fn from(value: Instant) -> Self {
        Self::Exact(value)
    }
}

impl Add<Self> for TimeDelta {
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

impl Sub<Self> for TimeDelta {
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

impl PartialOrd for TimeDelta {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Self::cmp(self, other))
    }
}

impl Ord for TimeDelta {
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

impl PartialEq<Duration> for TimeDelta {
    fn eq(&self, other: &Duration) -> bool {
        *self == Self::from(*other)
    }
}

impl PartialOrd<Duration> for TimeDelta {
    fn partial_cmp(&self, other: &Duration) -> Option<Ordering> {
        Some(Self::cmp(self, &Self::from(*other)))
    }
}

impl SubAssign<Self> for TimeDelta {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl AddAssign<Self> for TimeDelta {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Div<u32> for TimeDelta {
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

impl From<Duration> for TimeDelta {
    fn from(value: Duration) -> Self {
        Self::Positive(value)
    }
}

impl Div<TimeDelta> for DataSize {
    type Output = Bitrate;

    fn div(self, rhs: TimeDelta) -> Self::Output {
        let bytes = self.as_bytes_f64();
        let s = rhs.as_secs_f64();

        if s == 0.0 {
            return Bitrate::ZERO;
        }

        let bps = (bytes * 8.0) / s;

        bps.into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn instant_add_duration() {
        let now = Instant::now();

        assert_eq!(
            SuperInstant::Exact(now) + TimeDelta::from_secs(5),
            SuperInstant::from(now + Duration::from_secs(5))
        );
        assert_eq!(
            SuperInstant::Exact(now) + TimeDelta::from_secs(-5),
            SuperInstant::from(now - Duration::from_secs(5))
        );
        assert_eq!(
            SuperInstant::Exact(now) + TimeDelta::MinusInf,
            SuperInstant::DistantPast
        );
        assert_eq!(
            SuperInstant::Exact(now) + TimeDelta::PlusInf,
            SuperInstant::DistantFuture
        );

        assert_eq!(
            SuperInstant::DistantPast + TimeDelta::from_secs(5),
            SuperInstant::DistantPast
        );
        assert_eq!(
            SuperInstant::DistantPast + TimeDelta::from_secs(-5),
            SuperInstant::DistantPast
        );
        assert_eq!(
            SuperInstant::DistantPast + TimeDelta::MinusInf,
            SuperInstant::DistantPast
        );
        assert_eq!(
            SuperInstant::DistantPast + TimeDelta::PlusInf,
            SuperInstant::DistantFuture
        );

        assert_eq!(
            SuperInstant::DistantFuture + TimeDelta::from_secs(5),
            SuperInstant::DistantFuture
        );
        assert_eq!(
            SuperInstant::DistantFuture + TimeDelta::from_secs(-5),
            SuperInstant::DistantFuture
        );
        assert_eq!(
            SuperInstant::DistantFuture + TimeDelta::MinusInf,
            SuperInstant::DistantFuture
        );
        assert_eq!(
            SuperInstant::DistantFuture + TimeDelta::PlusInf,
            SuperInstant::DistantFuture
        );
    }

    #[test]
    fn instant_sub_duration() {
        let now = Instant::now();

        assert_eq!(
            SuperInstant::Exact(now) - TimeDelta::from_secs(5),
            SuperInstant::from(now - Duration::from_secs(5))
        );
        assert_eq!(
            SuperInstant::Exact(now) - TimeDelta::from_secs(-5),
            SuperInstant::from(now + Duration::from_secs(5))
        );
        assert_eq!(
            SuperInstant::Exact(now) - TimeDelta::MinusInf,
            SuperInstant::DistantFuture
        );
        assert_eq!(
            SuperInstant::Exact(now) - TimeDelta::PlusInf,
            SuperInstant::DistantPast
        );

        assert_eq!(
            SuperInstant::DistantPast - TimeDelta::from_secs(5),
            SuperInstant::DistantPast
        );
        assert_eq!(
            SuperInstant::DistantPast - TimeDelta::from_secs(-5),
            SuperInstant::DistantPast
        );
        assert_eq!(
            SuperInstant::DistantPast - TimeDelta::MinusInf,
            SuperInstant::DistantFuture
        );
        assert_eq!(
            SuperInstant::DistantPast - TimeDelta::PlusInf,
            SuperInstant::DistantPast
        );

        assert_eq!(
            SuperInstant::DistantFuture - TimeDelta::from_secs(5),
            SuperInstant::DistantFuture
        );
        assert_eq!(
            SuperInstant::DistantFuture - TimeDelta::from_secs(-5),
            SuperInstant::DistantFuture
        );
        assert_eq!(
            SuperInstant::DistantFuture - TimeDelta::MinusInf,
            SuperInstant::DistantFuture
        );
        assert_eq!(
            SuperInstant::DistantFuture - TimeDelta::PlusInf,
            SuperInstant::DistantFuture
        );
    }

    #[test]
    fn instant_sub_instant() {
        let now = Instant::now();

        assert_eq!(
            SuperInstant::Exact(now) - SuperInstant::Exact(now),
            TimeDelta::ZERO
        );
        assert_eq!(
            SuperInstant::Exact(now) - SuperInstant::Exact(now - Duration::from_secs(5)),
            TimeDelta::from_secs(5)
        );
        assert_eq!(
            SuperInstant::Exact(now) - SuperInstant::Exact(now + Duration::from_secs(5)),
            TimeDelta::from_secs(-5)
        );
        assert_eq!(
            SuperInstant::Exact(now) - SuperInstant::DistantPast,
            TimeDelta::PlusInf
        );
        assert_eq!(
            SuperInstant::Exact(now) - SuperInstant::DistantFuture,
            TimeDelta::MinusInf
        );

        assert_eq!(
            SuperInstant::DistantPast - SuperInstant::Exact(now),
            TimeDelta::MinusInf
        );
        assert_eq!(
            SuperInstant::DistantPast - SuperInstant::Exact(now - Duration::from_secs(5)),
            TimeDelta::MinusInf
        );
        assert_eq!(
            SuperInstant::DistantPast - SuperInstant::Exact(now + Duration::from_secs(5)),
            TimeDelta::MinusInf
        );
        assert_eq!(
            SuperInstant::DistantPast - SuperInstant::DistantPast,
            TimeDelta::PlusInf
        );
        assert_eq!(
            SuperInstant::DistantPast - SuperInstant::DistantFuture,
            TimeDelta::MinusInf
        );

        assert_eq!(
            SuperInstant::DistantFuture - SuperInstant::Exact(now),
            TimeDelta::PlusInf
        );
        assert_eq!(
            SuperInstant::DistantFuture - SuperInstant::Exact(now - Duration::from_secs(5)),
            TimeDelta::PlusInf
        );
        assert_eq!(
            SuperInstant::DistantFuture - SuperInstant::Exact(now + Duration::from_secs(5)),
            TimeDelta::PlusInf
        );
        assert_eq!(
            SuperInstant::DistantFuture - SuperInstant::DistantPast,
            TimeDelta::PlusInf
        );
        assert_eq!(
            SuperInstant::DistantFuture - SuperInstant::DistantFuture,
            TimeDelta::PlusInf
        );
    }

    #[test]
    fn instant_ord() {
        let now = SuperInstant::Exact(Instant::now());
        let now_minus_1 = now - TimeDelta::from_secs(1);
        let now_plus_1 = now + TimeDelta::from_secs(1);

        assert!(SuperInstant::DistantFuture > now_plus_1);
        assert!(SuperInstant::DistantFuture > now_minus_1);
        assert!(SuperInstant::DistantFuture > SuperInstant::DistantPast);

        assert!(now_plus_1 > now_minus_1);
        assert!(now_plus_1 > SuperInstant::DistantPast);

        assert!(now_minus_1 > SuperInstant::DistantPast);
    }

    #[test]
    fn duration_ord() {
        assert!(TimeDelta::PlusInf > TimeDelta::from_secs(-2));
        assert!(TimeDelta::PlusInf > TimeDelta::from_secs(2));
        assert!(TimeDelta::PlusInf > TimeDelta::MinusInf);

        assert!(TimeDelta::from_secs(2) > TimeDelta::from_secs(1));
        assert!(TimeDelta::from_secs(2) > TimeDelta::from_secs(-1));
        assert!(TimeDelta::from_secs(2) > TimeDelta::from_secs(-2));
        assert!(TimeDelta::from_secs(2) > TimeDelta::MinusInf);

        assert!(TimeDelta::from_secs(1) > TimeDelta::from_secs(-1));
        assert!(TimeDelta::from_secs(1) > TimeDelta::from_secs(-2));
        assert!(TimeDelta::from_secs(1) > TimeDelta::MinusInf);

        assert!(TimeDelta::from_secs(-1) > TimeDelta::from_secs(-2));
        assert!(TimeDelta::from_secs(-1) > TimeDelta::MinusInf);

        assert!(TimeDelta::from_secs(-2) > TimeDelta::MinusInf);

        assert_eq!(TimeDelta::from_secs(1), Duration::from_secs(1));
        assert!(TimeDelta::from_secs(2) > Duration::from_secs(1));
        assert!(TimeDelta::from_secs(1) < Duration::from_secs(2));
        assert!(TimeDelta::from_secs(-1) < Duration::ZERO);
        assert!(TimeDelta::from_secs(-1) < Duration::from_secs(1));
        assert!(TimeDelta::PlusInf > Duration::from_secs(2));
        assert!(TimeDelta::MinusInf < Duration::from_secs(1));
        assert!(TimeDelta::MinusInf < Duration::ZERO);
    }

    #[test]
    fn duration_add() {
        assert_eq!(TimeDelta::PlusInf + TimeDelta::PlusInf, TimeDelta::PlusInf);
        assert_eq!(TimeDelta::PlusInf + TimeDelta::MinusInf, TimeDelta::PlusInf);
        assert_eq!(
            TimeDelta::PlusInf + TimeDelta::from_secs(-2),
            TimeDelta::PlusInf
        );
        assert_eq!(
            TimeDelta::PlusInf + TimeDelta::from_secs(2),
            TimeDelta::PlusInf
        );

        assert_eq!(TimeDelta::MinusInf + TimeDelta::PlusInf, TimeDelta::PlusInf);
        assert_eq!(
            TimeDelta::MinusInf + TimeDelta::MinusInf,
            TimeDelta::MinusInf
        );
        assert_eq!(
            TimeDelta::MinusInf + TimeDelta::from_secs(-2),
            TimeDelta::MinusInf
        );
        assert_eq!(
            TimeDelta::MinusInf + TimeDelta::from_secs(2),
            TimeDelta::MinusInf
        );

        assert_eq!(
            TimeDelta::from_secs(1) + TimeDelta::PlusInf,
            TimeDelta::PlusInf
        );
        assert_eq!(
            TimeDelta::from_secs(1) + TimeDelta::MinusInf,
            TimeDelta::MinusInf
        );
        assert_eq!(
            TimeDelta::from_secs(1) + TimeDelta::from_secs(-1),
            TimeDelta::ZERO
        );
        assert_eq!(
            TimeDelta::from_secs(1) + TimeDelta::from_secs(-2),
            TimeDelta::from_secs(-1)
        );
        assert_eq!(
            TimeDelta::from_secs(1) + TimeDelta::from_secs(2),
            TimeDelta::from_secs(3)
        );

        assert_eq!(
            TimeDelta::from_secs(-1) + TimeDelta::PlusInf,
            TimeDelta::PlusInf
        );
        assert_eq!(
            TimeDelta::from_secs(-1) + TimeDelta::MinusInf,
            TimeDelta::MinusInf
        );
        assert_eq!(
            TimeDelta::from_secs(-1) + TimeDelta::from_secs(1),
            TimeDelta::ZERO
        );
        assert_eq!(
            TimeDelta::from_secs(-1) + TimeDelta::from_secs(-2),
            TimeDelta::from_secs(-3)
        );
        assert_eq!(
            TimeDelta::from_secs(-1) + TimeDelta::from_secs(2),
            TimeDelta::from_secs(1)
        );
    }

    #[test]
    fn duration_sub() {
        assert_eq!(TimeDelta::PlusInf - TimeDelta::PlusInf, TimeDelta::PlusInf);
        assert_eq!(TimeDelta::PlusInf - TimeDelta::MinusInf, TimeDelta::PlusInf);
        assert_eq!(
            TimeDelta::PlusInf - TimeDelta::from_secs(-2),
            TimeDelta::PlusInf
        );
        assert_eq!(
            TimeDelta::PlusInf - TimeDelta::from_secs(2),
            TimeDelta::PlusInf
        );

        assert_eq!(
            TimeDelta::MinusInf - TimeDelta::MinusInf,
            TimeDelta::PlusInf
        );
        assert_eq!(
            TimeDelta::MinusInf - TimeDelta::PlusInf,
            TimeDelta::MinusInf
        );
        assert_eq!(
            TimeDelta::MinusInf - TimeDelta::from_secs(-2),
            TimeDelta::MinusInf
        );
        assert_eq!(
            TimeDelta::MinusInf - TimeDelta::from_secs(2),
            TimeDelta::MinusInf
        );

        assert_eq!(
            TimeDelta::from_secs(1) - TimeDelta::MinusInf,
            TimeDelta::PlusInf
        );
        assert_eq!(
            TimeDelta::from_secs(1) - TimeDelta::PlusInf,
            TimeDelta::MinusInf
        );
        assert_eq!(
            TimeDelta::from_secs(1) - TimeDelta::from_secs(1),
            TimeDelta::ZERO
        );
        assert_eq!(
            TimeDelta::from_secs(1) - TimeDelta::from_secs(-1),
            TimeDelta::from_secs(2)
        );
        assert_eq!(
            TimeDelta::from_secs(1) - TimeDelta::from_secs(2),
            TimeDelta::from_secs(-1)
        );

        assert_eq!(
            TimeDelta::from_secs(-1) - TimeDelta::MinusInf,
            TimeDelta::PlusInf
        );
        assert_eq!(
            TimeDelta::from_secs(-1) - TimeDelta::PlusInf,
            TimeDelta::MinusInf
        );
        assert_eq!(
            TimeDelta::from_secs(-1) - TimeDelta::from_secs(-1),
            TimeDelta::ZERO
        );
        assert_eq!(
            TimeDelta::from_secs(-1) - TimeDelta::from_secs(1),
            TimeDelta::from_secs(-2)
        );
        assert_eq!(
            TimeDelta::from_secs(-1) - TimeDelta::from_secs(2),
            TimeDelta::from_secs(-3)
        );
    }

    #[test]
    fn super_instant_test() {
        let mut past = SuperInstant::DistantPast;
        let mut future = SuperInstant::DistantFuture;
        let now = SuperInstant::Exact(Instant::now());
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

        assert!(past - Duration::from_secs(1) == past);
        past -= Duration::from_secs(1);
        assert!(past == past);
        past += Duration::from_secs(1);
        assert!(past == past);

        assert!(future + Duration::from_secs(1) == future);
        assert!(future - Duration::from_secs(1) == future);
        future -= Duration::from_secs(1);
        assert!(future == future);
        future += Duration::from_secs(1);
        assert!(future == future);
    }
}
