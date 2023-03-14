use std::{
    ops::{Add, AddAssign, Deref, Sub, SubAssign},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

/// This is created to ease the modeling of values that represent a moment
/// that is far in the future or in the past, yet allowing PartialEq, Ord, Add,
/// "transparently".
//
// Before doing this, a workaround like Optional<Instant> was considered,
// but it would not clarify whether the absence of a value would be considered
// as a distant past or distant future and it would have to be handled on a
// case-by-case basis.
pub(crate) enum SuperInstant {
    DistantPast,
    Value { instant: Instant },
    DistantFuture,
}

impl SuperInstant {
    pub fn now() -> Self {
        Self::Value {
            instant: Instant::now(),
        }
    }

    pub fn is_finite(&self) -> bool {
        match self {
            Self::DistantPast | Self::DistantFuture => false,
            Self::Value { .. } => true,
        }
    }

    pub fn as_instant(&self) -> Option<Instant> {
        match self {
            Self::DistantPast | Self::DistantFuture => None,
            Self::Value { instant } => Some(*instant),
        }
    }
}

impl PartialOrd for SuperInstant {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (Self::DistantPast, Self::DistantPast) => Some(std::cmp::Ordering::Equal),
            (Self::DistantPast, _) => Some(std::cmp::Ordering::Less),
            (_, Self::DistantPast) => Some(std::cmp::Ordering::Greater),
            (Self::DistantFuture, Self::DistantFuture) => Some(std::cmp::Ordering::Equal),
            (Self::DistantFuture, _) => Some(std::cmp::Ordering::Greater),
            (_, Self::DistantFuture) => Some(std::cmp::Ordering::Less),
            (Self::Value { instant: a }, Self::Value { instant: b }) => a.partial_cmp(b),
        }
    }
}

impl Sub<Duration> for SuperInstant {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        match self {
            Self::DistantPast => Self::DistantPast,
            Self::DistantFuture => Self::DistantFuture,
            Self::Value { instant } => Self::Value {
                instant: instant - rhs,
            },
        }
    }
}

impl SubAssign<Duration> for SuperInstant {
    fn sub_assign(&mut self, rhs: Duration) {
        match self {
            Self::DistantPast => {}
            Self::DistantFuture => {}
            Self::Value { instant } => *instant -= rhs,
        }
    }
}

impl AddAssign<Duration> for SuperInstant {
    fn add_assign(&mut self, rhs: Duration) {
        match self {
            Self::DistantPast => {}
            Self::DistantFuture => {}
            Self::Value { instant } => *instant += rhs,
        }
    }
}

impl Add<Duration> for SuperInstant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        match self {
            Self::DistantPast => Self::DistantPast,
            Self::DistantFuture => Self::DistantFuture,
            Self::Value { instant } => Self::Value {
                instant: instant + rhs,
            },
        }
    }
}

impl From<Instant> for SuperInstant {
    fn from(instant: Instant) -> Self {
        Self::Value { instant }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use crate::packet::bwe::super_instant::SuperInstant;

    #[test]
    fn test() {
        let mut past = SuperInstant::DistantPast;
        let mut future = SuperInstant::DistantFuture;
        let now = SuperInstant::now();
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
