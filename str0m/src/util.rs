use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

pub fn not_happening() -> Instant {
    const YEARS_100: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 100);
    static FUTURE: Lazy<Instant> = Lazy::new(|| Instant::now() + YEARS_100);
    *FUTURE
}

pub fn already_happened() -> Instant {
    const HOURS_1: Duration = Duration::from_secs(60);
    static PAST: Lazy<Instant> = Lazy::new(|| Instant::now() - HOURS_1);
    *PAST
}

pub trait Soonest {
    fn soonest(self, other: Self) -> Self;
}

impl Soonest for (Option<Instant>, &'static str) {
    fn soonest(self, other: Self) -> Self {
        match (self, other) {
            ((Some(v1), s1), (Some(v2), s2)) => {
                if v1 < v2 {
                    (Some(v1), s1)
                } else {
                    (Some(v2), s2)
                }
            }
            ((None, _), (None, _)) => (None, ""),
            ((None, _), (v, s)) => (v, s),
            ((v, s), (None, _)) => (v, s),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn not_happening_works() {
        assert_eq!(not_happening(), not_happening());
        assert!(Instant::now() < not_happening());
    }

    #[test]
    fn already_happened_works() {
        assert_eq!(already_happened(), already_happened());
        assert!(Instant::now() > already_happened());
    }

    #[test]
    fn already_happened_ne() {
        assert_ne!(not_happening(), already_happened())
    }
}
