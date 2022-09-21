use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

pub fn not_happening() -> Instant {
    const YEARS_100: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 100);
    static FUTURE: Lazy<Instant> = Lazy::new(|| Instant::now() + YEARS_100);
    *FUTURE
}

pub fn already_happened() -> Instant {
    const HOURS_24: Duration = Duration::from_secs(60 * 60);
    static PAST: Lazy<Instant> = Lazy::new(|| Instant::now() - HOURS_24);
    *PAST
}

pub trait Soonest {
    fn soonest(self, other: Self) -> Self;
}

impl Soonest for Option<Instant> {
    fn soonest(self, other: Self) -> Self {
        match (self, other) {
            (Some(v1), Some(v2)) => {
                if v1 < v2 {
                    Some(v1)
                } else {
                    Some(v2)
                }
            }
            (None, None) => None,
            (None, v) => v,
            (v, None) => v,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn absolute_times() {
        assert_eq!(not_happening(), not_happening());
        assert!(Instant::now() < not_happening());
        assert_eq!(already_happened(), already_happened());
        assert!(Instant::now() > already_happened());
        assert_ne!(not_happening(), already_happened())
    }
}
