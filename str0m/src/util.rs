use std::time::{Duration, Instant};

pub fn not_happening() -> Instant {
    Instant::now() + Duration::from_secs(60 * 60 * 24 * 365 * 100)
}

pub fn already_happened() -> Instant {
    let now = Instant::now();
    let dur = now - now;
    now - dur
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
