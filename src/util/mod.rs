use std::time::SystemTime;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

mod bit_pattern;

pub(crate) use bit_pattern::BitPattern;

pub(crate) mod value_history;

pub(crate) fn not_happening() -> Instant {
    const YEARS_100: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 100);
    static FUTURE: Lazy<Instant> = Lazy::new(|| Instant::now() + YEARS_100);
    *FUTURE
}

// The goal here is to make a constant "beginning of time" in both Instant and SystemTime
// that we can use as relative values for the rest of str0m.
// This is indeed a bit dodgy, but we want str0m's internal idea of time to be completely
// driven from the external API using `Instant`. What works against us is that Instant can't
// represent things like UNIX EPOCH (but SystemTime can).
const HOURS_1: Duration = Duration::from_secs(60);
static PAST: Lazy<(Instant, SystemTime)> = Lazy::new(|| {
    // These two should be "frozen" the same instant. Hopefully they are not differing too much.
    let now = Instant::now();
    let now_sys = SystemTime::now();

    let beginning_of_time = now.checked_sub(HOURS_1).unwrap();
    // This might be less than 1 hour if the machine uptime is less.
    let since_beginning_of_time = Instant::now() - beginning_of_time;

    let beginning_of_time_sys = now_sys - since_beginning_of_time;

    // This pair represents our "beginning of time" for the same moment.
    (beginning_of_time, beginning_of_time_sys)
});

pub(crate) fn already_happened() -> Instant {
    PAST.0
}

pub(crate) trait Soonest {
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

/// Calculate the round trip time for a given peer as described in
/// [RFC3550 6.4.1](https://datatracker.ietf.org/doc/html/rfc3550#section-6.4.1).
///
/// ## Params
/// - `ntp_time` the offset since 1900-01-01.
/// - `delay` the delay(`DLSR`) since last sender report expressed as fractions of a second in 32 bits.
/// - `last_report` the middle 32 bits of an NTP timestamp for the most recent sender report(LSR) or Receiver Report(LRR).
pub(crate) fn calculate_rtt_ms(ntp_time: Duration, delay: u32, last_report: u32) -> Option<f32> {
    // [10 Nov 1995 11:33:25.125 UTC]       [10 Nov 1995 11:33:36.5 UTC]
    // n                 SR(n)              A=b710:8000 (46864.500 s)
    // ---------------------------------------------------------------->
    //                    v                 ^
    // ntp_sec =0xb44db705 v               ^ dlsr=0x0005:4000 (    5.250s)
    // ntp_frac=0x20000000  v             ^  lsr =0xb705:2000 (46853.125s)
    //   (3024992005.125 s)  v           ^
    // r                      v         ^ RR(n)
    // ---------------------------------------------------------------->
    //                        |<-DLSR->|
    //                         (5.250 s)
    //
    // A     0xb710:8000 (46864.500 s)
    // DLSR -0x0005:4000 (    5.250 s)
    // LSR  -0xb705:2000 (46853.125 s)
    // -------------------------------
    // delay 0x0006:2000 (    6.125 s)

    // - we want the current middle 32 bits of an NTP timestamp for the current time.
    // We treat the seconds separately to the fractions.
    // [32 bit seconds].[32 bit fractions]
    //         [16 bit].[16 bit]

    let now_secs = ntp_time.as_secs();
    let now_fract_ns = ntp_time.subsec_nanos() as u64;
    let now_fract = ((now_fract_ns * u32::MAX as u64) / 1_000_000_000) as u32;

    // Combine the final 2x16 bits together.
    let now = (now_secs as u32) << 16 | (now_fract >> 16);

    let rtt = now.checked_sub(delay)?.checked_sub(last_report)?;
    let rtt_seconds = rtt >> 16;
    let rtt_fraction = (rtt & (u16::MAX as u32)) as f32 / (u16::MAX as u32) as f32;

    Some(rtt_seconds as f32 * 1000.0 + rtt_fraction * 1000.0)
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
