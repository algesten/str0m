use std::time::SystemTime;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

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
static BEGINNING_OF_TIME: Lazy<(Instant, SystemTime)> = Lazy::new(|| {
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
    BEGINNING_OF_TIME.0
}

pub trait InstantExt {
    /// Convert an Instant to a Duration for unix time.
    ///
    /// First ever time must be "now".
    ///
    /// panics if `time` goes backwards, i.e. we use this for one Instant and then an earlier Instant.
    fn to_unix_duration(&self) -> Duration;

    /// Convert an Instant to a Duration for ntp time.
    fn to_ntp_duration(&self) -> Duration;
}

impl InstantExt for Instant {
    fn to_unix_duration(&self) -> Duration {
        // This is a bit fishy. We "freeze" a moment in time for Instant and SystemTime,
        // so we can make relative comparisons of Instant - Instant and translate that to
        // SystemTime - unix epoch. Hopefully the error is quite small.
        if *self < BEGINNING_OF_TIME.0 {
            warn!("Time went backwards from beginning_of_time Instant");
        }

        let duration_since_time_0 = self.duration_since(BEGINNING_OF_TIME.0);
        let system_time = BEGINNING_OF_TIME.1 + duration_since_time_0;

        system_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock to go forwards from unix epoch")
    }

    fn to_ntp_duration(&self) -> Duration {
        // RTP spec "wallclock" uses NTP time, which starts at 1900-01-01.
        //
        // https://tools.ietf.org/html/rfc868
        //
        // 365 days * 70 years + 17 leap year days
        // (365 * 70 + 17) * 86400 = 2208988800
        const MICROS_1900: Duration = Duration::from_micros(2_208_988_800 * 1_000_000 as u64);

        self.to_unix_duration() + MICROS_1900
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
