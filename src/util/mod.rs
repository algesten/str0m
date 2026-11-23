use std::time::{Duration, Instant};

mod bit_pattern;

pub(crate) use bit_pattern::BitPattern;

pub(crate) mod value_history;

mod time_tricks;
pub(crate) use time_tricks::{InstantExt, SystemTimeExt, not_happening};
pub(crate) use time_tricks::{already_happened, epoch_to_beginning};

mod average;
pub(crate) use average::MovingAverage;

pub(crate) trait Soonest {
    fn soonest(self, other: Self) -> Self;
}

impl<T: Default> Soonest for (Option<Instant>, T) {
    fn soonest(self, other: Self) -> Self {
        match (self, other) {
            ((Some(v1), s1), (Some(v2), s2)) => {
                if v1 < v2 {
                    (Some(v1), s1)
                } else {
                    (Some(v2), s2)
                }
            }
            ((None, _), (None, _)) => (None, T::default()),
            ((None, _), (v, s)) => (v, s),
            ((v, s), (None, _)) => (v, s),
        }
    }
}

/// Compact NTP timestamps (RFC 3550 section 4) are 16.16 fixed point seconds, so one unit
/// is 1/65536 s (about 15.26 µs).
const COMPACT_NTP_FRACTION_BITS: u32 = 16;

/// How far below zero, in compact NTP units, a raw RTT may fall and still be attributed to
/// quantization rather than bad data.
///
/// `A`, `LSR` and `DLSR` are each quantized to whole units. `A` and `LSR` are always truncated.
/// If the peer also truncates `DLSR`, as str0m does, the raw result is less than one unit below
/// the true RTT; a peer that rounds `DLSR` to nearest adds up to half a unit more. Either way,
/// quantization alone never takes a valid sample below -1. The second unit is margin for the
/// `f64` conversion that produces our SR timestamp (well under one unit) and for the peer's
/// clock running at a slightly different rate while it measures `DLSR`.
const RTT_ROUNDING_TOLERANCE: i32 = 2;

/// Largest raw RTT, in compact NTP units, accepted as a real measurement (60 s).
///
/// This is far above any real network round trip, including satellite links and heavily
/// buffered paths. Larger values come from a stale or corrupted `LSR` or a peer that fills
/// `DLSR` incorrectly, and would otherwise be reported as RTTs of minutes to hours.
const MAX_PLAUSIBLE_RTT: i32 = 60 << COMPACT_NTP_FRACTION_BITS;

/// Calculate the round trip time for a given peer as described in
/// [RFC3550 6.4.1](https://datatracker.ietf.org/doc/html/rfc3550#section-6.4.1).
///
/// The inputs have a resolution of 1/65536 s, so a raw result of zero, or slightly below zero
/// because of rounding, means the round trip was shorter than one unit. Such results are reported
/// as one unit (about 15.26 µs) instead of [`Duration::ZERO`] or `None`, so a completed round
/// trip is never reported as taking no time. One unit is the smallest non-zero value the format
/// can express; the true RTT may be anywhere from zero up to about that value, so treat
/// sub-resolution RTTs as approximate.
///
/// Returns `None` if no report has been received by the peer (`last_report == 0`), or if the
/// result is more negative than the rounding tolerance or implausibly large.
///
/// ## Params
/// - `ntp_time` the offset since 1900-01-01.
/// - `delay` the delay(`DLSR`) since last sender report, in units of 1/65536 s.
/// - `last_report` the middle 32 bits of an NTP timestamp for the most recent sender report(LSR)
///   or Receiver Report(LRR).
pub(crate) fn calculate_rtt(ntp_time: Duration, delay: u32, last_report: u32) -> Option<Duration> {
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

    // As per RFC, LSR/LRR is 0 if no report has been received yet. A zero delay is valid when
    // the peer replies within one compact NTP unit.
    if last_report == 0 {
        return None;
    }

    // The 16 bit seconds field wraps every 65536 s, so subtract with wrapping arithmetic and
    // read the result as a signed difference.
    let raw = compact_ntp(ntp_time)
        .wrapping_sub(delay)
        .wrapping_sub(last_report) as i32;

    if !(-RTT_ROUNDING_TOLERANCE..=MAX_PLAUSIBLE_RTT).contains(&raw) {
        return None;
    }

    let units = raw.max(1) as u64;
    let nanos = (units * 1_000_000_000) >> COMPACT_NTP_FRACTION_BITS;
    Some(Duration::from_nanos(nanos))
}

/// The middle 32 bits of the 64 bit NTP timestamp for `ntp_time`, truncated like `LSR`.
fn compact_ntp(ntp_time: Duration) -> u32 {
    ((ntp_time.as_nanos() << COMPACT_NTP_FRACTION_BITS) / 1_000_000_000) as u32
}

#[cfg(test)]
mod test {
    use super::*;

    /// One compact NTP unit, truncated to whole nanoseconds.
    const ONE_UNIT: Duration = Duration::from_nanos(15_258);

    /// An NTP time whose compact form is `compact`, in the given 65536 s era.
    fn ntp_time(era: u64, compact: u32) -> Duration {
        let nanos = (compact as u64 * 1_000_000_000).div_ceil(1 << COMPACT_NTP_FRACTION_BITS);
        Duration::from_secs(era << 16) + Duration::from_nanos(nanos)
    }

    #[test]
    fn rfc_example_is_exact() {
        let now = ntp_time(0xb44d, 0xb710_8000);
        assert_eq!(compact_ntp(now), 0xb710_8000);
        assert_eq!(
            calculate_rtt(now, 0x0005_4000, 0xb705_2000),
            Some(Duration::from_millis(6125))
        );
    }

    #[test]
    fn exact_zero_is_one_unit() {
        let now = ntp_time(0xb44d, 0xb710_8000);
        assert_eq!(calculate_rtt(now, 0x0005_4000, 0xb70b_4000), Some(ONE_UNIT));
    }

    #[test]
    fn rounding_below_zero_is_one_unit() {
        let now = ntp_time(0xb44d, 0xb710_8000);
        for below in 1..=RTT_ROUNDING_TOLERANCE as u32 {
            let lsr = 0xb70b_4000 + below;
            assert_eq!(calculate_rtt(now, 0x0005_4000, lsr), Some(ONE_UNIT));
        }
    }

    #[test]
    fn large_negative_is_none() {
        let now = ntp_time(0xb44d, 0xb710_8000);
        let past_tolerance = 0xb70b_4000 + RTT_ROUNDING_TOLERANCE as u32 + 1;
        assert_eq!(calculate_rtt(now, 0x0005_4000, past_tolerance), None);
        assert_eq!(calculate_rtt(now, 0x0005_4000, 0xb710_0000), None);
    }

    #[test]
    fn implausibly_large_is_none() {
        let now = ntp_time(0xb44d, 0xb710_8000);
        let lsr = 0xb710_8000 - 1 - MAX_PLAUSIBLE_RTT as u32;
        assert_eq!(calculate_rtt(now, 1, lsr), Some(Duration::from_secs(60)));
        assert_eq!(calculate_rtt(now, 1, lsr - 1), None);
    }

    #[test]
    fn small_rtt_across_seconds_wrap() {
        // SR sent at 65535.75 s, held 0.25 s by the peer, RR received 10 units after the wrap.
        let now = ntp_time(3, 0x0000_000a);
        assert_eq!(
            calculate_rtt(now, 0x0000_4000, 0xffff_c000),
            Some(Duration::from_nanos(152_587))
        );
    }

    #[test]
    fn no_sender_report_is_none() {
        let now = ntp_time(0xb44d, 0xb710_8000);
        assert_eq!(calculate_rtt(now, 0, 0), None);
    }

    #[test]
    fn zero_delay_with_sender_report_is_valid() {
        // A peer that replies within one compact NTP tick can encode its holding time as zero.
        // The echoed sender-report timestamp still lets us compute the RTT.
        let now = ntp_time(0xb44d, 0xb710_8000);
        assert_eq!(calculate_rtt(now, 0, 0xb710_7fff), Some(ONE_UNIT));
    }

    #[test]
    fn fraction_conversion_is_exact() {
        let now = ntp_time(0xb44d, 0xb710_8000);
        let rtt = |raw: u32| calculate_rtt(now, 1, 0xb710_8000 - 1 - raw);
        assert_eq!(rtt(0x0000_8000), Some(Duration::from_millis(500)));
        assert_eq!(rtt(0x0000_0001), Some(ONE_UNIT));
        assert_eq!(rtt(0x0001_0000), Some(Duration::from_secs(1)));
    }
}
