use std::cmp::Ordering;
use std::ops::{Add, Sub};
use std::time::SystemTime;

/// 2^32 as float.
const F32: f64 = 4_294_967_296.0;
// /// 2^16 as float.
// const F16: f64 = 65_536.0;

/// Microseconds in a second.
const MICROS: i64 = 1_000_000;

/// Milliseconds in a second.
const MILLIS: i64 = 1_000;

#[derive(Debug, Clone, Copy)]
pub struct MediaTime(i64, i64);

#[allow(dead_code)]
impl MediaTime {
    pub const ZERO: MediaTime = MediaTime(0, 1);

    pub const fn new(numer: i64, denum: i64) -> MediaTime {
        MediaTime(numer, denum)
    }

    #[inline(always)]
    pub const fn numer(&self) -> i64 {
        self.0
    }

    #[inline(always)]
    pub const fn denum(&self) -> i64 {
        self.1
    }

    pub fn now() -> MediaTime {
        // RTP spec "wallclock" uses NTP time, which starts at 1900-01-01.
        //
        // https://tools.ietf.org/html/rfc868
        const MICROS_1900: i64 = 2_208_988_800 * MICROS;

        let dur = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let now_micros = dur.as_secs() as i64 * 1_000_000 + dur.subsec_micros() as i64;

        MediaTime::from_micros(now_micros + MICROS_1900)
    }

    #[inline(always)]
    pub const fn from_micros(v: i64) -> MediaTime {
        MediaTime(v, MICROS)
    }

    #[inline(always)]
    pub const fn from_millis(v: i64) -> MediaTime {
        MediaTime(v, MILLIS)
    }

    #[inline(always)]
    pub fn from_seconds(v: impl Into<f64>) -> MediaTime {
        Self::from_micros((v.into() * 1_000_000.0_f64) as i64)
    }

    #[inline(always)]
    pub fn as_seconds(&self) -> f64 {
        self.0 as f64 / self.1 as f64
    }

    pub const fn as_micros(&self) -> i64 {
        self.rebase(MICROS).numer()
    }

    #[inline(always)]
    pub fn from_ntp_64(v: u64) -> MediaTime {
        // https://tools.ietf.org/html/rfc3550#section-4
        // Wallclock time (absolute date and time) is represented using the
        // timestamp format of the Network Time Protocol (NTP), which is in
        // seconds relative to 0h UTC on 1 January 1900 [4]. The full
        // resolution NTP timestamp is a 64-bit unsigned fixed-point number with
        // the integer part in the first 32 bits and the fractional part in the
        // last 32 bits.
        let secs = (v as f64) / F32;

        MediaTime::from_seconds(secs)
    }

    #[inline(always)]
    pub fn as_ntp_64(&self) -> u64 {
        let secs = self.as_seconds();
        assert!(secs >= 0.0);

        // sec * (2 ^ 32)
        (secs * F32) as u64
    }

    // #[inline(always)]
    // pub fn from_ntp_32(v: u32) -> Ts {
    //     let secs = (v as f64) / F16;

    //     Ts::from_seconds(secs)
    // }

    #[inline(always)]
    pub fn as_ntp_32(&self) -> u32 {
        let ntp_64 = self.as_ntp_64();

        ((ntp_64 >> 16) & 0xffff_ffff) as u32
    }

    #[inline(always)]
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub const fn abs(mut self) -> MediaTime {
        if self.0 < 0 {
            self.0 = -self.0;
        }
        self
    }

    #[inline(always)]
    pub const fn rebase(self, denum: i64) -> MediaTime {
        if denum == self.1 {
            self
        } else {
            let numer = self.0 as i128 * denum as i128 / self.1 as i128;
            MediaTime::new(numer as i64, denum)
        }
    }

    #[inline(always)]
    fn same_base(t0: MediaTime, t1: MediaTime) -> (MediaTime, MediaTime) {
        let max = t0.1.max(t1.1);
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
        let (t0, t1) = MediaTime::same_base(*self, *other);
        Some(t0.cmp(&t1))
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

impl Add for MediaTime {
    type Output = MediaTime;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        let (t0, t1) = MediaTime::same_base(self, rhs);
        MediaTime::new(t0.0 + t1.0, t0.1)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ts_rebase() {
        let t1 = MediaTime::from_seconds(10.0);
        let t2 = t1.rebase(90_000);
        assert_eq!(t2.numer(), 90_000 * 10);
        assert_eq!(t2.denum(), 90_000);

        println!("{}", (10.0234_f64).fract());
    }
}
