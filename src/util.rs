use hmac::{Hmac, Mac, NewMac};
use rand::prelude::*;
use sha1::Sha1;
use std::cmp::Ordering;
use std::ops::Add;
use std::ops::Sub;
use std::time::SystemTime;

pub type HmacSha1 = Hmac<Sha1>;

pub fn hmac_sha1(secret: &[u8], payload: &[u8]) -> [u8; 20] {
    let mut hmac = HmacSha1::new_varkey(secret).expect("Make HMAC-SHA1");
    hmac.update(payload);
    let comp = hmac.finalize().into_bytes();
    return comp.into();
}

// deliberate subset of ice-char, etc that are "safe"
const CHARS: &[u8] = b"abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ0123456789";

pub fn rand_id(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut rng = rand::thread_rng();
    for _ in 0..len {
        let y: f32 = rng.gen();
        let idx = (CHARS.len() as f32 * y).floor() as usize;
        v.push(CHARS[idx]);
    }
    v
}

pub fn rand_id_s(len: usize) -> String {
    unsafe { String::from_utf8_unchecked(rand_id(len)) }
}

pub struct FingerprintFmt<'a>(pub &'a [u8]);

impl<'a> std::fmt::Display for FingerprintFmt<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let last = self.0.len() - 1;
        for (idx, b) in self.0.iter().enumerate() {
            if idx < last {
                write!(f, "{:02X}:", b)?;
            } else {
                write!(f, "{:02X}", b)?;
            }
        }
        Ok(())
    }
}

pub fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// 2^32 as float.
const F32: f64 = 4_294_967_296.0;
// /// 2^16 as float.
// const F16: f64 = 65_536.0;
/// Microseconds i a second.
const MICROS: i64 = 1_000_000;

#[derive(Debug, Clone, Copy)]
pub struct Ts(i64, i64);

impl Ts {
    pub const ZERO: Ts = Ts(0, 1);

    pub fn new(numer: impl Into<i64>, denum: impl Into<i64>) -> Ts {
        Ts(numer.into(), denum.into())
    }

    #[inline(always)]
    pub fn numer(&self) -> i64 {
        self.0
    }

    #[inline(always)]
    pub fn denum(&self) -> i64 {
        self.1
    }

    pub fn now() -> Ts {
        // RTP spec "wallclock" uses NTP time, which starts at 1900-01-01.
        // We offset every .
        //
        // https://tools.ietf.org/html/rfc868
        const MICROS_1900: i64 = 2_208_988_800 * MICROS;

        let dur = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let now_micros = dur.as_secs() as i64 * 1_000_000 + dur.subsec_micros() as i64;

        Ts::from_micros(now_micros + MICROS_1900)
    }

    #[inline(always)]
    pub fn from_micros(v: impl Into<i64>) -> Ts {
        Ts(v.into(), MICROS)
    }

    #[inline(always)]
    pub fn from_seconds(v: impl Into<f64>) -> Ts {
        Self::from_micros((v.into() * 1_000_000.0_f64) as i64)
    }

    #[inline(always)]
    pub fn to_seconds(&self) -> f64 {
        self.0 as f64 / self.1 as f64
    }

    pub fn to_micros(&self) -> i64 {
        self.rebase(MICROS).numer()
    }

    #[inline(always)]
    pub fn from_ntp_64(v: u64) -> Ts {
        // https://tools.ietf.org/html/rfc3550#section-4
        // Wallclock time (absolute date and time) is represented using the
        // timestamp format of the Network Time Protocol (NTP), which is in
        // seconds relative to 0h UTC on 1 January 1900 [4]. The full
        // resolution NTP timestamp is a 64-bit unsigned fixed-point number with
        // the integer part in the first 32 bits and the fractional part in the
        // last 32 bits.
        let secs = (v as f64) / F32;

        Ts::from_seconds(secs)
    }

    #[inline(always)]
    pub fn to_ntp_64(&self) -> u64 {
        let secs = self.to_seconds();
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
    pub fn to_ntp_32(&self) -> u32 {
        let ntp_64 = self.to_ntp_64();

        ((ntp_64 >> 16) & 0xffff_ffff) as u32
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub fn abs(mut self) -> Ts {
        if self.0 < 0 {
            self.0 = -self.0;
        }
        self
    }

    #[inline(always)]
    pub fn rebase(self, denum: i64) -> Ts {
        if denum == self.1 {
            self
        } else {
            let numer = self.0 as i128 * denum as i128 / self.1 as i128;
            Ts::new(numer as i64, denum)
        }
    }

    #[inline(always)]
    fn same_base(t0: Ts, t1: Ts) -> (Ts, Ts) {
        let max = t0.1.max(t1.1);
        (t0.rebase(max), t1.rebase(max))
    }
}

impl PartialEq for Ts {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        let (t0, t1) = Ts::same_base(*self, *other);
        t0.0 == t1.0
    }
}
impl Eq for Ts {}

impl PartialOrd for Ts {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let (t0, t1) = Ts::same_base(*self, *other);
        Some(t0.cmp(&t1))
    }
}

impl Ord for Ts {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        let (t0, t1) = Ts::same_base(*self, *other);
        if t0 == t1 {
            Ordering::Equal
        } else if t0.0 < t1.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl Sub for Ts {
    type Output = Ts;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        let (t0, t1) = Ts::same_base(self, rhs);
        Ts::new(t0.0 - t1.0, t0.1)
    }
}

impl Add for Ts {
    type Output = Ts;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        let (t0, t1) = Ts::same_base(self, rhs);
        Ts::new(t0.0 + t1.0, t0.1)
    }
}

pub trait VecExt<T> {
    fn find_or_append(&mut self, f: impl Fn(&T) -> bool, i: impl FnOnce() -> T) -> &mut T;
}

impl<T> VecExt<T> for Vec<T> {
    fn find_or_append<'a>(&mut self, f: impl Fn(&T) -> bool, i: impl FnOnce() -> T) -> &mut T {
        let pos = self.iter().position(f).unwrap_or_else(|| {
            self.push(i());
            self.len() - 1
        });

        &mut self[pos]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ts_rebase() {
        let t1 = Ts::from_seconds(10.0);
        let t2 = t1.rebase(90_000);
        assert_eq!(t2.numer(), 90_000 * 10);
        assert_eq!(t2.denum(), 90_000);

        println!("{}", (10.0234_f64).fract());
    }
}
