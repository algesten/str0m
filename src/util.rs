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

#[derive(Debug, Clone, Copy)]
pub struct Ts(f64, f64);

impl Ts {
    pub const ZERO: Ts = Ts(0.0, 1.0);
    const TOLERANCE: f64 = 0.0000000000000001;

    pub fn new(numer: f64, denum: f64) -> Ts {
        Ts(numer, denum)
    }

    #[inline(always)]
    pub fn numer(&self) -> f64 {
        self.0
    }

    #[inline(always)]
    pub fn denum(&self) -> f64 {
        self.1
    }

    pub fn now() -> Ts {
        let dur = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let time = (dur.as_secs() * 1_000_000 + dur.subsec_micros() as u64) as f64;
        Ts::from_micros(time)
    }

    pub fn from_micros(v: f64) -> Ts {
        Ts(v, 1_000_000.0)
    }

    pub fn from_seconds(v: f64) -> Ts {
        Ts(v, 1.0)
    }

    pub fn to_seconds(&self) -> f64 {
        self.rebase(1.0).0
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        (self.0 - 0.0) < Ts::TOLERANCE
    }

    #[inline(always)]
    pub fn abs(mut self) -> Ts {
        if self.0 < 0.0 {
            self.0 = -self.0;
        }
        self
    }

    #[inline(always)]
    pub fn rebase(self, denum: f64) -> Ts {
        if denum == self.1 {
            self
        } else {
            Ts::new((self.0 / self.1) * denum, denum)
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
        (t0.0 - t1.0).abs() < Ts::TOLERANCE
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
        let t2 = t1.rebase(90_000.0);
        assert_eq!(t2.numer(), 90_000.0 * 10.0);
        assert_eq!(t2.denum(), 90_000.0);
    }
}
