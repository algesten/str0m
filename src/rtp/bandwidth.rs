use std::fmt;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};
use std::time::Duration;

/// A data rate expressed as bits per second(bps).
///
/// Internally the value is tracked as a floating point number for accuracy in the presence of
/// repeated calculations that can yield decimal values.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Bitrate(f64);

impl Bitrate {
    /// A bitrate of zero bit/s.
    pub const ZERO: Self = Self::bps(0);

    /// Create a bitrate of some bit per second(bps).
    pub const fn bps(bps: u64) -> Self {
        Bitrate(bps as f64)
    }

    /// Create a bitrate of some **Kilobits** per second(kbps).
    pub const fn kbps(kbps: u64) -> Self {
        Self::bps(kbps * 10_u64.pow(3))
    }

    /// Create a bitrate of some **Megabits** per second(mbps).
    pub const fn mbps(mbps: u64) -> Self {
        Self::bps(mbps * 10_u64.pow(6))
    }

    /// Create a bitrate of some **Gigabits** per second(gbps).
    pub const fn gbps(gbps: u64) -> Self {
        Self::bps(gbps * 10_u64.pow(9))
    }

    /// The number of bits per second as f64.
    pub fn as_f64(&self) -> f64 {
        self.0
    }

    /// The number of bits per second rounded upwards as u64.
    pub fn as_u64(&self) -> u64 {
        self.0.ceil() as u64
    }

    /// Clamp the value between a min and a max.
    pub fn clamp(&self, min: Self, max: Self) -> Self {
        Self(self.0.clamp(min.0, max.0))
    }

    /// Return the minimum bitrate between `self` and `other`.
    pub fn min(&self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    /// Return the maximum bitrate between `self` and `other`.
    pub fn max(&self, other: Self) -> Self {
        Self(self.0.max(other.0))
    }
}

impl From<u64> for Bitrate {
    fn from(value: u64) -> Self {
        Self::bps(value)
    }
}

impl From<f64> for Bitrate {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl Mul<Duration> for Bitrate {
    type Output = DataSize;

    fn mul(self, rhs: Duration) -> Self::Output {
        let bits = self.0 * rhs.as_secs_f64();
        let bytes = bits / 8.0;

        DataSize::bytes(bytes.round() as u64)
    }
}

impl Mul<f64> for Bitrate {
    type Output = Bitrate;

    fn mul(self, rhs: f64) -> Self::Output {
        Bitrate(self.0 * rhs)
    }
}

impl Sub<Bitrate> for Bitrate {
    type Output = Bitrate;

    fn sub(self, rhs: Bitrate) -> Self::Output {
        assert!(
            self.0 >= rhs.0,
            "Attempted to subtract Bitrates that would result in overflow. lhs={}, rhs={}",
            self,
            rhs
        );

        Self(self.0 - rhs.0)
    }
}

impl Add<Bitrate> for Bitrate {
    type Output = Bitrate;

    fn add(self, rhs: Bitrate) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl fmt::Display for Bitrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rate = self.0;
        let log = rate.log10().floor() as u64;

        match log {
            0..=2 => write!(f, "{rate}bit/s"),
            3..=5 => write!(f, "{:.3}kbit/s", rate / 10.0_f64.powf(3.0)),
            6..=8 => write!(f, "{:.3}Mbit/s", rate / 10.0_f64.powf(6.0)),
            9..=11 => write!(f, "{:.3}Gbit/s", rate / 10.0_f64.powf(9.0)),
            12.. => write!(f, "{:.3}Tbit/s", rate / 10.0_f64.powf(12.0)),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DataSize(u64);

impl DataSize {
    pub const ZERO: Self = DataSize::bytes(0);

    pub const fn bytes(bytes: u64) -> DataSize {
        Self(bytes)
    }

    pub fn as_bytes_f64(&self) -> f64 {
        self.0 as f64
    }

    pub fn as_bytes_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl From<usize> for DataSize {
    fn from(value: usize) -> Self {
        Self(value as u64)
    }
}

impl From<u8> for DataSize {
    fn from(value: u8) -> Self {
        Self(value as u64)
    }
}

impl Div<Duration> for DataSize {
    type Output = Bitrate;

    fn div(self, rhs: Duration) -> Self::Output {
        let bytes = self.as_bytes_f64();

        let bps = (bytes * 8.0) / rhs.as_secs_f64();

        bps.into()
    }
}

impl Div<Bitrate> for DataSize {
    type Output = Duration;

    fn div(self, rhs: Bitrate) -> Self::Output {
        let bits = self.as_bytes_f64() * 8.0;
        let seconds = bits / rhs.as_f64();

        Duration::from_secs_f64(seconds)
    }
}

impl Mul<u64> for DataSize {
    type Output = DataSize;

    fn mul(self, rhs: u64) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl AddAssign<DataSize> for DataSize {
    fn add_assign(&mut self, rhs: DataSize) {
        self.0 += rhs.0;
    }
}

impl SubAssign<DataSize> for DataSize {
    fn sub_assign(&mut self, rhs: DataSize) {
        self.0 = self.0.saturating_sub(rhs.0);
    }
}

impl Add<DataSize> for DataSize {
    type Output = DataSize;

    fn add(self, rhs: DataSize) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sum<DataSize> for DataSize {
    fn sum<I: Iterator<Item = DataSize>>(iter: I) -> Self {
        iter.fold(DataSize::ZERO, |acc, s| acc + s)
    }
}

impl fmt::Display for DataSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size = self.0 as f64;
        // TODO: Use ilog10 when MSRV policy allows Rust 1.67.0
        let log = size.log10().floor() as u64;

        match log {
            0..=2 => write!(f, "{size}B"),
            3..=5 => write!(f, "{:.3}kB", size / 10.0_f64.powf(3.0)),
            6..=8 => write!(f, "{:.3}MB", size / 10.0_f64.powf(6.0)),
            9..=11 => write!(f, "{:.3}GB", size / 10.0_f64.powf(9.0)),
            12.. => write!(f, "{:.3}TB", size / 10.0_f64.powf(12.0)),
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::{Bitrate, DataSize};

    #[test]
    fn test_bitrate_display() {
        let rate = Bitrate::bps(1);
        assert_eq!(rate.to_string(), "1bit/s");

        let rate = Bitrate::bps(12);
        assert_eq!(rate.to_string(), "12bit/s");

        let rate = Bitrate::bps(123);
        assert_eq!(rate.to_string(), "123bit/s");

        let rate = Bitrate::bps(1234);
        assert_eq!(rate.to_string(), "1.234kbit/s");

        let rate = Bitrate::bps(12345);
        assert_eq!(rate.to_string(), "12.345kbit/s");

        let rate = Bitrate::bps(123456);
        assert_eq!(rate.to_string(), "123.456kbit/s");

        let rate = Bitrate::bps(1234567);
        assert_eq!(rate.to_string(), "1.235Mbit/s");

        let rate = Bitrate::bps(12345678);
        assert_eq!(rate.to_string(), "12.346Mbit/s");

        let rate = Bitrate::bps(123456789);
        assert_eq!(rate.to_string(), "123.457Mbit/s");

        let rate = Bitrate::bps(1234567898);
        assert_eq!(rate.to_string(), "1.235Gbit/s");

        let rate = Bitrate::bps(12345678987);
        assert_eq!(rate.to_string(), "12.346Gbit/s");

        let rate = Bitrate::bps(123456789876);
        assert_eq!(rate.to_string(), "123.457Gbit/s");

        let rate = Bitrate::bps(1234567898765);
        assert_eq!(rate.to_string(), "1.235Tbit/s");
    }

    #[test]
    fn test_data_size_div_duration() {
        let size = DataSize::bytes(2_500_000);
        let rate = size / Duration::from_secs(1);

        assert_eq!(rate.as_u64(), 20_000_000);
    }

    #[test]
    fn test_data_size_div_bitrate() {
        let size = DataSize::bytes(12_500);
        let rate = Bitrate::kbps(2_500);
        let duration = size / rate;

        assert_eq!(duration.as_millis(), 40);
    }
}
