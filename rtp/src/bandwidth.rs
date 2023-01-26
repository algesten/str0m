use std::fmt;

/// A data rate expressed as bits per second(bps).
///
/// Internally the value is tracked as a floating point number for accuracy in the presence of
/// repeated calculations that can yield decimal values.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Bitrate(f64);

impl Bitrate {
    pub fn new(bps: u64) -> Self {
        Bitrate(bps as f64)
    }

    pub fn as_f64(&self) -> f64 {
        self.0
    }

    pub fn as_u64(&self) -> u64 {
        self.0.ceil() as u64
    }

    pub fn clamp(&self, min: Self, max: Self) -> Self {
        Self(self.0.clamp(min.0, max.0))
    }
}

impl From<u64> for Bitrate {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<f64> for Bitrate {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl fmt::Display for Bitrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rate = self.0;
        // TODO: Use ilog10(available since 1.67.0) when the MSRV allows it.
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

#[cfg(test)]
mod test {
    use super::Bitrate;

    #[test]
    fn test_display() {
        let rate = Bitrate::new(1);
        assert_eq!(rate.to_string(), "1bit/s");

        let rate = Bitrate::new(12);
        assert_eq!(rate.to_string(), "12bit/s");

        let rate = Bitrate::new(123);
        assert_eq!(rate.to_string(), "123bit/s");

        let rate = Bitrate::new(1234);
        assert_eq!(rate.to_string(), "1.234kbit/s");

        let rate = Bitrate::new(12345);
        assert_eq!(rate.to_string(), "12.345kbit/s");

        let rate = Bitrate::new(123456);
        assert_eq!(rate.to_string(), "123.456kbit/s");

        let rate = Bitrate::new(1234567);
        assert_eq!(rate.to_string(), "1.235Mbit/s");

        let rate = Bitrate::new(12345678);
        assert_eq!(rate.to_string(), "12.346Mbit/s");

        let rate = Bitrate::new(123456789);
        assert_eq!(rate.to_string(), "123.457Mbit/s");

        let rate = Bitrate::new(1234567898);
        assert_eq!(rate.to_string(), "1.235Gbit/s");

        let rate = Bitrate::new(12345678987);
        assert_eq!(rate.to_string(), "12.346Gbit/s");

        let rate = Bitrate::new(123456789876);
        assert_eq!(rate.to_string(), "123.457Gbit/s");

        let rate = Bitrate::new(1234567898765);
        assert_eq!(rate.to_string(), "1.235Tbit/s");
    }
}
