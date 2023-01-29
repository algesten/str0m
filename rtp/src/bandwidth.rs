use std::fmt;

/// A data rate expressed as bits per second(bps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bitrate(u64);

impl Bitrate {
    pub fn new(bps: u64) -> Self {
        Bitrate(bps)
    }
}

impl From<u64> for Bitrate {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}
impl fmt::Display for Bitrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rate = self.0;
        // TODO: Use ilog10(available since 1.67.0) when the MSRV allows it.
        let log = (rate as f64).log10().floor() as u64;

        match log {
            0..=2 => write!(f, "{rate}bit/s"),
            3..=5 => write!(f, "{:.3}kbit/s", rate as f64 / 10.0_f64.powf(3.0)),
            6..=8 => write!(f, "{:.3}Mbit/s", rate as f64 / 10.0_f64.powf(6.0)),
            9..=11 => write!(f, "{:.3}Gbit/s", rate as f64 / 10.0_f64.powf(9.0)),
            12.. => write!(f, "{:.3}Tbit/s", rate as f64 / 10.0_f64.powf(12.0)),
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
