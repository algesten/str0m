macro_rules! log_stat {
    ($name:expr, $($arg:expr),+) => {
        {
            use std::time::SystemTime;
            use std::io::{self, Write};

            let now = SystemTime::now();
            let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
            let unix_time_ms = since_epoch.as_millis();
            let mut lock = io::stdout().lock();
            write!(lock, "{} ", $name).expect("Failed to write to stdout");

            $(
                write!(lock, "{},", $arg).expect("Failed to write to stdout");
            )+
            writeln!(lock, "{}", unix_time_ms).expect("Failed to write to stdout");
        }
    };
}

macro_rules! log_delay_variation {
    ($($arg:expr),+) => {
        crate::bwe::macros::log_stat!("DELAY_VARIATION", $($arg),+);
    }
}

macro_rules! log_trendline_estimate {
    ($($arg:expr),+) => {
        crate::bwe::macros::log_stat!("TRENDLINE_ESTIMATE", $($arg),+);
    }
}

macro_rules! log_trendline_modified_trend {
    ($($arg:expr),+) => {
        crate::bwe::macros::log_stat!("TRENDLINE_MODIFIED_TREND", $($arg),+);
    }
}

macro_rules! log_bitrate_estimate {
    ($($arg:expr),+) => {
        crate::bwe::macros::log_stat!("BITRATE_ESTIMATE", $($arg),+);
    }
}

macro_rules! log_rate_control_state {
    ($($arg:expr),+) => {
        crate::bwe::macros::log_stat!("RATE_CONTROL_STATE", $($arg),+);
    }
}

macro_rules! log_rate_control_observed_bitrate {
    ($($arg:expr),+) => {
        crate::bwe::macros::log_stat!("RATE_CONTROL_OBSERVED_BITRATE", $($arg),+);
    }
}

macro_rules! log_rate_control_applied_change {
    ($($arg:expr),+) => {
        crate::bwe::macros::log_stat!("RATE_CONTROL_APPLIED_CHANGE", $($arg),+);
    }
}

macro_rules! log_pacer_media_debt {
    ($($arg:expr),+) => {
        crate::bwe::macros::log_stat!("PACER_DEBT", $($arg),+, "media");
    }
}

macro_rules! log_pacer_padding_debt {
    ($($arg:expr),+) => {
        crate::bwe::macros::log_stat!("PACER_DEBT", $($arg),+, "padding");
    }
}

pub(crate) use log_bitrate_estimate;
pub(crate) use log_delay_variation;
pub(crate) use log_pacer_media_debt;
pub(crate) use log_pacer_padding_debt;
pub(crate) use log_rate_control_applied_change;
pub(crate) use log_rate_control_observed_bitrate;
pub(crate) use log_rate_control_state;
pub(crate) use log_stat;
pub(crate) use log_trendline_estimate;
pub(crate) use log_trendline_modified_trend;
