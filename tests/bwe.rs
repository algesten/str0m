#![cfg_attr(not(feature = "aws-lc-rs"), allow(unused))]

//! Integration tests for Bandwidth Estimation (BWE) under various network conditions.
//!
//! We only run the BWE tests with the aws-lc-rs crypto backend. This is because the
//! choice of backend doesn't affect the test. For rust-crypto, the pure rust backend,
//! the tests run very slow under debug mode and we don't want to run tests in release mode.

use std::time::Duration;

use netem::{DataSize, NetemConfig};
use str0m::bwe::{Bitrate, BweKind};
use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::media::Pt;
use str0m::rtp::{ExtensionValues, Ssrc};
use str0m::{Event, Rtc, RtcError};

mod common;
use common::{init_crypto_default, init_log, progress, TestRtc};
use tracing::info;

use crate::common::connect_l_r_with_rtc;

const LAYER_LOW: Bitrate = Bitrate::kbps(250);
const LAYER_MID: Bitrate = Bitrate::kbps(750);
const LAYER_TOP: Bitrate = Bitrate::kbps(1_500);

const RAMP_UP_SINGLE: &[Step] = &[
    Step::Conditions {
        config: NetemConfig::new(),
    },
    Step::Media {
        current_bitrate: LAYER_LOW,
        desired_bitrate: LAYER_MID,
        media_send_rate: LAYER_LOW,
    },
    Step::Run {
        duration: Duration::from_secs(10),
    },
    Step::Check {
        at_least: Bitrate::kbps(750),
    },
    Step::Media {
        current_bitrate: LAYER_MID,
        desired_bitrate: LAYER_TOP,
        media_send_rate: LAYER_MID,
    },
    Step::Run {
        duration: Duration::from_secs(30),
    },
    Step::Check {
        at_least: Bitrate::kbps(1_500),
    },
    Step::Media {
        current_bitrate: LAYER_TOP,
        desired_bitrate: LAYER_TOP,
        media_send_rate: LAYER_TOP,
    },
    Step::Run {
        duration: Duration::from_secs(10),
    },
    Step::Check {
        at_least: Bitrate::kbps(1_500),
    },
];

#[test]
#[cfg(feature = "aws-lc-rs")]
pub fn bwe_cellular() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut plan = RAMP_UP_SINGLE.to_vec();
    plan[0] = Step::Conditions {
        config: NetemConfig::cellular().seed(42),
    };

    let (mut l, mut r) = connect_with_bwe(LAYER_LOW, LAYER_MID);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    ctx.run_plan(&mut l, &mut r, &plan)?;

    Ok(())
}

#[test]
#[cfg(feature = "aws-lc-rs")]
pub fn bwe_wifi_normal() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // WiFi: 100 Mbps link, 5ms latency, ~1% loss
    let mut plan = RAMP_UP_SINGLE.to_vec();
    plan[0] = Step::Conditions {
        config: NetemConfig::wifi().seed(42),
    };

    let (mut l, mut r) = connect_with_bwe(LAYER_LOW, LAYER_MID);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    ctx.run_plan(&mut l, &mut r, &RAMP_UP_SINGLE)?;

    Ok(())
}

#[test]
#[cfg(feature = "aws-lc-rs")]
pub fn bwe_wifi_congested() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Congested WiFi: 5 Mbps link, 10ms latency, ~10% loss
    let mut plan = RAMP_UP_SINGLE.to_vec();
    plan[0] = Step::Conditions {
        config: NetemConfig::congested().seed(42),
    };

    let (mut l, mut r) = connect_with_bwe(LAYER_LOW, LAYER_MID);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    ctx.run_plan(&mut l, &mut r, &RAMP_UP_SINGLE)?;

    Ok(())
}

#[test]
#[cfg(feature = "aws-lc-rs")]
pub fn bwe_changing_bandwidth() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Send rate: 2 Mbps - bandwidth conditions will straddle this
    let media_send_rate = Bitrate::mbps(2);
    let initial_bitrate = Bitrate::mbps(1);
    let desired_bitrate = Bitrate::mbps(5);

    let plan = vec![
        // Phase 1: High bandwidth (10 Mbps) - above send rate, no constraint
        Step::Conditions {
            config: NetemConfig::new()
                .latency(Duration::from_millis(10))
                .jitter(Duration::from_millis(2))
                .link(Bitrate::mbps(10), DataSize::kbytes(200))
                .seed(42),
        },
        Step::Media {
            current_bitrate: initial_bitrate,
            desired_bitrate,
            media_send_rate,
        },
        Step::Run {
            duration: Duration::from_secs(40),
        },
        Step::Check {
            // BWE should discover high bandwidth (10 Mbps link)
            // Should be well above the send rate
            at_least: Bitrate::mbps(5),
        },
        // Phase 2: Low bandwidth (1 Mbps) - below send rate, constrains it
        Step::Conditions {
            config: NetemConfig::new()
                .latency(Duration::from_millis(10))
                .jitter(Duration::from_millis(20))
                .link(Bitrate::mbps(1), DataSize::kbytes(50))
                .seed(42),
        },
        Step::Run {
            duration: Duration::from_secs(30),
        },
        Step::Check {
            // BWE should detect the reduced bandwidth and lower estimate
            // Link is 1 Mbps, so estimate should be constrained to ~1 Mbps
            at_least: Bitrate::kbps(500), // At least 500 kbps, but should be around 1 Mbps
        },
        // Phase 3: Switch back to high bandwidth (10 Mbps)
        Step::Conditions {
            config: NetemConfig::new()
                .latency(Duration::from_millis(10))
                .jitter(Duration::from_millis(2))
                .link(Bitrate::mbps(10), DataSize::kbytes(200))
                .seed(42),
        },
        Step::Run {
            duration: Duration::from_secs(30),
        },
        Step::Check {
            // BWE should recover and discover high bandwidth again
            // Should be higher than the constrained phase 2
            at_least: Bitrate::mbps(3),
        },
    ];

    let (mut l, mut r) = connect_with_bwe(initial_bitrate, desired_bitrate);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    // Run the plan that changes bandwidth conditions
    ctx.run_plan(&mut l, &mut r, &plan)?;

    Ok(())
}

/// Helper to create two connected peers with BWE enabled on the sender.
fn connect_with_bwe(initial_bitrate: Bitrate, desired_bitrate: Bitrate) -> (TestRtc, TestRtc) {
    // Only sender (L) needs BWE enabled
    let rtc1 = Rtc::builder()
        .set_rtp_mode(true)
        .enable_bwe(Some(initial_bitrate))
        // .enable_raw_packets(true)
        .build();

    let rtc2 = Rtc::builder()
        //
        .set_rtp_mode(true)
        .build();

    let (mut l, mut r) = connect_l_r_with_rtc(rtc1, rtc2);

    l.bwe().set_current_bitrate(initial_bitrate);
    l.bwe().set_desired_bitrate(desired_bitrate);

    // The resolution must be smaller than the fastest send rate we want to test.
    l.set_forced_time_advance(Duration::from_micros(100));
    r.set_forced_time_advance(Duration::from_micros(100));

    // Normalize time after DTLS connection to make tests deterministic across backends
    // This ensures all crypto backends start from the same simulated time
    let normalized_time = l.start + Duration::from_millis(100);

    l.last = normalized_time;
    r.last = normalized_time;

    (l, r)
}

/// Extract the last BWE estimate from events.
fn get_last_bwe_estimate(rtc: &TestRtc) -> Option<Bitrate> {
    rtc.events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::EgressBitrateEstimate(BweKind::Twcc(bitrate)) = e {
                Some(*bitrate)
            } else {
                None
            }
        })
        .last()
}

/// BweTestContext holds state for running BWE tests.
struct BweTestContext {
    ssrc: Ssrc,
    pt: Pt,
    seq_no: u64,
    /// Current media send rate (excluding padding/probes)
    media_send_rate: Bitrate,
    /// Accumulated byte budget for sending (smooths out timing variations)
    byte_budget: f64,
}

#[derive(Debug, Clone, Copy)]
enum Step {
    /// Network conditions
    Conditions { config: NetemConfig },
    /// Send media
    Media {
        current_bitrate: Bitrate,
        desired_bitrate: Bitrate,
        media_send_rate: Bitrate,
    },
    /// Run simulation for duration
    Run { duration: Duration },
    /// Check the latest BWE estimate
    Check { at_least: Bitrate },
}

impl BweTestContext {
    fn new(l: &mut TestRtc, r: &mut TestRtc) -> Self {
        let mid = "vid".into();
        let ssrc_tx: Ssrc = 42.into();
        let ssrc_rtx: Ssrc = 44.into();

        l.direct_api().declare_media(mid, MediaKind::Video);
        l.direct_api()
            .declare_stream_tx(ssrc_tx, Some(ssrc_rtx), mid, None);

        r.direct_api().declare_media(mid, MediaKind::Video);
        r.direct_api()
            .expect_stream_rx(ssrc_tx, Some(ssrc_rtx), mid, None);

        // Enable TWCC feedback on the receiver so it sends feedback to the sender
        r.direct_api().enable_twcc_feedback();

        // Sync time
        let max = l.last.max(r.last);
        l.last = max;
        r.last = max;

        let params = l.params_vp8();
        assert_eq!(params.spec().codec, Codec::Vp8);
        let pt = params.pt();

        let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();

        Self {
            ssrc,
            pt,
            seq_no: 47_000,
            media_send_rate: Bitrate::mbps(2), // Default to 2 Mbps
            byte_budget: 0.0,
        }
    }

    fn run_plan(
        &mut self,
        l: &mut TestRtc,
        r: &mut TestRtc,
        plan: &[Step],
    ) -> Result<(), RtcError> {
        for (no, step) in plan.iter().enumerate() {
            info!("Running step {}: {:?}", no + 1, step);

            match step {
                Step::Conditions { config } => {
                    l.set_netem(*config);
                    r.set_netem(*config);
                }
                Step::Media {
                    current_bitrate,
                    desired_bitrate,
                    media_send_rate,
                } => {
                    l.bwe().set_current_bitrate(*current_bitrate);
                    l.bwe().set_desired_bitrate(*desired_bitrate);
                    self.set_media_send_rate(*media_send_rate);
                }
                Step::Run { duration } => {
                    self.run_for_duration(l, r, *duration)?;
                }
                Step::Check { at_least } => {
                    let estimate = get_last_bwe_estimate(l).expect("a BWE estimate");

                    const TOLERANCE: f64 = 0.01;

                    let is_ok = estimate >= *at_least * (1.0 - TOLERANCE);

                    assert!(
                        is_ok,
                        "Step {} estimate {} should be within {}% of expected {}",
                        no + 1,
                        estimate,
                        TOLERANCE * 100.0,
                        *at_least
                    );
                }
            }
        }

        Ok(())
    }

    pub fn set_media_send_rate(&mut self, media_send_rate: Bitrate) {
        self.media_send_rate = media_send_rate;
    }

    /// Run traffic for specified duration
    pub fn run_for_duration(
        &mut self,
        l: &mut TestRtc,
        r: &mut TestRtc,
        duration: Duration,
    ) -> Result<Option<Bitrate>, RtcError> {
        let start_duration = l.duration();
        let end_time = start_duration + duration;

        let mut last_send_time = l.duration();

        while l.duration() < end_time {
            let current_time = l.duration();

            // Calculate elapsed time since last send
            let elapsed = current_time.saturating_sub(last_send_time);
            last_send_time = current_time;

            // Accumulate byte budget based on elapsed time and target bitrate
            // This smooths out timing variations by allowing budget to carry over
            let elapsed_secs = elapsed.as_secs_f64();
            let bytes_earned = (self.media_send_rate.as_u64() as f64 / 8.0) * elapsed_secs;
            self.byte_budget += bytes_earned;

            // Use packet size of ~1150 bytes (allows RTX probe reuse)
            let packet_size = 1150;

            let mut did_progress = false;

            // Send packets while we have budget
            // IMPORTANT: Must call progress() after EACH write_rtp to consume outputs
            while self.byte_budget >= packet_size as f64 {
                // Calculate wallclock for THIS packet at current simulated time
                let wallclock = l.start + l.duration();
                let time = (self.seq_no * 1000 + 47_000_000) as u32;

                let mut direct = l.direct_api();
                let stream = direct.stream_tx(&self.ssrc).unwrap();

                let exts = ExtensionValues::default();

                // Send a video packet
                let payload = vec![0u8; packet_size];
                stream
                    .write_rtp(
                        self.pt,
                        self.seq_no.into(),
                        time,
                        wallclock,
                        false,
                        exts,
                        true,
                        payload,
                    )
                    .expect("clean write");

                self.seq_no += 1;
                self.byte_budget -= packet_size as f64;

                // Must progress after each write_rtp to consume outputs
                progress(l, r)?;
                did_progress = true;
            }

            if !did_progress {
                progress(l, r)?;
            }
        }

        Ok(get_last_bwe_estimate(l))
    }
}
