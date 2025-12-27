#![cfg_attr(not(feature = "aws-lc-rs"), allow(unused))]

//! Integration tests for Bandwidth Estimation (BWE) under various network conditions.
//!
//! We only run the BWE tests with the aws-lc-rs crypto backend. This is because the
//! choice of backend doesn't affect the test. For rust-crypto, the pure rust backend,
//! the tests run very slow under debug mode and we don't want to run tests in release mode.

use std::time::Duration;

use netem::NetemConfig;
use str0m::bwe::{Bitrate, BweKind};
use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::media::Pt;
use str0m::rtp::{ExtensionValues, Ssrc};
use str0m::{Event, Rtc, RtcError};

mod common;
use common::{init_crypto_default, init_log, progress, TestRtc};

use crate::common::connect_l_r_with_rtc;

#[test]
#[cfg(feature = "aws-lc-rs")]
pub fn bwe_cellular() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Cellular: 30 Mbps link, 50ms latency, ~2% loss
    let netem_config = NetemConfig::cellular().seed(42);
    let initial_bitrate = Bitrate::mbps(2);
    let desired_bitrate = Bitrate::mbps(20);

    let (mut l, mut r) =
        connect_with_bwe(initial_bitrate, desired_bitrate, netem_config, netem_config);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    let estimate = ctx
        .run_for_duration(&mut l, &mut r, Duration::from_secs(30), desired_bitrate)?
        .expect("Should have BWE estimate");

    // Cellular link is 30 Mbps. We're sending 2Mbps and asking for 20 Mbps
    let expected = Bitrate::kbps(17797);
    let tolerance = 0.001;
    let min_expected = Bitrate::bps((expected.as_u64() as f64 * (1.0 - tolerance)) as u64);
    let max_expected = Bitrate::bps((expected.as_u64() as f64 * (1.0 + tolerance)) as u64);

    assert!(
        estimate >= min_expected && estimate <= max_expected,
        "BWE estimate {} should be within {}% of {} (range: {} - {})",
        estimate,
        tolerance * 100.0,
        expected,
        min_expected,
        max_expected
    );

    Ok(())
}

#[test]
#[cfg(feature = "aws-lc-rs")]
pub fn bwe_wifi() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // WiFi: 100 Mbps link, 5ms latency, ~1% loss
    let netem_config = NetemConfig::wifi().seed(42);
    let initial_bitrate = Bitrate::mbps(2);
    let desired_bitrate = Bitrate::mbps(50);

    let (mut l, mut r) =
        connect_with_bwe(initial_bitrate, desired_bitrate, netem_config, netem_config);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    let estimate = ctx
        .run_for_duration(&mut l, &mut r, Duration::from_secs(40), desired_bitrate)?
        .expect("Should have BWE estimate");

    let expected = Bitrate::kbps(42930);
    let tolerance = 0.01;
    let min_expected = Bitrate::bps((expected.as_u64() as f64 * (1.0 - tolerance)) as u64);
    let max_expected = Bitrate::bps((expected.as_u64() as f64 * (1.0 + tolerance)) as u64);

    assert!(
        estimate >= min_expected && estimate <= max_expected,
        "BWE estimate {} should be within {}% of {} (range: {} - {})",
        estimate,
        tolerance * 100.0,
        expected,
        min_expected,
        max_expected
    );

    Ok(())
}

#[test]
#[cfg(feature = "aws-lc-rs")]
pub fn bwe_wifi_congested() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Congested WiFi: 5 Mbps link, 10ms latency, ~10% loss
    let netem_config = NetemConfig::wifi_congested().seed(42);
    let initial_bitrate = Bitrate::mbps(2);
    let desired_bitrate = Bitrate::mbps(40);

    let (mut l, mut r) =
        connect_with_bwe(initial_bitrate, desired_bitrate, netem_config, netem_config);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    let estimate =
        ctx.run_for_duration(&mut l, &mut r, Duration::from_secs(30), desired_bitrate)?;

    let estimate = estimate.expect("Should have BWE estimate");

    // Congested WiFi link is 5 Mbps, BWE should converge towards this
    let expected = Bitrate::kbps(5512);
    let tolerance = 0.01;
    let min_expected = Bitrate::bps((expected.as_u64() as f64 * (1.0 - tolerance)) as u64);
    let max_expected = Bitrate::bps((expected.as_u64() as f64 * (1.0 + tolerance)) as u64);

    assert!(
        estimate >= min_expected && estimate <= max_expected,
        "BWE estimate {} should be within {}% of {} (range: {} - {})",
        estimate,
        tolerance * 100.0,
        expected,
        min_expected,
        max_expected
    );

    Ok(())
}

#[test]
#[cfg(feature = "aws-lc-rs")]
pub fn bwe_changing_bandwidth() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Start with good WiFi: 100 Mbps
    let wifi_config = NetemConfig::wifi().seed(42);
    let congested_config = NetemConfig::wifi_congested().seed(42);
    let initial_bitrate = Bitrate::mbps(2);
    let desired_bitrate = Bitrate::mbps(12);

    let (mut l, mut r) =
        connect_with_bwe(initial_bitrate, desired_bitrate, wifi_config, wifi_config);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    // Phase 1: Good WiFi (40 seconds)
    let phase1_estimate = ctx
        .run_for_duration(&mut l, &mut r, Duration::from_secs(40), desired_bitrate)?
        .expect("Should have BWE estimate after phase 1");

    // Phase 2: Switch to congested WiFi (5 Mbps) for 30 seconds
    l.set_netem(congested_config);
    r.set_netem(congested_config);

    let phase2_estimate = ctx
        .run_for_duration(&mut l, &mut r, Duration::from_secs(30), desired_bitrate)?
        .expect("Should have BWE estimate after phase 2");

    // Phase 3: Switch back to good WiFi (100 Mbps) for 30 seconds
    l.set_netem(wifi_config);
    r.set_netem(wifi_config);

    let phase3_estimate = ctx
        .run_for_duration(&mut l, &mut r, Duration::from_secs(30), desired_bitrate)?
        .expect("Should have BWE estimate after phase 3");

    // Assertions:
    // Phase 1 (WiFi 100 Mbps): BWE should be high
    let wifi_expected = Bitrate::kbps(16934);
    let tolerance = 0.01;
    let wifi_min = Bitrate::bps((wifi_expected.as_u64() as f64 * (1.0 - tolerance)) as u64);
    let wifi_max = Bitrate::bps((wifi_expected.as_u64() as f64 * (1.0 + tolerance)) as u64);

    assert!(
        phase1_estimate >= wifi_min && phase1_estimate <= wifi_max,
        "Phase 1 BWE estimate {} should be within {}% of {} (range: {} - {})",
        phase1_estimate,
        tolerance * 100.0,
        wifi_expected,
        wifi_min,
        wifi_max
    );

    // Phase 2 (Congested 5 Mbps): BWE should drop significantly
    let congested_expected = Bitrate::kbps(6282);
    let congested_min =
        Bitrate::bps((congested_expected.as_u64() as f64 * (1.0 - tolerance)) as u64);
    let congested_max =
        Bitrate::bps((congested_expected.as_u64() as f64 * (1.0 + tolerance)) as u64);

    assert!(
        phase2_estimate >= congested_min && phase2_estimate <= congested_max,
        "Phase 2 BWE estimate {} should be within {}% of {} (range: {} - {})",
        phase2_estimate,
        tolerance * 100.0,
        congested_expected,
        congested_min,
        congested_max
    );

    // Phase 3 (WiFi 100 Mbps again): BWE should recover
    assert!(
        phase3_estimate >= wifi_min && phase3_estimate <= wifi_max,
        "Phase 3 BWE estimate {} should be within {}% of {} (range: {} - {})",
        phase3_estimate,
        tolerance * 100.0,
        wifi_expected,
        wifi_min,
        wifi_max
    );

    // Additional check: phase 2 should be significantly lower than phases 1 and 3
    assert!(
        phase2_estimate < phase1_estimate,
        "Phase 2 estimate {} should be lower than phase 1 estimate {}",
        phase2_estimate,
        phase1_estimate
    );
    assert!(
        phase2_estimate < phase3_estimate,
        "Phase 2 estimate {} should be lower than phase 3 estimate {}",
        phase2_estimate,
        phase3_estimate
    );

    Ok(())
}

/// Helper to create two connected peers with BWE enabled on the sender.
fn connect_with_bwe(
    initial_bitrate: Bitrate,
    desired_bitrate: Bitrate,
    l_netem: NetemConfig,
    r_netem: NetemConfig,
) -> (TestRtc, TestRtc) {
    // Only sender (L) needs BWE enabled
    let rtc1 = Rtc::builder()
        .set_rtp_mode(true)
        .enable_bwe(Some(initial_bitrate))
        .build();

    let rtc2 = Rtc::builder()
        //
        .set_rtp_mode(true)
        .build();

    let (mut l, mut r) = connect_l_r_with_rtc(rtc1, rtc2);

    l.bwe().set_current_bitrate(initial_bitrate, true);
    l.bwe().set_desired_bitrate(desired_bitrate);

    // Set netem configurations for incoming traffic
    l.set_netem(l_netem);
    r.set_netem(r_netem);

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
        }
    }

    /// Run traffic for specified duration while sending at high rate.
    /// Sets desired_bitrate high to allow BWE to probe for available bandwidth.
    fn run_for_duration(
        &mut self,
        l: &mut TestRtc,
        r: &mut TestRtc,
        duration: Duration,
        desired_bitrate: Bitrate,
    ) -> Result<Option<Bitrate>, RtcError> {
        // Configure BWE with desired bitrate to enable probing
        l.bwe().set_current_bitrate(desired_bitrate, true);
        l.bwe().set_desired_bitrate(desired_bitrate);

        let start_duration = l.duration();
        let end_time = start_duration + duration;

        while l.duration() < end_time {
            let wallclock = l.start + l.duration();

            // Send ~2 Mbps of media to simulate a video stream
            // 2 packets * 1200 bytes = 2.4 KB per iteration
            // At ~100 iterations/second = ~240 KB/s = ~2 Mbps
            // This leaves room for the pacer to generate padding probes
            for _ in 0..2 {
                let mut direct = l.direct_api();
                let stream = direct.stream_tx(&self.ssrc).unwrap();

                let time = (self.seq_no * 1000 + 47_000_000) as u32;
                let exts = ExtensionValues::default();

                // Send a video packet (~1150 bytes to allow RTX probe reuse)
                let payload = vec![0u8; 1150];
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
            }

            progress(l, r)?;
        }

        Ok(get_last_bwe_estimate(l))
    }
}
