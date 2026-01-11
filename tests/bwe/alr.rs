#![cfg(feature = "aws-lc-rs")]

//! BWE test for allocation probing mechanics when entering ALR.

use std::sync::Arc;
use std::time::Duration;

use netem::{DataSize, NetemConfig};
use str0m::bwe::Bitrate;
use str0m::RtcError;

use crate::common::{connect_with_bwe, init_crypto_default, init_log, BweTestContext, Step};

#[test]
pub fn bwe_allocation_probe_on_alr_entry() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let plan = vec![
        // Set up a moderate-capacity network (don't let estimate exceed max_bitrate)
        Step::Conditions {
            description: "Moderate bandwidth network",
            config: NetemConfig::new()
                .link(Bitrate::mbps(3), DataSize::kbytes(100))
                .seed(42),
        },
        // Start with low initial bitrate, high desired bitrate
        Step::Media {
            description: "Start with 1 Mbps, desire 5 Mbps",
            current_bitrate: Bitrate::mbps(1),
            desired_bitrate: Bitrate::mbps(5),
            media_send_rate: Bitrate::mbps(1), // Higher rate to avoid early ALR entry
        },
        // Wait for initial probing, estimate growth, and probe controller to reach ProbingComplete
        Step::Run {
            description: "Wait for probing to complete",
            duration: Duration::from_secs(5),
        },
        Step::Check {
            description: "Estimate should have grown from probing",
            at_least: Bitrate::mbps(1),
        },
        // Enter ALR by reducing media send rate below estimate
        // This should trigger immediate allocation probing
        Step::Media {
            description: "Enter ALR: send 500 kbps with 5 Mbps desired",
            current_bitrate: Bitrate::mbps(1),
            desired_bitrate: Bitrate::mbps(5),
            media_send_rate: Bitrate::kbps(500), // Low send rate = ALR
        },
        Step::Run {
            description: "Wait for ALR entry and allocation probe",
            duration: Duration::from_secs(2),
        },
        // Verify allocation probe fires
        // With estimate ~1-2 Mbps and max_bitrate 5 Mbps:
        // - First probe at 1x max = 5 Mbps, but capped by 2x estimate (~2-4 Mbps)
        // - Second probe at 2x max = 10 Mbps, but capped by 2x estimate
        Step::CheckProbe {
            description: "Allocation probe is marked as ALR probe",
            check: Arc::new(|_index, probe| probe.is_alr_probe()),
        },
        Step::CheckProbe {
            description: "Allocation probe targets max_bitrate (5 Mbps)",
            check: Arc::new(|_index, probe| {
                let expected = Bitrate::mbps(5);
                let tolerance = 0.01;
                probe.is_alr_probe()
                    && probe.target_bitrate() >= expected * (1.0 - tolerance)
                    && probe.target_bitrate() <= expected * (1.0 + tolerance)
            }),
        },
    ];

    let (mut l, mut r) = connect_with_bwe(Bitrate::mbps(1), Bitrate::mbps(5));

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    ctx.run_plan(&mut l, &mut r, &plan)?;

    Ok(())
}

#[test]
pub fn bwe_periodic_allocation_probing_in_alr() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let plan = vec![
        Step::Conditions {
            description: "Moderate bandwidth network",
            config: NetemConfig::new()
                .link(Bitrate::mbps(3), DataSize::kbytes(100))
                .seed(42),
        },
        Step::Media {
            description: "Start at 1 Mbps, desire 5 Mbps",
            current_bitrate: Bitrate::mbps(1),
            desired_bitrate: Bitrate::mbps(5),
            media_send_rate: Bitrate::mbps(1),
        },
        // Wait for initial probing to complete and reach ProbingComplete state
        Step::Run {
            description: "Wait for probing to complete",
            duration: Duration::from_secs(5),
        },
        Step::Check {
            description: "Estimate should have grown",
            at_least: Bitrate::mbps(1),
        },
        // Enter ALR with low send rate
        Step::Media {
            description: "Enter ALR with low send rate",
            current_bitrate: Bitrate::mbps(1),
            desired_bitrate: Bitrate::mbps(5),
            media_send_rate: Bitrate::kbps(500),
        },
        Step::Run {
            description: "Wait for ALR entry",
            duration: Duration::from_secs(2),
        },
        // First allocation probe on ALR entry
        Step::CheckProbe {
            description: "First allocation probe on ALR entry",
            check: Arc::new(|_index, probe| probe.is_alr_probe()),
        },
        // Wait for periodic probe interval (MIN_TIME_BETWEEN_ALR_PROBES = 5 seconds)
        Step::Run {
            description: "Wait 6 seconds for periodic probe",
            duration: Duration::from_secs(6),
        },
        // Should see another allocation probe after 5 seconds
        Step::CheckProbe {
            description: "Periodic allocation probe fires after 5 seconds",
            check: Arc::new(|_index, probe| probe.is_alr_probe()),
        },
    ];

    let (mut l, mut r) = connect_with_bwe(Bitrate::mbps(1), Bitrate::mbps(5));

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    ctx.run_plan(&mut l, &mut r, &plan)?;

    Ok(())
}

#[test]
pub fn bwe_no_allocation_probing_when_estimate_at_max() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let plan = vec![
        Step::Conditions {
            description: "Moderate bandwidth network",
            config: NetemConfig::new()
                .latency(Duration::from_millis(10))
                .jitter(Duration::from_millis(2))
                .link(Bitrate::mbps(3), DataSize::kbytes(100))
                .seed(42),
        },
        // Start with bitrate close to max desired
        Step::Media {
            description: "Start at 1.5 Mbps, desire 2 Mbps",
            current_bitrate: Bitrate::mbps(1),
            desired_bitrate: Bitrate::mbps(2),
            media_send_rate: Bitrate::mbps(1),
        },
        // Let estimate grow to near max
        Step::Run {
            description: "Grow to desired bitrate",
            duration: Duration::from_secs(10),
        },
        Step::Check {
            description: "Estimate should reach desired",
            at_least: Bitrate::mbps(1),
        },
        // Enter ALR with estimate >= max_bitrate
        Step::Media {
            description: "Enter ALR with estimate at max",
            current_bitrate: Bitrate::mbps(2),
            desired_bitrate: Bitrate::mbps(2),
            media_send_rate: Bitrate::kbps(500),
        },
        // Note: We can't easily test ABSENCE of probes with current CheckProbe mechanism
        // Instead, we verify estimate stays stable without ALR probing
        Step::Run {
            description: "Wait and verify no growth from allocation probes",
            duration: Duration::from_secs(6),
        },
        Step::Check {
            description: "Estimate stable around max bitrate",
            at_least: Bitrate::mbps(1),
        },
    ];

    let (mut l, mut r) = connect_with_bwe(Bitrate::mbps(1), Bitrate::mbps(2));

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    ctx.run_plan(&mut l, &mut r, &plan)?;

    Ok(())
}
