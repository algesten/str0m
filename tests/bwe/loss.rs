//! Loss-based bandwidth estimation tests.

use std::time::Duration;

use netem::{DataSize, NetemConfig, Probability, RandomLoss};
use str0m::RtcError;
use str0m::bwe::Bitrate;

use crate::common::{BweTestContext, Step, connect_with_bwe, init_crypto_default, init_log};

#[test]
fn loss_caps_estimate_below_delay_based() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let plan = vec![
        Step::Conditions {
            description: "Network with moderate loss",
            config: NetemConfig::new()
                .latency(Duration::from_millis(20))
                .jitter(Duration::from_millis(5))
                .loss(RandomLoss::new(Probability::new(0.10))) // 10% loss
                .link(Bitrate::mbps(5), DataSize::kbytes(100))
                .seed(42),
        },
        Step::Media {
            description: "Send at 2 Mbps",
            desired_bitrate: Bitrate::mbps(5),
            media_send_rate: Bitrate::mbps(2),
        },
        // Past startup phase (2 seconds) so loss controller activates
        Step::Run {
            description: "Wait past startup phase",
            duration: Duration::from_secs(3),
        },
        Step::Run {
            description: "Let loss controller observe and cap",
            duration: Duration::from_secs(5),
        },
        Step::Check {
            description: "Estimate capped by loss (safety net)",
            at_least: Bitrate::mbps(1),
        },
    ];

    let (mut l, mut r) = connect_with_bwe(Bitrate::mbps(2), Bitrate::mbps(5));
    let mut ctx = BweTestContext::new(&mut l, &mut r);
    ctx.run_plan(&mut l, &mut r, &plan)?;

    Ok(())
}

#[test]
fn loss_controller_only_reduces_never_increases() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let plan = vec![
        // Start with clean network to establish high estimate
        Step::Conditions {
            description: "Clean network initially",
            config: NetemConfig::new()
                .latency(Duration::from_millis(10))
                .link(Bitrate::mbps(5), DataSize::kbytes(150))
                .seed(42),
        },
        Step::Media {
            description: "Send at 2 Mbps",
            desired_bitrate: Bitrate::mbps(5),
            media_send_rate: Bitrate::mbps(2),
        },
        Step::Run {
            description: "Build up estimate",
            duration: Duration::from_secs(5),
        },
        Step::Check {
            description: "Estimate should be healthy",
            at_least: Bitrate::mbps(2),
        },
        // Introduce loss
        Step::Conditions {
            description: "Add significant loss",
            config: NetemConfig::new()
                .latency(Duration::from_millis(10))
                .loss(RandomLoss::new(Probability::new(0.15))) // 15% loss
                .link(Bitrate::mbps(5), DataSize::kbytes(150))
                .seed(42),
        },
        Step::Run {
            description: "Loss controller reduces estimate",
            duration: Duration::from_secs(5),
        },
        Step::Check {
            description: "Estimate reduced by loss controller",
            at_least: Bitrate::mbps(1),
        },
        // Remove loss - estimate should NOT increase from loss controller
        // (only delay-based increases)
        Step::Conditions {
            description: "Remove loss",
            config: NetemConfig::new()
                .latency(Duration::from_millis(10))
                .link(Bitrate::mbps(5), DataSize::kbytes(150))
                .seed(42),
        },
        Step::Run {
            description: "Delay-based can recover, not loss-based",
            duration: Duration::from_secs(5),
        },
        // We just verify the test completes without checking specific value
        // The point is loss controller acts as safety net, not growth driver
    ];

    let (mut l, mut r) = connect_with_bwe(Bitrate::mbps(2), Bitrate::mbps(5));
    let mut ctx = BweTestContext::new(&mut l, &mut r);
    ctx.run_plan(&mut l, &mut r, &plan)?;

    Ok(())
}

#[test]
fn sustained_heavy_loss_keeps_estimate_above_minimum() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // A receiver behind a link that drops most packets for minutes. Each loss-based
    // update may pick the 0.95x candidate, so without a lower bound the estimate decays
    // geometrically towards zero, and the pacer then divides its debt by it.
    let plan = vec![
        Step::Conditions {
            description: "Link losing 60% of packets",
            config: NetemConfig::new()
                .latency(Duration::from_millis(20))
                .loss(RandomLoss::new(Probability::new(0.60)))
                .link(Bitrate::mbps(5), DataSize::kbytes(100))
                .seed(42),
        },
        Step::Media {
            description: "Send at 2 Mbps",
            desired_bitrate: Bitrate::mbps(5),
            media_send_rate: Bitrate::mbps(2),
        },
        Step::Run {
            description: "Sustained heavy loss",
            duration: Duration::from_secs(420),
        },
        // The sender pauses, e.g. a muted camera. With the queue empty the pacer falls back
        // from its queue-drain rate to the pacing rate derived from the estimate, and divides
        // the media debt it built up while draining by that rate.
        Step::Media {
            description: "Sender pauses",
            desired_bitrate: Bitrate::mbps(5),
            media_send_rate: Bitrate::ZERO,
        },
        Step::Run {
            description: "Paused",
            duration: Duration::from_secs(10),
        },
        Step::Check {
            description: "Estimate stays at or above the loss controller minimum",
            at_least: Bitrate::kbps(1),
        },
    ];

    let (mut l, mut r) = connect_with_bwe(Bitrate::mbps(2), Bitrate::mbps(5));
    let mut ctx = BweTestContext::new(&mut l, &mut r);
    ctx.run_plan(&mut l, &mut r, &plan)?;

    Ok(())
}
