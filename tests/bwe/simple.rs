#![cfg(feature = "aws-lc-rs")]

//! Simple BWE tests under different network conditions (cellular, WiFi).

use netem::NetemConfig;
use str0m::RtcError;

use crate::common::{connect_with_bwe, BweTestContext, Step, LAYER_LOW, LAYER_MID, RAMP_UP_SINGLE};
use crate::common::{init_crypto_default, init_log};

#[test]
pub fn bwe_cellular() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut plan = RAMP_UP_SINGLE.to_vec();
    plan[0] = Step::Conditions {
        description: "Cellular conditions",
        config: NetemConfig::cellular().seed(42),
    };

    let (mut l, mut r) = connect_with_bwe(LAYER_LOW, LAYER_MID);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    ctx.run_plan(&mut l, &mut r, &plan)?;

    Ok(())
}

#[test]
pub fn bwe_wifi_normal() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // WiFi: 100 Mbps link, 5ms latency, ~1% loss
    let mut plan = RAMP_UP_SINGLE.to_vec();
    plan[0] = Step::Conditions {
        description: "WiFi conditions",
        config: NetemConfig::wifi().seed(42),
    };

    let (mut l, mut r) = connect_with_bwe(LAYER_LOW, LAYER_MID);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    ctx.run_plan(&mut l, &mut r, &RAMP_UP_SINGLE)?;

    Ok(())
}

#[test]
pub fn bwe_wifi_congested() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Congested WiFi: 5 Mbps link, 10ms latency, ~10% loss
    let mut plan = RAMP_UP_SINGLE.to_vec();
    plan[0] = Step::Conditions {
        description: "Congested WiFi conditions",
        config: NetemConfig::congested().seed(42),
    };

    let (mut l, mut r) = connect_with_bwe(LAYER_LOW, LAYER_MID);

    let mut ctx = BweTestContext::new(&mut l, &mut r);

    ctx.run_plan(&mut l, &mut r, &RAMP_UP_SINGLE)?;

    Ok(())
}
