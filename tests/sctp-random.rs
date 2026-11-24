use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use str0m::crypto::{CryptoError, CryptoProvider, SecureRandom, from_feature_flags};
use str0m::{Event, Rtc, RtcError};
use tracing::info_span;

mod common;
use common::{TestRtc, init_log, progress};

/// Counts the draws, and delegates to the random source of the feature flag provider.
#[derive(Debug)]
struct CountingRandom;

static DRAWS: AtomicUsize = AtomicUsize::new(0);
static COUNTING_RANDOM: CountingRandom = CountingRandom;

impl SecureRandom for CountingRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        DRAWS.fetch_add(1, Ordering::SeqCst);
        from_feature_flags()
            .secure_random
            .expect("feature flag provider has a random source")
            .fill(buf)
    }
}

// sctp-proto holds one random source per process, so this is the only test in this file.
#[test]
pub fn sctp_draws_from_crypto_provider() -> Result<(), RtcError> {
    init_log();

    let provider = Arc::new(CryptoProvider {
        secure_random: Some(&COUNTING_RANDOM),
        ..from_feature_flags()
    });

    let now = Instant::now();
    let rtc_l = Rtc::builder()
        .set_crypto_provider(provider.clone())
        .build(now);
    let rtc_r = Rtc::builder().set_crypto_provider(provider).build(now);

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc_l);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("random".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    let open = |t: &TestRtc| {
        t.events
            .iter()
            .any(|(_, e)| matches!(e, Event::ChannelOpen(id, _) if *id == cid))
    };

    while !(open(&l) && open(&r)) {
        progress(&mut l, &mut r)?;
        assert!(
            l.duration() < Duration::from_secs(10),
            "data channel did not open"
        );
    }

    // Only SCTP draws from the provider's random source: verification tags and
    // initial TSNs on both sides, and the state cookie.
    assert!(DRAWS.load(Ordering::SeqCst) >= 3);

    Ok(())
}
