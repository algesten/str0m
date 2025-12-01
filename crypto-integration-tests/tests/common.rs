//! Common test utilities for apple_crypto integration tests.

#![cfg(target_vendor = "apple")]
#![allow(unused)]

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::sync::Once;
use std::time::{Duration, Instant};

use str0m::Candidate;
use str0m::change::SdpApi;
use str0m::format::Codec;
use str0m::format::PayloadParams;
use str0m::media::MediaKind;
use str0m::net::Receive;
use str0m::{Event, Input, Output, Rtc, RtcError};
use tracing::Span;
use tracing::info_span;

pub struct TestRtc {
    pub span: Span,
    pub rtc: Rtc,
    pub start: Instant,
    pub last: Instant,
    pub events: Vec<(Instant, Event)>,
}

impl TestRtc {
    pub fn new(span: Span) -> Self {
        Self::new_with_rtc(span, Rtc::new())
    }

    pub fn new_with_rtc(span: Span, rtc: Rtc) -> Self {
        let now = Instant::now();
        TestRtc {
            span,
            rtc,
            start: now,
            last: now,
            events: vec![],
        }
    }

    pub fn add_host_candidate(&mut self, socket: SocketAddr) -> Candidate {
        self.rtc
            .add_local_candidate(Candidate::host(socket, "udp").unwrap())
            .unwrap()
            .clone()
    }

    pub fn duration(&self) -> Duration {
        self.last - self.start
    }

    pub fn params_opus(&self) -> PayloadParams {
        self.rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::Opus)
            .cloned()
            .unwrap()
    }

    pub fn params_vp8(&self) -> PayloadParams {
        self.rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::Vp8)
            .cloned()
            .unwrap()
    }
}

pub fn progress(l: &mut TestRtc, r: &mut TestRtc) -> Result<(), RtcError> {
    let (f, t) = if l.last < r.last { (l, r) } else { (r, l) };

    loop {
        f.span
            .in_scope(|| f.rtc.handle_input(Input::Timeout(f.last)))?;

        match f.span.in_scope(|| f.rtc.poll_output())? {
            Output::Timeout(v) => {
                let tick = f.last + Duration::from_millis(10);
                f.last = if v == f.last { tick } else { tick.min(v) };
                break;
            }
            Output::Transmit(v) => {
                let data = v.contents;
                let input = Input::Receive(
                    f.last,
                    Receive {
                        proto: v.proto,
                        source: v.source,
                        destination: v.destination,
                        contents: (&*data).try_into()?,
                    },
                );
                t.span.in_scope(|| t.rtc.handle_input(input))?;
            }
            Output::Event(v) => {
                f.events.push((f.last, v));
            }
        }
    }

    Ok(())
}

/// Perform a change to the session via an offer and answer.
pub fn negotiate<F, R>(offerer: &mut TestRtc, answerer: &mut TestRtc, mut do_change: F) -> R
where
    F: FnMut(&mut SdpApi) -> R,
{
    let (offer, pending, result) = offerer.span.in_scope(|| {
        let mut change = offerer.rtc.sdp_api();

        let result = do_change(&mut change);

        let (offer, pending) = change.apply().unwrap();

        (offer, pending, result)
    });

    let answer = answerer
        .span
        .in_scope(|| answerer.rtc.sdp_api().accept_offer(offer).unwrap());

    offerer.span.in_scope(|| {
        offerer
            .rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .unwrap();
    });

    result
}

pub fn connect_l_r() -> (TestRtc, TestRtc) {
    let rtc1 = Rtc::builder()
        .set_rtp_mode(true)
        .enable_raw_packets(true)
        .build();
    let rtc2 = Rtc::builder()
        .set_rtp_mode(true)
        .enable_raw_packets(true)
        .set_reordering_size_audio(0)
        .build();
    connect_l_r_with_rtc(rtc1, rtc2)
}

pub fn connect_l_r_with_rtc(rtc1: Rtc, rtc2: Rtc) -> (TestRtc, TestRtc) {
    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc1);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc2);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();
    l.add_local_candidate(host1.clone());
    l.add_remote_candidate(host2.clone());
    r.add_local_candidate(host2);
    r.add_remote_candidate(host1);

    let finger_l = l.direct_api().local_dtls_fingerprint().clone();
    let finger_r = r.direct_api().local_dtls_fingerprint().clone();

    l.direct_api().set_remote_fingerprint(finger_r);
    r.direct_api().set_remote_fingerprint(finger_l);

    let creds_l = l.direct_api().local_ice_credentials();
    let creds_r = r.direct_api().local_ice_credentials();

    l.direct_api().set_remote_ice_credentials(creds_r);
    r.direct_api().set_remote_ice_credentials(creds_l);

    l.direct_api().set_ice_controlling(true);
    r.direct_api().set_ice_controlling(false);

    l.direct_api().start_dtls(true).unwrap();
    r.direct_api().start_dtls(false).unwrap();

    l.direct_api().start_sctp(true);
    r.direct_api().start_sctp(false);

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r).expect("clean progress");
    }

    (l, r)
}

impl Deref for TestRtc {
    type Target = Rtc;

    fn deref(&self) -> &Self::Target {
        &self.rtc
    }
}

impl DerefMut for TestRtc {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rtc
    }
}

pub fn init_log() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    static START: Once = Once::new();

    START.call_once(|| {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(env_filter)
            .init();
    });
}

/// Install the appropriate crypto provider for the current platform.
///
/// This function automatically selects the right crypto provider based on
/// the target platform:
/// - macOS/iOS: str0m-apple-crypto
/// - Windows: str0m-wincrypto (TODO)
/// - Linux/other: str0m default crypto (TODO)
pub fn init_crypto() {
    #[cfg(target_vendor = "apple")]
    {
        str0m_apple_crypto::default_provider().install_process_default();
    }

    // TODO: When wincrypto is added as a dependency
    // #[cfg(windows)]
    // {
    //     str0m_wincrypto::default_provider().install_process_default();
    // }

    // TODO: When OpenSSL/default is added as a dependency
    // #[cfg(all(not(target_vendor = "apple"), not(windows)))]
    // {
    //     // Use str0m's default crypto provider
    // }
}

/// Progress with packet replay - sends each packet multiple times to test replay protection.
pub fn progress_with_replay(
    l: &mut TestRtc,
    r: &mut TestRtc,
    replay: usize,
) -> Result<(), RtcError> {
    let (f, t) = if l.last < r.last { (l, r) } else { (r, l) };

    loop {
        f.span
            .in_scope(|| f.rtc.handle_input(Input::Timeout(f.last)))?;

        match f.span.in_scope(|| f.rtc.poll_output())? {
            Output::Timeout(v) => {
                let tick = f.last + Duration::from_millis(10);
                f.last = if v == f.last { tick } else { tick.min(v) };
                break;
            }
            Output::Transmit(v) => {
                let data = v.contents;
                for _ in 0..replay {
                    let input = Input::Receive(
                        f.last,
                        Receive {
                            proto: v.proto,
                            source: v.source,
                            destination: v.destination,
                            contents: (&*data).try_into().unwrap(),
                        },
                    );
                    t.span.in_scope(|| t.rtc.handle_input(input)).unwrap();
                }
            }
            Output::Event(v) => {
                f.events.push((f.last, v));
            }
        }
    }

    Ok(())
}

/// Connect two RTCs with mismatched fingerprints (L's remote fingerprint doesn't match R's local).
/// This should cause the DTLS handshake to fail.
pub fn connect_with_wrong_fingerprint() -> (TestRtc, TestRtc) {
    let rtc1 = Rtc::builder()
        .set_rtp_mode(true)
        .enable_raw_packets(true)
        .build();
    let rtc2 = Rtc::builder()
        .set_rtp_mode(true)
        .enable_raw_packets(true)
        .set_reordering_size_audio(0)
        .build();

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc1);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc2);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();
    l.add_local_candidate(host1.clone());
    l.add_remote_candidate(host2.clone());
    r.add_local_candidate(host2);
    r.add_remote_candidate(host1);

    let finger_l = l.direct_api().local_dtls_fingerprint().clone();
    let finger_r = r.direct_api().local_dtls_fingerprint().clone();

    // Set correct fingerprints for R, but WRONG for L
    // L gets its own fingerprint as the remote (which is wrong)
    l.direct_api().set_remote_fingerprint(finger_l.clone()); // WRONG! Should be finger_r
    r.direct_api().set_remote_fingerprint(finger_l);

    let creds_l = l.direct_api().local_ice_credentials();
    let creds_r = r.direct_api().local_ice_credentials();

    l.direct_api().set_remote_ice_credentials(creds_r);
    r.direct_api().set_remote_ice_credentials(creds_l);

    l.direct_api().set_ice_controlling(true);
    r.direct_api().set_ice_controlling(false);

    l.direct_api().start_dtls(true).unwrap();
    r.direct_api().start_dtls(false).unwrap();

    l.direct_api().start_sctp(true);
    r.direct_api().start_sctp(false);

    (l, r)
}
