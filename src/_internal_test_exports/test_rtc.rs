use std::net::Ipv4Addr;
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use rand::Rng;

use crate::change::SdpApi;
use crate::format::Codec;
use crate::format::PayloadParams;
use crate::net::Receive;
use crate::Candidate;
use crate::{Event, Input, Output, Rtc, RtcError};
use tracing::info_span;
use tracing::Span;

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

    pub fn params_vp9(&self) -> PayloadParams {
        self.rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::Vp9)
            .cloned()
            .unwrap()
    }

    pub fn params_h264(&self) -> PayloadParams {
        self.rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::H264)
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

pub fn progress_with_loss(l: &mut TestRtc, r: &mut TestRtc, loss: f32) -> Result<(), RtcError> {
    let (f, t) = if l.last < r.last { (l, r) } else { (r, l) };
    let mut rng = rand::thread_rng();

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
                if rng.gen::<f32>() <= loss {
                    // LOSS !
                    break;
                }

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
///
/// The closure is passed the [`SdpApi`] for the offer side to make any changes, these are then
/// applied locally and the offer is negotiated with the answerer.
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

pub fn connect_l_r() -> (TestRtc, TestRtc) {
    let rtc1 = Rtc::builder()
        .set_rtp_mode(true)
        .enable_raw_packets(true)
        .build();
    let rtc2 = Rtc::builder()
        .set_rtp_mode(true)
        .enable_raw_packets(true)
        // release packet straight away
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

    let finger_l = l.direct_api().local_dtls_fingerprint();
    let finger_r = r.direct_api().local_dtls_fingerprint();

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
