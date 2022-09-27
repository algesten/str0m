use std::net::Ipv4Addr;
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use net_::Receive;
use str0m::media::{Codec, Direction, MediaKind, MediaTime};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcError};
use tracing::{info_span, Span};

pub struct TestRtc {
    pub span: Span,
    pub rtc: Rtc,
    pub start: Instant,
    pub last: Instant,
    pub events: Vec<Event>,
}

impl TestRtc {
    pub fn new(span: Span) -> Self {
        let now = Instant::now();
        TestRtc {
            span,
            rtc: Rtc::new(),
            start: now,
            last: now,
            events: vec![],
        }
    }

    pub fn duration(&self) -> Duration {
        self.last - self.start
    }
}

pub fn progress(l: &mut TestRtc, r: &mut TestRtc) -> Result<(), RtcError> {
    let (f, t) = if l.last < r.last { (l, r) } else { (r, l) };

    loop {
        f.span
            .in_scope(|| f.rtc.handle_input(Input::Timeout(f.last)))?;

        match f.span.in_scope(|| f.rtc.poll_output())? {
            Output::Timeout(v) => {
                f.last = v;
                break;
            }
            Output::Transmit(v) => {
                let data = v.contents;
                let input = Input::Receive(
                    f.last,
                    Receive {
                        source: v.source,
                        destination: v.destination,
                        contents: (&*data).try_into()?,
                    },
                );
                t.span.in_scope(|| t.rtc.handle_input(input))?;
            }
            Output::Event(v) => {
                f.events.push(v);
            }
        }
    }

    Ok(())
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
    use std::env;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}

#[test]
pub fn bidirectional_same_m_line() -> Result<(), RtcError> {
    init_log();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into())?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into())?;
    l.add_local_candidate(host1);
    r.add_local_candidate(host2);

    let mut change = l.create_offer();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv);
    let offer = change.apply();

    let answer = r.accept_offer(offer)?;
    l.pending_changes().unwrap().accept_answer(answer)?;

    loop {
        if l.ice_connection_state().is_connected() || r.ice_connection_state().is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.media(mid).unwrap().codecs()[0];
    assert_eq!(params.codec(), Codec::Opus);
    let pt = params.pt();
    const STEP: MediaTime = MediaTime::new(960, 48_000);

    let mut time_l: MediaTime = l.duration().into();
    time_l = time_l.rebase(48_000);
    let mut time_r: MediaTime = r.duration().into();
    time_r = time_r.rebase(48_000);

    let data_a = vec![1_u8; 80];
    let data_b = vec![2_u8; 80];

    loop {
        while l.duration() > time_l.into() {
            let free = l
                .media(mid)
                .unwrap()
                .get_writer(pt)
                .write(time_l, &data_a)?;
            time_l = time_l + STEP;
            if free == 0 {
                break;
            };
        }

        while r.duration() > time_r.into() {
            let free = r
                .media(mid)
                .unwrap()
                .get_writer(pt)
                .write(time_r, &data_b)?;
            time_r = time_r + STEP;
            if free == 0 {
                break;
            };
        }

        progress(&mut l, &mut r)?;

        if time_l > MediaTime::from_seconds(30) {
            break;
        }
    }

    println!("{:?}", r.events);

    Ok(())
}
