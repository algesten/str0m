#![allow(unused)]
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use str0m::net::Receive;
use str0m::{Event, Input, Output, Rtc, RtcError};
use tracing::Span;

pub struct TestRtc {
    pub span: Span,
    pub rtc: Rtc,
    pub start: Instant,
    pub last: Instant,
    pub events: Vec<Event>,
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
}

pub fn progress(l: &mut TestRtc, r: &mut TestRtc) -> Result<(), RtcError> {
    let (f, t) = if l.last < r.last { (l, r) } else { (r, l) };

    loop {
        f.span
            .in_scope(|| f.rtc.handle_input(Input::Timeout(f.last)))?;

        match f.span.in_scope(|| f.rtc.poll_output())? {
            Output::Timeout(v) => {
                let tick = f.last + Duration::from_millis(100);
                f.last = if v == f.last { tick } else { tick.min(v) };
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
        env::set_var("RUST_LOG", "debug");
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}
