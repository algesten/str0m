use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::meta::Meta;
use str0m::{Event, Rtc, RtcError};

mod common;
use common::{TestRtc, init_crypto_default, init_log, progress};

/// Buffer type that wraps an `Arc<[u8]>`, enabling zero-copy SFU fanout:
/// the same allocation can be forwarded to multiple `Writer::write` calls
/// by cloning the `Arc` rather than copying the bytes.
#[derive(Clone)]
struct ArcInput(Arc<[u8]>);

impl AsRef<[u8]> for ArcInput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<ArcInput> for Vec<u8> {
    fn from(buf: ArcInput) -> Vec<u8> {
        buf.0.to_vec()
    }
}

impl From<Arc<[u8]>> for ArcInput {
    fn from(arc: Arc<[u8]>) -> Self {
        ArcInput(arc)
    }
}

struct ArcMeta;

impl Meta for ArcMeta {
    type Input = ArcInput;
}

#[test]
pub fn arc_input_write() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = std::time::Instant::now();

    let mut l: TestRtc<ArcMeta> = TestRtc::new_with_rtc(
        tracing::info_span!("L"),
        Rtc::builder().build_meta(now),
    );
    let mut r: TestRtc<ArcMeta> = TestRtc::new_with_rtc(
        tracing::info_span!("R"),
        Rtc::builder().build_meta(now),
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = common::negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None)
    });

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let pt = l
        .rtc
        .codec_config()
        .find(|p| p.spec().codec == Codec::Opus)
        .unwrap()
        .pt();

    // Shared buffer — in an SFU this Arc would be cloned once per egress leg
    // rather than copying the payload bytes for each destination.
    let shared: Arc<[u8]> = vec![1_u8; 80].into();

    loop {
        {
            let wallclock = l.start + l.duration();
            let time = l.duration().into();
            l.rtc
                .writer(mid)
                .unwrap()
                .write(pt, wallclock, time, ArcInput::from(shared.clone()))?;
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(2) {
            break;
        }
    }

    let received = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(received > 0, "no MediaData events received");

    Ok(())
}
