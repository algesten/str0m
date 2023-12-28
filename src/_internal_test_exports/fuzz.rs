//! Exported fuzz targets to get them part of the compilation with feature `_internal_test_exports`.

use std::time::Duration;
use std::time::Instant;

pub fn rtx_buffer(data: &[u8]) {
    use crate::streams::rtx_cache_buf::EvictingBuffer;

    if data.len() < 4 {
        return;
    }

    let buf_size = u16::from_be_bytes([data[0], data[1]]);
    let max_age = data[2] as u64;
    let max_size = data[3] as usize;
    let mut buf = EvictingBuffer::new(buf_size as usize, Duration::from_secs(max_age), max_size);
    let mut now = Instant::now();
    let mut pos = 0;

    for d in &data[4..] {
        now += Duration::from_millis(*d as u64);
        if d % 2 == 0 {
            buf.maybe_evict(now)
        } else {
            pos += *d as u64;
            buf.push(pos, now, d);
        }
    }
}

pub fn init_log() {
    use std::env;
    use std::sync::Once;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "str0m=trace");
    }

    static START: Once = Once::new();

    START.call_once(|| {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();
    });
}

pub fn rtp_data(data: &[u8]) {
    init_log();

    if data.len() < 20 {
        return;
    }

    use crate::media::MediaKind;
    use crate::rtp::ExtensionValues;
    use crate::rtp::Ssrc;

    use super::test_rtc::{connect_l_r, progress};

    let (mut l, mut r) = connect_l_r();

    let mid = "aud".into();

    // In this example we are using MID only (no RID) to identify the incoming media.
    let ssrc_tx: Ssrc = 42.into();

    let kind = if data[0] < 128 {
        MediaKind::Audio
    } else {
        MediaKind::Audio
    };

    l.direct_api().declare_media(mid, kind);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);
    r.direct_api().declare_media(mid, kind);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let codec_count = l.codec_config().len();
    let codec_idx = ((data[1] as f32 / 256.0) * codec_count as f32).floor() as usize;
    let params = l.codec_config()[codec_idx];

    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    let pt = params.pt();

    let mut write_at = l.last + Duration::from_millis(300);

    let mut data = &data[2..];

    loop {
        if data.len() < 20 {
            break;
        }

        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            let wallclock = l.start + l.duration();

            let mut direct = l.direct_api();
            let stream = direct.stream_tx(&ssrc).unwrap();

            let exts = ExtensionValues::default();

            let seq_no = u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])
            .into();

            let time = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let size = u16::from_be_bytes([data[12], data[13]]) as usize;
            let packet = &data[14..];
            let max = size.min(packet.len());
            let packet = &packet[..max];

            data = &data[14 + max..];

            stream
                .write_rtp(
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    packet.to_vec(),
                )
                .expect("clean write");
        }

        progress(&mut l, &mut r).ok();
    }
}
