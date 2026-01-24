use std::time::Duration;

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::net::Receive;
use str0m::rtp::{ExtensionValues, RawPacket, SeqNo, Ssrc};
use str0m::{Event, Output, Rtc, RtcError};

mod common;
use common::{connect_l_r, connect_l_r_with_rtc, init_crypto_default, init_log, TestRtc};

const EXPECTED_PACKETS: usize = 50;
const REPLAY_PER_PACKET: usize = 5;

#[test]
pub fn srtp_replay_attack_rtp_mode() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();
    let mid = "aud".into();

    let ssrc_tx: Ssrc = 42.into();
    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Audio);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();
    let mut write_at = l.last + Duration::from_millis(20);
    let mut seq_no: SeqNo = 0_u64.into();
    let mut time = 0;
    let mut send_count = 0;
    const TIME_INTERVAL: u32 = 960;

    // Process the DTLS Handshake, before we start duplicating SRTP packets
    progress_with_replay(&mut l, &mut r, 1)?;

    loop {
        if l.start + l.duration() > write_at && send_count < EXPECTED_PACKETS {
            seq_no.inc();
            time += TIME_INTERVAL;
            write_at = l.last + Duration::from_millis(20);
            let wallclock = l.start + l.duration();
            let mut direct = l.direct_api();
            let stream = direct.stream_tx(&ssrc).unwrap();
            let exts = ExtensionValues {
                audio_level: Some(-42),
                voice_activity: Some(false),
                ..Default::default()
            };

            stream
                .write_rtp(
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    vec![1, 3, 3, 7],
                )
                .expect("clean write");
            send_count += 1;
        }

        progress_with_replay(&mut l, &mut r, REPLAY_PER_PACKET)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let rtp_raw_rx: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Some(RawPacket::RtpRx(header, payload)) = e.as_raw_packet() {
                Some((header, payload))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(rtp_raw_rx.len(), EXPECTED_PACKETS);

    let rtp: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::RtpPacket(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(rtp.len(), EXPECTED_PACKETS);
    Ok(())
}

#[test]
pub fn srtp_replay_attack_frame_mode() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc1 = Rtc::builder()
        .set_rtp_mode(true)
        .enable_raw_packets(true)
        .build();
    let rtc2 = Rtc::builder()
        .enable_raw_packets(true)
        // release packet straight away
        .set_reordering_size_audio(0)
        .build();

    let (mut l, mut r) = connect_l_r_with_rtc(rtc1, rtc2);

    let mid = "aud".into();

    let ssrc_tx: Ssrc = 42.into();
    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Audio);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();
    let mut write_at = l.last + Duration::from_millis(20);
    let mut seq_no: SeqNo = 0_u64.into();
    let mut time = 0;
    let mut send_count = 0;
    const TIME_INTERVAL: u32 = 960;

    // Process the DTLS Handshake, before we start duplicating SRTP packets
    progress_with_replay(&mut l, &mut r, 1)?;

    loop {
        if l.start + l.duration() > write_at && send_count < EXPECTED_PACKETS {
            seq_no.inc();
            time += TIME_INTERVAL;
            write_at = l.last + Duration::from_millis(20);
            let wallclock = l.start + l.duration();
            let mut direct = l.direct_api();
            let stream = direct.stream_tx(&ssrc).unwrap();
            let exts = ExtensionValues {
                audio_level: Some(-42),
                voice_activity: Some(false),
                ..Default::default()
            };

            stream
                .write_rtp(
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    vec![1, 3, 3, 7],
                )
                .expect("clean write");
            send_count += 1;
        }

        progress_with_replay(&mut l, &mut r, REPLAY_PER_PACKET)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let rtp_raw_rx: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Some(RawPacket::RtpRx(header, payload)) = e.as_raw_packet() {
                Some((header, payload))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(rtp_raw_rx.len(), EXPECTED_PACKETS);

    let media: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::MediaData(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(media.len(), EXPECTED_PACKETS);
    Ok(())
}

pub fn progress_with_replay(
    l: &mut TestRtc,
    r: &mut TestRtc,
    replay: usize,
) -> Result<(), RtcError> {
    let (f, t) = if l.last < r.last { (l, r) } else { (r, l) };

    // Use transaction API - matches original behavior:
    // Poll sender until timeout, immediately forward transmits to receiver
    let tx = f.rtc.begin(f.last);
    let mut tx = tx.finish();

    loop {
        match f.span.in_scope(|| tx.poll()) {
            Output::Timeout(v) => {
                let tick = f.last + Duration::from_millis(10);
                f.last = if v == f.last { tick } else { tick.min(v) };
                break;
            }
            Output::Transmit(t_handle, v) => {
                tx = t_handle;
                let data = v.contents.to_vec();
                // Replay the packet to the receiver (like original)
                for _ in 0..replay {
                    let recv = Receive {
                        proto: v.proto,
                        source: v.source,
                        destination: v.destination,
                        contents: (&*data).try_into().unwrap(),
                        timestamp: Some(f.last),
                    };
                    let recv_tx = t.rtc.begin(f.last);
                    let mut recv_tx = t.span.in_scope(|| recv_tx.receive(f.last, recv))?;
                    // Poll receive to completion
                    loop {
                        match t.span.in_scope(|| recv_tx.poll()) {
                            Output::Timeout(_) => break,
                            Output::Transmit(th, _) => recv_tx = th,
                            Output::Event(th, ev) => {
                                recv_tx = th;
                                t.events.push((t.last, ev));
                            }
                        }
                    }
                }
            }
            Output::Event(t_handle, v) => {
                tx = t_handle;
                f.events.push((f.last, v));
            }
        }
    }

    Ok(())
}
