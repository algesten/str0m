use std::time::{Duration, Instant};

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::net::Receive;
use str0m::rtp::{ExtensionValues, RawPacket, SeqNo, Ssrc};
use str0m::{Event, Output, Rtc, RtcError};

mod common;
use common::{connect_l_r, connect_l_r_with_rtc, init_crypto_default, init_log, TestRtc};
use tracing::Span;

const EXPECTED_PACKETS: usize = 50;
const REPLAY_PER_PACKET: usize = 5;

#[test]
pub fn srtp_replay_attack_rtp_mode() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();
    let mid = "aud".into();

    let ssrc_tx: Ssrc = 42.into();
    l.with_direct_api(|api| { api.declare_media(mid, MediaKind::Audio); });
    l.with_direct_api(|api| { api.declare_stream_tx(ssrc_tx, None, mid, None); });
    r.with_direct_api(|api| { api.declare_media(mid, MediaKind::Audio); });

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
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

            let exts = ExtensionValues {
                audio_level: Some(-42),
                voice_activity: Some(false),
                ..Default::default()
            };

            // Use transaction API: write_rtp returns RtcTx<Poll> that must be polled
            let tx = l.rtc.begin(l.last).expect("begin");
            let tx = l.span.in_scope(|| {
                tx.write_rtp(
                    ssrc_tx,
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    vec![1, 3, 3, 7],
                )
            })?;

            // Poll and replay transmits to receiver
            let (new_last, events) =
                poll_and_replay_tx(&l.span, &mut r, tx, l.last, REPLAY_PER_PACKET)?;
            l.last = new_last;
            l.events.extend(events);
            send_count += 1;
        } else {
            // Just advance time without writing
            let tx = l.rtc.begin(l.last).expect("begin").finish();
            let (new_last, events) =
                poll_and_replay_tx(&l.span, &mut r, tx, l.last, REPLAY_PER_PACKET)?;
            l.last = new_last;
            l.events.extend(events);
        }

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
    l.with_direct_api(|api| { api.declare_media(mid, MediaKind::Audio); });
    l.with_direct_api(|api| { api.declare_stream_tx(ssrc_tx, None, mid, None); });
    r.with_direct_api(|api| { api.declare_media(mid, MediaKind::Audio); });

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
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

            let exts = ExtensionValues {
                audio_level: Some(-42),
                voice_activity: Some(false),
                ..Default::default()
            };

            // Use transaction API: write_rtp returns RtcTx<Poll> that must be polled
            let tx = l.rtc.begin(l.last).expect("begin");
            let tx = l.span.in_scope(|| {
                tx.write_rtp(
                    ssrc_tx,
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    vec![1, 3, 3, 7],
                )
            })?;

            // Poll and replay transmits to receiver
            let (new_last, events) =
                poll_and_replay_tx(&l.span, &mut r, tx, l.last, REPLAY_PER_PACKET)?;
            l.last = new_last;
            l.events.extend(events);
            send_count += 1;
        } else {
            // Just advance time without writing
            let tx = l.rtc.begin(l.last).expect("begin").finish();
            let (new_last, events) =
                poll_and_replay_tx(&l.span, &mut r, tx, l.last, REPLAY_PER_PACKET)?;
            l.last = new_last;
            l.events.extend(events);
        }

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

/// Poll a transaction to timeout, replaying transmits to the receiver.
/// Returns the new timestamp for l and any events collected.
fn poll_and_replay_tx<'a>(
    span: &Span,
    r: &mut TestRtc,
    tx: str0m::RtcTx<'a, str0m::Poll>,
    mut last: Instant,
    replay: usize,
) -> Result<(Instant, Vec<(Instant, Event)>), RtcError> {
    let mut tx = tx;
    let mut events = Vec::new();

    loop {
        match span.in_scope(|| tx.poll()).expect("poll") {
            Output::Timeout(v) => {
                let tick = last + Duration::from_millis(10);
                last = if v == last { tick } else { tick.min(v) };
                break;
            }
            Output::Transmit(t, pkt) => {
                tx = t;
                let data = pkt.contents.to_vec();

                // Replay the packet to the receiver
                for _ in 0..replay {
                    let recv = Receive {
                        proto: pkt.proto,
                        source: pkt.source,
                        destination: pkt.destination,
                        contents: (&*data).try_into().unwrap(),
                        recv_time: Some(last),
                    };
                    let recv_tx = r.rtc.begin(last).expect("begin");
                    let mut recv_tx = r.span.in_scope(|| recv_tx.receive(recv))?;

                    // Poll receiver to timeout
                    loop {
                        match r.span.in_scope(|| recv_tx.poll()).expect("poll") {
                            Output::Timeout(_) => break,
                            Output::Transmit(th, _) => recv_tx = th,
                            Output::Event(th, ev) => {
                                recv_tx = th;
                                r.events.push((r.last, ev));
                            }
                        }
                    }
                }
            }
            Output::Event(t, ev) => {
                tx = t;
                events.push((last, ev));
            }
        }
    }

    Ok((last, events))
}

/// Progress without writing - just advance time and replay transmits.
fn progress_with_replay(l: &mut TestRtc, r: &mut TestRtc, replay: usize) -> Result<(), RtcError> {
    // Create transaction, poll, and collect results
    let tx = l.rtc.begin(l.last).expect("begin").finish();
    let span = l.span.clone();
    let last = l.last;

    let (new_last, events) = poll_and_replay_tx(&span, r, tx, last, replay)?;
    l.last = new_last;
    l.events.extend(events);
    Ok(())
}
