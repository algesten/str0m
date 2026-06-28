//! AMR-WB (RFC 4867 / RFC 7875) negotiation and media round-trip tests.

use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::{Codec, FormatParams};
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid};
use str0m::{Event, RtcConfig, RtcError};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

/// Speech bits carried by each AMR-WB frame type (RFC 4867 Table 1a). Reserved
/// types (10..=13) and the empty frames (14 speech-lost, 15 no-data) are 0.
const FT_BITS: [u16; 16] = [
    132, 177, 253, 285, 317, 365, 397, 461, 477, 40, 0, 0, 0, 0, 0, 0,
];

/// Build a valid 3GPP IF frame for AMR-WB frame type `ft` (Q = 1, good frame):
/// the header octet `(FT << 3) | (Q << 2)` followed by the speech bytes filled
/// with `fill`. Padding bits in the final speech byte are zeroed so the frame
/// round-trips byte-for-byte in both the octet-aligned and bandwidth-efficient
/// layouts.
fn if_frame(ft: u8, fill: u8) -> Vec<u8> {
    let bits = FT_BITS[ft as usize] as usize;
    let mut data = vec![fill; bits.div_ceil(8)];
    let remainder = bits % 8;
    if remainder != 0 {
        if let Some(last) = data.last_mut() {
            *last &= 0xffu8 << (8 - remainder);
        }
    }
    let mut v = vec![(ft << 3) | (1 << 2)];
    v.extend(data);
    v
}

/// Assert a received IF frame is an intact round-trip: a 1-octet header with the
/// good (Q) bit set, the correct length for its frame type, and — for frames that
/// carry speech — byte-identical to `if_frame(ft, fill)`.
fn assert_pristine_frame(data: &[u8]) {
    assert!(!data.is_empty(), "empty AMR-WB frame");
    let ft = (data[0] >> 3) & 0x0f;
    assert_eq!((data[0] >> 2) & 1, 1, "Q bit should be 1 (good frame)");
    let nbytes = (FT_BITS[ft as usize] as usize).div_ceil(8);
    assert_eq!(data.len(), 1 + nbytes, "wrong length for FT {ft}");
    if nbytes > 0 {
        let expected = if_frame(ft, data[1]);
        assert_eq!(data, expected.as_slice(), "FT {ft} corrupted in transit");
    }
}

/// A config closure that enables a single AMR-WB payload type (PT 122) with the
/// given `octet_align` setting. `None` and `Some(false)` are bandwidth-efficient
/// (the RFC default); `Some(true)` is octet-aligned.
fn amr_wb_config(octet_align: Option<bool>) -> impl FnOnce(RtcConfig) -> RtcConfig {
    move |c| {
        let mut c = c.clear_codecs();
        c.codec_config().add_config(
            122u8.into(),
            None,
            Codec::AmrWb,
            Frequency::SIXTEEN_KHZ,
            Some(1),
            FormatParams {
                octet_align,
                mode_change_capability: Some(2),
                max_red: Some(0),
                ..Default::default()
            },
        );
        c
    }
}

/// Build two peers with a single AMR-WB PT using `octet_align`, negotiate, and
/// drive them to connected. Returns the peers and the media mid.
fn connect_amr_wb(octet_align: Option<bool>) -> (TestRtc, TestRtc, Mid) {
    let mut l = TestRtc::new_with_config(Peer::Left, amr_wb_config(octet_align));
    let mut r = TestRtc::new_with_config(Peer::Right, amr_wb_config(octet_align));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer).unwrap();
    l.rtc.sdp_api().accept_answer(pending, answer).unwrap();

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r).unwrap();
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    (l, r, mid)
}

/// Negotiate AMR-WB with the given layout, then send one frame of every mode
/// (the nine speech modes, SID, and no-data) repeatedly and verify each is
/// received intact at the 16 kHz media clock.
fn round_trip_all_modes(octet_align: Option<bool>) {
    init_log();
    init_crypto_default();

    let (mut l, mut r, mid) = connect_amr_wb(octet_align);

    let pt = l
        .rtc
        .codec_config()
        .find(|p| p.spec().codec == Codec::AmrWb)
        .expect("AMR-WB to be negotiated")
        .pt();

    // Every AMR-WB mode: the nine speech modes, the SID frame, and no-data.
    const MODES: [u8; 11] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15];

    let mut samples: u64 = 0;
    let mut idx: usize = 0;
    loop {
        let ft = MODES[idx % MODES.len()];
        let frame = if_frame(ft, idx as u8);
        let wallclock = l.start + l.duration();
        let time = MediaTime::new(samples, Frequency::SIXTEEN_KHZ);
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, frame)
            .unwrap();
        samples += 320;
        idx += 1;

        progress(&mut l, &mut r).unwrap();
        if l.duration() > Duration::from_secs(1) {
            break;
        }
    }

    let media: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::MediaData(d) => Some(d),
            _ => None,
        })
        .collect();

    assert!(
        !media.is_empty(),
        "R received no AMR-WB MediaData (octet_align={octet_align:?})"
    );

    let (mut saw_speech, mut saw_sid, mut saw_no_data) = (false, false, false);
    for d in &media {
        assert_eq!(d.params.spec().codec, Codec::AmrWb);
        assert_eq!(d.time.frequency(), Frequency::SIXTEEN_KHZ);
        assert_pristine_frame(&d.data);
        match (d.data[0] >> 3) & 0x0f {
            0..=8 => saw_speech = true,
            9 => saw_sid = true,
            15 => saw_no_data = true,
            _ => {}
        }
    }
    assert!(
        saw_speech && saw_sid && saw_no_data,
        "expected speech, SID and no-data frames to all round-trip (octet_align={octet_align:?})"
    );
}

/// Negotiate AMR-WB and verify both the negotiated parameters and that the
/// generated offer carries the expected rtpmap/fmtp lines.
#[test]
pub fn amr_wb_negotiates_with_default_fmtp() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, |c| c.clear_codecs().enable_amr_wb(true));
    let mut r = TestRtc::new_with_config(Peer::Right, |c| c.clear_codecs().enable_amr_wb(true));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    // The offer advertises AMR-WB the way production IMS/VoLTE endpoints expect.
    let offer_sdp = offer.to_sdp_string();
    assert!(
        offer_sdp.contains("a=rtpmap:122 AMR-WB/16000/1"),
        "offer missing AMR-WB rtpmap:\n{offer_sdp}"
    );
    assert!(
        offer_sdp.contains("a=fmtp:122 octet-align=1;mode-change-capability=2;max-red=0"),
        "offer missing AMR-WB fmtp:\n{offer_sdp}"
    );

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    for peer in [&l, &r] {
        let params = peer
            .rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::AmrWb)
            .cloned()
            .expect("AMR-WB to be negotiated");
        let spec = params.spec();
        assert_eq!(spec.clock_rate, Frequency::SIXTEEN_KHZ);
        assert_eq!(spec.channels, Some(1));
        assert_eq!(spec.format.octet_align, Some(true));
        assert_eq!(spec.format.mode_change_capability, Some(2));
        assert_eq!(spec.format.max_red, Some(0));
    }

    Ok(())
}

/// Octet-aligned (`octet-align=1`) end-to-end round-trip across every mode.
#[test]
pub fn amr_wb_octet_aligned_round_trip() {
    round_trip_all_modes(Some(true));
}

/// Bandwidth-efficient (no `octet-align`, the RFC default) round-trip. This
/// exercises the bit-packed packetizer/depacketizer path negotiated end-to-end.
#[test]
pub fn amr_wb_bandwidth_efficient_round_trip() {
    round_trip_all_modes(None);
}

/// An explicit `octet-align=0` is also bandwidth-efficient; round-trip it too.
#[test]
pub fn amr_wb_octet_align_zero_round_trip() {
    round_trip_all_modes(Some(false));
}

/// A bandwidth-efficient config advertises AMR-WB without `octet-align`, and the
/// layout stays unset on both peers after negotiation.
#[test]
pub fn amr_wb_bandwidth_efficient_offer_omits_octet_align() {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, amr_wb_config(None));
    let mut r = TestRtc::new_with_config(Peer::Right, amr_wb_config(None));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let offer_sdp = offer.to_sdp_string();
    assert!(
        offer_sdp.contains("a=rtpmap:122 AMR-WB/16000/1"),
        "offer missing AMR-WB rtpmap:\n{offer_sdp}"
    );
    assert!(
        offer_sdp.contains("a=fmtp:122 mode-change-capability=2;max-red=0"),
        "bandwidth-efficient offer should carry the hint fmtp:\n{offer_sdp}"
    );
    assert!(
        !offer_sdp.contains("octet-align"),
        "bandwidth-efficient offer must not advertise octet-align:\n{offer_sdp}"
    );

    let answer = r.rtc.sdp_api().accept_offer(offer).unwrap();
    l.rtc.sdp_api().accept_answer(pending, answer).unwrap();

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r).unwrap();
    }

    for peer in [&l, &r] {
        let spec = peer
            .rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::AmrWb)
            .expect("AMR-WB to be negotiated")
            .spec();
        assert_eq!(
            spec.format.octet_align, None,
            "bandwidth-efficient negotiation leaves octet-align unset"
        );
    }
}
