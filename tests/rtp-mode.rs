use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Duration;
use tracing::info_span;

use str0m::format::Codec;
use str0m::media::{ExtensionValues, MediaKind, MediaTime, RtpPacketReceived, RtpPacketToSend};
use str0m::{Candidate, Event, Rtc, RtcError};

mod common;
use common::{init_log, progress, TestRtc};

#[test]
pub fn rtp_mode() -> Result<(), RtcError> {
    init_log();

    let rtc1 = Rtc::builder().build();
    let rtc2 = Rtc::builder().build();

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc1);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc2);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into())?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into())?;
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

    let mid = "mid".into();
    // TODO: Test RTX
    let primary_to_rtx_ssrc_mapping = vec![];
    let max_retain = 3;
    let enable_nack = false;
    l.direct_api()
        .add_rtp_packet_sender(
            mid,
            MediaKind::Audio,
            max_retain,
            primary_to_rtx_ssrc_mapping,
            None,
        )
        .unwrap();
    r.direct_api()
        .add_rtp_packet_receiver(mid, MediaKind::Audio, enable_nack)
        .unwrap();

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.media(mid).unwrap().payload_params()[0];
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let ssrc = 42.into();

    let to_write = vec![
        RtpPacketToSend {
            mid,
            ssrc,
            sequence_number: 47000.into(),
            timestamp: 10000,
            payload_type: pt,
            marker: false,
            header_extensions: Default::default(),
            payload: vec![0x1, 0x2, 0x3, 0x4],
        },
        RtpPacketToSend {
            mid,
            ssrc,
            sequence_number: 47003.into(),
            timestamp: 14000,
            payload_type: pt,
            marker: false,
            header_extensions: Default::default(),
            payload: vec![0x9, 0xa, 0xb, 0xc],
        },
        RtpPacketToSend {
            mid,
            ssrc,
            sequence_number: 47001.into(),
            timestamp: 12000,
            payload_type: pt,
            marker: true,
            header_extensions: Default::default(),
            payload: vec![0x5, 0x6, 0x7, 0x8],
        },
    ];

    let mut to_write: VecDeque<_> = to_write.into();

    let mut write_at = l.last + Duration::from_millis(300);

    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            if let Some(packet) = to_write.pop_front() {
                let now = l.start + l.duration();
                l.direct_api().send_rtp_packet(packet, now).unwrap();
            }
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    let rtp_packets_received: Vec<_> = r
        .events
        .into_iter()
        .filter_map(|e| {
            if let Event::RtpPacketReceived(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    let mut header_extensions = ExtensionValues::default();
    header_extensions.mid = Some(mid);
    let expected = vec![
        RtpPacketReceived {
            mid,
            rid: None,
            ssrc,
            sequence_number: 47000.into(),
            timestamp: MediaTime::new(10000, 48000),
            payload_type: pt,
            marker: false,
            header_extensions,
            payload: vec![0x1, 0x2, 0x3, 0x4],
        },
        RtpPacketReceived {
            mid,
            rid: None,
            ssrc,
            sequence_number: 47003.into(),
            timestamp: MediaTime::new(14000, 48000),
            payload_type: pt,
            marker: false,
            header_extensions,
            payload: vec![0x9, 0xa, 0xb, 0xc],
        },
        RtpPacketReceived {
            mid,
            rid: None,
            ssrc,
            sequence_number: 47001.into(),
            timestamp: MediaTime::new(12000, 48000),
            payload_type: pt,
            marker: true,
            header_extensions,
            payload: vec![0x5, 0x6, 0x7, 0x8],
        },
    ];

    assert_eq!(expected[0], rtp_packets_received[0]);
    Ok(())
}
