use std::net::Ipv4Addr;
use std::time::{Instant, SystemTime};

use str0m::change::{SdpAnswer, SdpOffer};
use str0m::error::PacketError;
use str0m::format::Codec;
use str0m::media::{Direction, Frequency, MediaData, MediaKind, MediaTime, Mid};
use str0m::rtp::dependency_descriptor::{DecodeTargetIndication, DependencyDescriptor, URI};
use str0m::rtp::dependency_descriptor::{DependencyDescriptorError, DependencyDescriptorReceiver};
use str0m::rtp::dependency_descriptor::{ReceivedDependencyDescriptor, Serializer};
use str0m::rtp::vla::encode_leb_u63;
use str0m::rtp::{AbsCaptureTime, VideoOrientation};
use str0m::rtp::{Extension, ExtensionMap, ExtensionValues, RawPacket, RtpHeader, RtpWrite, Ssrc};
use str0m::{DATAGRAM_MTU_TARGET, DATAGRAM_MTU_TARGET_MAX, DATAGRAM_MTU_TARGET_MIN};
use str0m::{Event, Rtc, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{TestRtc, connect_l_r_with_rtc, init_crypto_default, init_log, progress};

/// One decode target, one switch template, no chains, with the structure attached.
fn descriptor() -> DependencyDescriptor {
    DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80, 0, 0xe0]).unwrap()
}

/// Progress the pair until `done`.
fn progress_until(
    l: &mut TestRtc,
    r: &mut TestRtc,
    done: impl Fn(&TestRtc, &TestRtc) -> bool,
) -> Result<(), RtcError> {
    for _ in 0..1000 {
        if done(l, r) {
            return Ok(());
        }
        progress(l, r)?;
    }
    panic!("the pair did not get there");
}

fn media_data_count(rtc: &TestRtc) -> usize {
    rtc.events
        .iter()
        .filter(|(_, event)| matches!(event, Event::MediaData(_)))
        .count()
}

#[test]
fn dependency_descriptor_rtp_mode_preserves_wire_bytes() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let config = || {
        Rtc::builder()
            .set_rtp_mode(true)
            .set_extension(14, Extension::with_serializer(URI, Serializer))
    };
    let (mut l, mut r) = connect_l_r_with_rtc(config().build(now), config().build(now));
    let mid = "vid".into();
    let ssrc: Ssrc = 1000.into();
    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api().declare_stream_tx(ssrc, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api().expect_stream_rx(ssrc, None, mid, None);
    let pt = l.params_vp8().pt();
    let mut expected = Vec::new();
    let last = l.last;
    for (index, size) in [6, 16, 17, 255].into_iter().enumerate() {
        // Each packet is a whole frame. Only the first attaches the structure.
        let mut bytes = if index == 0 {
            descriptor().as_bytes().to_vec()
        } else {
            vec![0xc0, 0, 0]
        };
        bytes[1..3].copy_from_slice(&(index as u16).to_be_bytes());
        bytes.resize(size, 0);
        let raw = DependencyDescriptor::from_bytes(bytes).unwrap();
        let mut extensions = ExtensionValues::default();
        extensions.user_values.set(raw.clone());
        expected.push(raw);
        l.direct_api().stream_tx(&ssrc).unwrap().write_rtp(
            RtpWrite::new(
                pt,
                (1000 + index as u64).into(),
                index as u32 * 3000,
                last,
                [0xaa; 10],
            )
            .marker(true)
            .ext_vals(extensions),
        );
    }
    let mut received = Vec::new();
    for _ in 0..100 {
        progress(&mut l, &mut r)?;
        for (_, event) in r.events.drain(..) {
            if let Event::RtpPacket(packet) = event {
                assert_eq!(packet.header.ssrc, ssrc);
                received.push(
                    packet
                        .header
                        .ext_vals
                        .user_values
                        .get::<DependencyDescriptor>()
                        .expect("DD on every packet")
                        .clone(),
                );
            }
        }
        if received.len() == expected.len() {
            break;
        }
    }
    assert_eq!(received, expected);
    Ok(())
}

/// A pair negotiated with SDP, where the left offers DD on video, and the right supports it if
/// `right_supports_dd`. The answer does not negotiate mixed RTP header extension formats.
fn sdp_pair(
    right_supports_dd: bool,
    config: RtcConfig,
) -> Result<(TestRtc, TestRtc, Mid), RtcError> {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let config = config.enable_raw_packets(true);
    let rtc_l = config
        .clone()
        .set_extension(14, Extension::with_serializer(URI, Serializer))
        .build(now);
    let mut builder_r = config;
    if right_supports_dd {
        builder_r = builder_r.set_extension(16, Extension::with_serializer(URI, Serializer));
    }
    let rtc_r = builder_r.build(now);
    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc_l);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);
    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());
    let mut change = l.sdp_api();
    let video = change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let audio = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let offer_sdp = offer.to_sdp_string();
    assert_eq!(offer_sdp.matches(URI).count(), 1, "DD is video-only");
    let offer = SdpOffer::from_sdp_string(&offer_sdp).unwrap();
    let answer = r.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer
        .to_sdp_string()
        .replace("a=extmap-allow-mixed\r\n", "");
    assert_eq!(
        answer_sdp.matches(URI).count(),
        usize::from(right_supports_dd)
    );
    let answer = SdpAnswer::from_sdp_string(&answer_sdp).unwrap();
    l.sdp_api().accept_answer(pending, answer)?;
    for rtc in [&l, &r] {
        // Both sides use the offered ID.
        assert_eq!(dd_id(rtc, video), right_supports_dd.then_some(14));
        assert_eq!(dd_id(rtc, audio), None);
    }
    finish_connecting(&mut l, &mut r)?;
    Ok((l, r, video))
}

/// The ID that DD was negotiated with on the m-line of `mid`, if any.
fn dd_id(rtc: &TestRtc, mid: Mid) -> Option<u8> {
    let exts = rtc.media(mid).unwrap().remote_extmap();
    exts.iter()
        .find(|(_, ext)| ext.as_uri() == URI)
        .map(|(id, _)| id)
}

/// Progress a negotiated pair until it is connected, and forget the events so far.
fn finish_connecting(l: &mut TestRtc, r: &mut TestRtc) -> Result<(), RtcError> {
    progress_until(l, r, |l, r| l.is_connected() && r.is_connected())?;
    l.events.clear();
    r.events.clear();
    Ok(())
}

/// The outcome of writing one frame.
struct SentFrame {
    /// Frames received by the other side.
    frames: Vec<MediaData>,
    /// Headers and bytes of the RTP packets sent for the frame, before encryption.
    packets: Vec<(RtpHeader, Vec<u8>)>,
}

/// Write a frame to a peer that supports DD if `supports_dd`.
fn send_frame_to(
    supports_dd: bool,
    descriptor: Option<DependencyDescriptor>,
    size: usize,
) -> Result<SentFrame, RtcError> {
    send_video_frame(
        supports_dd,
        Codec::Vp8,
        descriptor,
        size,
        DATAGRAM_MTU_TARGET,
    )
}

fn video_frame(codec: Codec, size: usize) -> Vec<u8> {
    let mut frame = match codec {
        Codec::Vp8 => Vec::new(),
        Codec::Vp9 => vec![0x80],
        Codec::Av1 => {
            let mut frame = vec![0x32];
            let mut length = [0; 9];
            let count = encode_leb_u63(size as u64, &mut length);
            frame.extend_from_slice(&length[..count]);
            frame
        }
        Codec::H264 => vec![0, 0, 0, 1, 0x65],
        Codec::H265 => vec![0, 0, 0, 1, 0x26, 0x01],
        _ => panic!("unsupported test codec: {codec:?}"),
    };
    frame.resize(frame.len() + size, 0xaa);
    frame
}

fn send_video_frame(
    supports_dd: bool,
    codec: Codec,
    descriptor: Option<DependencyDescriptor>,
    size: usize,
    mtu: usize,
) -> Result<SentFrame, RtcError> {
    // Packets exceed the target MTU by their header, so don't warn about them.
    let config = Rtc::builder().set_mtu(mtu..=usize::MAX);
    let (mut l, mut r, mid) = sdp_pair(supports_dd, config)?;
    let pt = l
        .codec_config()
        .find(|params| params.spec().codec == codec)
        .expect("test codec is configured")
        .pt();
    let last = l.last;
    let mut writer = l
        .writer(mid)
        .unwrap()
        .video_orientation(VideoOrientation::Deg90)
        .abs_capture_time(AbsCaptureTime {
            capture_time: SystemTime::UNIX_EPOCH,
            clock_offset: Some(1),
        });
    if let Some(descriptor) = descriptor {
        writer = writer.user_extension_value(descriptor);
    }
    writer.write(pt, last, MediaTime::ZERO, video_frame(codec, size))?;
    progress_until(&mut l, &mut r, |_, r| media_data_count(r) > 0)?;
    let frames = r
        .events
        .drain(..)
        .filter_map(|(_, event)| match event {
            Event::MediaData(data) => Some(data),
            _ => None,
        })
        .collect();
    let packets = l
        .events
        .iter()
        .filter_map(|(_, event)| match event.as_raw_packet() {
            Some(RawPacket::RtpTx(header, buf)) if header.payload_type == pt => {
                Some((header.clone(), buf.clone()))
            }
            _ => None,
        })
        .collect();
    Ok(SentFrame { frames, packets })
}

fn assert_frame_descriptors(sent: &SentFrame, raw: &DependencyDescriptor) {
    assert_eq!(sent.frames.len(), 1);
    assert!(!sent.packets.is_empty());
    let expected = raw.parse(None).unwrap();
    let structure = expected.attached_structure.clone();
    let mut receiver = DependencyDescriptorReceiver::default();
    for (index, (header, _)) in sent.packets.iter().enumerate() {
        let descriptor = header
            .ext_vals
            .user_values
            .get::<DependencyDescriptor>()
            .expect("DD on every packet");
        let parsed = descriptor.parse(structure.as_ref()).unwrap();
        let mut packet_expected = expected.clone();
        packet_expected.is_first_packet = index == 0;
        packet_expected.is_last_packet = index + 1 == sent.packets.len();
        if index != 0 {
            packet_expected.attached_structure = None;
        }
        assert_eq!(header.marker, packet_expected.is_last_packet);
        assert_eq!(parsed, packet_expected);
        assert_eq!(
            receiver.receive(descriptor),
            ReceivedDependencyDescriptor::Parsed {
                frame_number: i64::from(expected.truncated_frame_number),
                descriptor: packet_expected,
            }
        );
    }
    let mut first_descriptor = raw.clone();
    first_descriptor.set_packet_flags(true, sent.packets.len() == 1);
    assert_eq!(
        sent.frames[0]
            .ext_vals
            .user_values
            .get::<DependencyDescriptor>(),
        Some(&first_descriptor),
        "frame metadata must retain the first packet's structure and custom fields",
    );
}

#[test]
fn dependency_descriptor_sdp_and_frame_mode() -> Result<(), RtcError> {
    for (size, padded_size) in [(10, 0), (5000, 0), (5000, 255)] {
        let mut expected = descriptor().parse(None).unwrap();
        expected.frame_diffs = vec![17, 4096];
        expected.decode_target_indications = vec![DecodeTargetIndication::Required];
        let mut bytes = expected.serialize(None).unwrap().as_bytes().to_vec();
        if padded_size > 0 {
            bytes.resize(padded_size, 0);
        }
        let raw = DependencyDescriptor::from_bytes(bytes).unwrap();
        let payload = vec![0xaa; size];

        let sent = send_frame_to(true, Some(raw.clone()), size)?;
        assert_frame_descriptors(&sent, &raw);
        assert_eq!(&sent.frames[0].data[..], payload.as_slice());
        if size == 10 {
            assert_eq!(sent.packets.len(), 1);
        } else {
            assert!(sent.packets.len() > 1);
        }
    }
    Ok(())
}

#[test]
fn dependency_descriptor_does_not_mix_header_forms_without_negotiation() -> Result<(), RtcError> {
    let (mut l, mut r, mid) = sdp_pair(true, Rtc::builder())?;
    let pt = l.params_vp8().pt();
    let now = l.last;
    let mut bytes = descriptor().as_bytes().to_vec();
    bytes.resize(17, 0);
    let descriptors = [
        Some(DependencyDescriptor::from_bytes(bytes).unwrap()),
        Some(DependencyDescriptor::from_bytes([0xc0, 0, 43]).unwrap()),
        None,
    ];
    let frame_count = descriptors.len();
    for (index, descriptor) in descriptors.into_iter().enumerate() {
        let mut writer = l.writer(mid).unwrap();
        if let Some(descriptor) = descriptor {
            writer = writer.user_extension_value(descriptor);
        }
        writer.write(
            pt,
            now,
            MediaTime::new(3000 * index as u64, Frequency::NINETY_KHZ),
            vec![0xaa; 5000],
        )?;
    }
    progress_until(&mut l, &mut r, |_, r| media_data_count(r) == frame_count)?;
    let (profiles, sizes): (Vec<_>, Vec<_>) = l
        .events
        .iter()
        .filter_map(|(_, event)| match event.as_raw_packet() {
            Some(RawPacket::RtpTx(header, bytes)) if header.payload_type == pt => {
                let offset = 12 + 4 * header.csrc_count;
                let profile = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                let size = header
                    .ext_vals
                    .user_values
                    .get::<DependencyDescriptor>()
                    .map(|descriptor| descriptor.as_bytes().len());
                Some((profile, size))
            }
            _ => None,
        })
        .unzip();
    assert!(profiles.len() > frame_count, "frames must fragment");
    assert!(sizes.contains(&Some(17)));
    assert!(sizes.contains(&Some(3)));
    assert!(sizes.contains(&None));
    assert!(
        profiles.iter().all(|profile| *profile == 0x1000),
        "DD must use two-byte headers even without a descriptor: {profiles:x?}"
    );
    Ok(())
}

#[test]
fn dependency_descriptor_bytes_come_out_of_the_payload() -> Result<(), RtcError> {
    let padded = |mut bytes: Vec<u8>, size| {
        bytes.resize(size, 0);
        DependencyDescriptor::from_bytes(bytes).unwrap()
    };
    let descriptors = [
        padded(vec![0xc0, 0, 42], 3),
        padded(descriptor().as_bytes().to_vec(), 16),
        padded(descriptor().as_bytes().to_vec(), 17),
        padded(descriptor().as_bytes().to_vec(), 255),
        // Without a structure, every packet carries all of the bytes.
        padded(vec![0xc0, 0, 42, 0], 255),
    ];
    let largest_packet = |sent: &SentFrame, codec| {
        assert_eq!(sent.frames.len(), 1);
        assert_eq!(sent.frames[0].data.as_ref(), video_frame(codec, 5000));
        assert!(sent.packets.len() > 1, "{codec:?} must fragment");
        sent.packets
            .iter()
            .map(|(_, bytes)| bytes.len())
            .max()
            .unwrap()
    };
    for mtu in [
        DATAGRAM_MTU_TARGET_MIN,
        DATAGRAM_MTU_TARGET,
        DATAGRAM_MTU_TARGET_MAX,
    ] {
        // VP8 fills its packets, so without a descriptor it reaches the most the MTU allows.
        let limit = largest_packet(
            &send_video_frame(true, Codec::Vp8, None, 5000, mtu)?,
            Codec::Vp8,
        );
        for codec in [Codec::Vp8, Codec::Av1, Codec::Vp9, Codec::H264, Codec::H265] {
            for raw in &descriptors {
                let sent = send_video_frame(true, codec, Some(raw.clone()), 5000, mtu)?;
                let largest = largest_packet(&sent, codec);
                let len = raw.as_bytes().len();
                assert!(
                    largest <= limit,
                    "{largest} > {limit} with a {len}-byte DD, {codec:?} at MTU {mtu}"
                );
                if raw.parse(None).is_ok() {
                    assert_frame_descriptors(&sent, raw);
                    continue;
                }
                // A descriptor without a structure is sent as given.
                for (index, (header, _)) in sent.packets.iter().enumerate() {
                    let mut expected = raw.clone();
                    expected.set_packet_flags(index == 0, index + 1 == sent.packets.len());
                    assert_eq!(
                        header.ext_vals.user_values.get::<DependencyDescriptor>(),
                        Some(&expected)
                    );
                }
            }
        }
    }
    Ok(())
}

/// The descriptor in the bytes of a sent RTP packet, at the ID the left side of an SDP pair
/// offers.
fn on_wire_descriptor(bytes: &[u8]) -> Option<DependencyDescriptor> {
    let mut exts = ExtensionMap::empty();
    exts.set(14, Extension::with_serializer(URI, Serializer));
    let header = RtpHeader::_parse(bytes, &exts).expect("RTP header");
    header
        .ext_vals
        .user_values
        .get::<DependencyDescriptor>()
        .cloned()
}

#[test]
fn dependency_descriptor_is_only_sent_when_negotiated() -> Result<(), RtcError> {
    // A peer that doesn't support DD doesn't negotiate it. A descriptor set anyway, as by an SFU
    // forwarding a publisher's descriptors, is not sent, takes no room, and is not checked.
    let packet_sizes = |packets: &[(RtpHeader, Vec<u8>)]| {
        packets
            .iter()
            .map(|(_, bytes)| bytes.len())
            .collect::<Vec<_>>()
    };
    let without_dd = send_frame_to(false, None, 5000)?;
    let malformed = DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80]).unwrap();
    for descriptor in [descriptor(), malformed] {
        let SentFrame { frames, packets } = send_frame_to(false, Some(descriptor), 5000)?;
        assert_eq!(frames.len(), 1);
        assert!(
            frames[0]
                .ext_vals
                .user_values
                .get::<DependencyDescriptor>()
                .is_none()
        );
        assert_eq!(packet_sizes(&packets), packet_sizes(&without_dd.packets));
        assert!(
            packets
                .iter()
                .all(|(_, bytes)| on_wire_descriptor(bytes).is_none())
        );
    }

    // Negotiated, every packet carries it.
    let SentFrame { packets, .. } = send_frame_to(true, Some(descriptor()), 5000)?;
    assert!(packets.len() > 1);
    assert!(
        packets
            .iter()
            .all(|(_, bytes)| on_wire_descriptor(bytes).is_some())
    );
    Ok(())
}

#[test]
fn dependency_descriptor_malformed_structure_is_rejected_by_write() -> Result<(), RtcError> {
    let (mut l, mut r, mid) = sdp_pair(true, Rtc::builder())?;
    let pt = l.params_vp8().pt();
    let last = l.last;
    // The structure flag is set, but the structure is truncated.
    let malformed = DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80]).unwrap();
    let error = l
        .writer(mid)
        .unwrap()
        .user_extension_value(malformed)
        .write(pt, last, MediaTime::ZERO, vec![0xaa; 5000])
        .expect_err("a malformed structure must be rejected");
    assert!(matches!(
        error,
        RtcError::Packet(
            error_mid,
            error_pt,
            PacketError::InvalidDependencyDescriptor(DependencyDescriptorError::NotEnoughBits)
        ) if error_mid == mid && error_pt == pt
    ));

    // Nothing was queued, and the session keeps sending. Without a structure, the descriptor
    // cannot be checked, so it is sent as given.
    let unchecked = DependencyDescriptor::from_bytes([0xc0, 0, 43, 0x14]).unwrap();
    l.writer(mid)
        .unwrap()
        .user_extension_value(unchecked.clone())
        .write(pt, last, MediaTime::ZERO, vec![0xaa; 10])?;
    progress_until(&mut l, &mut r, |_, r| media_data_count(r) > 0)?;
    let sent = l
        .events
        .iter()
        .filter(|(_, event)| {
            matches!(event.as_raw_packet(), Some(RawPacket::RtpTx(header, _)) if header.payload_type == pt)
        })
        .count();
    assert_eq!(sent, 1);
    let data = r
        .events
        .iter()
        .find_map(|(_, event)| match event {
            Event::MediaData(data) => Some(data),
            _ => None,
        })
        .expect("frame after the rejected write");
    assert_eq!(
        data.ext_vals.user_values.get::<DependencyDescriptor>(),
        Some(&unchecked)
    );
    Ok(())
}
