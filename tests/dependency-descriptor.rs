use std::net::Ipv4Addr;
use std::time::Instant;

use str0m::change::{SdpAnswer, SdpOffer};
use str0m::error::PacketError;
use str0m::media::{Direction, Frequency, MediaData, MediaKind, MediaTime, Mid};
use str0m::rtp::dependency_descriptor::{
    DecodeTargetIndication, DependencyDescriptor, DependencyDescriptorError,
    DependencyDescriptorReceiver, ParsedDependencyDescriptor, ReceivedDependencyDescriptor,
    Serializer, SharedStructure, SharedStructureTemplate, URI,
};
use str0m::rtp::{Extension, ExtensionValues, RawPacket, RtpHeader, RtpWrite, Ssrc};
use str0m::{Event, Rtc, RtcError};
use tracing::info_span;

mod common;
use common::{TestRtc, connect_l_r_with_rtc, init_crypto_default, init_log, progress};

/// One decode target, one switch template, no chains, with the structure attached.
fn descriptor() -> DependencyDescriptor {
    DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80, 0, 0xe0]).unwrap()
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
        let mut extensions = ExtensionValues {
            mid: Some(mid),
            ..Default::default()
        };
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

#[test]
fn dependency_descriptor_of_frames_per_spatial_layer_is_not_merged() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let config = || Rtc::builder().set_extension(14, Extension::with_serializer(URI, Serializer));
    let (mut l, mut r) =
        connect_l_r_with_rtc(config().set_rtp_mode(true).build(now), config().build(now));
    let mid = "vid".into();
    let ssrc: Ssrc = 1000.into();
    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api().declare_stream_tx(ssrc, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api().expect_stream_rx(ssrc, None, mid, None);
    let pt = l.params_vp8().pt();
    let last = l.last;
    // Two temporal units of two packets: one frame, as with a single spatial layer, and then one
    // frame per spatial layer, each with its own frame number.
    let units = [[[0x80, 0, 1], [0x40, 0, 1]], [[0xc0, 0, 2], [0xc0, 0, 3]]];
    for (unit, descriptors) in units.into_iter().enumerate() {
        for (index, descriptor) in descriptors.into_iter().enumerate() {
            let mut extensions = ExtensionValues {
                mid: Some(mid),
                ..Default::default()
            };
            extensions
                .user_values
                .set(DependencyDescriptor::from_bytes(descriptor).unwrap());
            // The VP8 payload descriptor starts partition 0 in the first packet only.
            let mut payload = vec![0xaa; 11];
            payload[0] = if index == 0 { 0x10 } else { 0 };
            l.direct_api().stream_tx(&ssrc).unwrap().write_rtp(
                RtpWrite::new(
                    pt,
                    (1000 + 2 * unit as u64 + index as u64).into(),
                    unit as u32 * 3000,
                    last,
                    payload,
                )
                .marker(index == 1)
                .ext_vals(extensions),
            );
        }
    }
    let mut frames = Vec::new();
    for _ in 0..100 {
        progress(&mut l, &mut r)?;
        frames.extend(r.events.drain(..).filter_map(|(_, event)| match event {
            Event::MediaData(data) => Some(data),
            _ => None,
        }));
        if frames.len() == 2 {
            break;
        }
    }
    assert_eq!(frames.len(), 2);
    assert_eq!(
        frames[0].ext_vals.user_values.get::<DependencyDescriptor>(),
        Some(&DependencyDescriptor::from_bytes([0x80, 0, 1]).unwrap())
    );
    // The second temporal unit is one sample spanning both frames, so no descriptor fits it.
    assert_eq!(frames[1].data.len(), 20);
    assert!(
        frames[1]
            .ext_vals
            .user_values
            .get::<DependencyDescriptor>()
            .is_none()
    );
    Ok(())
}

fn sdp_pair() -> Result<(TestRtc, TestRtc, Mid), RtcError> {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let rtc_l = Rtc::builder()
        .enable_raw_packets(true)
        .set_extension(14, Extension::with_serializer(URI, Serializer))
        .build(now);
    let rtc_r = Rtc::builder()
        .enable_raw_packets(true)
        .set_extension(16, Extension::with_serializer(URI, Serializer))
        .build(now);
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
    let answer_sdp = answer.to_sdp_string();
    assert_eq!(answer_sdp.matches(URI).count(), 1);
    let answer = SdpAnswer::from_sdp_string(&answer_sdp).unwrap();
    l.sdp_api().accept_answer(pending, answer)?;
    for rtc in [&l, &r] {
        assert_eq!(
            rtc.media(video)
                .unwrap()
                .remote_extmap()
                .lookup(14)
                .map(Extension::as_uri),
            Some(URI)
        );
        assert!(
            !rtc.media(audio)
                .unwrap()
                .remote_extmap()
                .iter()
                .any(|(_, ext)| ext.as_uri() == URI)
        );
    }
    for _ in 0..100 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }
    assert!(l.is_connected() && r.is_connected());
    l.events.clear();
    r.events.clear();
    Ok((l, r, video))
}

/// The outcome of writing one frame.
struct SentFrame {
    /// Frames received by the other side.
    frames: Vec<MediaData>,
    /// Headers and sizes of the RTP packets sent for the frame.
    packets: Vec<(RtpHeader, usize)>,
}

fn send_frame(
    descriptor: Option<DependencyDescriptor>,
    size: usize,
) -> Result<SentFrame, RtcError> {
    let (mut l, mut r, mid) = sdp_pair()?;
    let pt = l.params_vp8().pt();
    let last = l.last;
    let mut writer = l.writer(mid).unwrap();
    if let Some(descriptor) = descriptor {
        writer = writer.user_extension_value(descriptor);
    }
    writer.write(pt, last, MediaTime::ZERO, vec![0xaa; size])?;
    for _ in 0..100 {
        progress(&mut l, &mut r)?;
        if r.events
            .iter()
            .any(|(_, event)| matches!(event, Event::MediaData(_)))
        {
            break;
        }
    }
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
                Some((header.clone(), buf.len()))
            }
            _ => None,
        })
        .collect();
    Ok(SentFrame { frames, packets })
}

#[test]
fn dependency_descriptor_sdp_and_frame_mode() -> Result<(), RtcError> {
    for (size, padded_size) in [(10, 0), (5000, 0), (5000, 255)] {
        let mut expected = descriptor().parse(None).unwrap();
        expected.referred_relative_frame_numbers = vec![17, 4096];
        expected.decode_target_indication_by_decode_target_index =
            vec![DecodeTargetIndication::Required];
        let mut bytes = expected.serialize(None).unwrap().as_bytes().to_vec();
        if padded_size > 0 {
            bytes.resize(padded_size, 0);
        }
        let raw = DependencyDescriptor::from_bytes(bytes).unwrap();
        let payload = vec![0xaa; size];

        let SentFrame { frames, packets } = send_frame(Some(raw.clone()), size)?;
        assert_eq!(frames.len(), 1);
        assert_eq!(&frames[0].data[..], payload.as_slice());
        if size == 10 {
            assert_eq!(packets.len(), 1);
        } else {
            assert!(packets.len() > 1);
        }
        let structure = expected.attached_structure.clone();
        // Each packet also passes libwebrtc's receive checks.
        let mut receiver = DependencyDescriptorReceiver::default();
        for (index, (header, _)) in packets.iter().enumerate() {
            let descriptor = header
                .ext_vals
                .user_values
                .get::<DependencyDescriptor>()
                .expect("DD on every packet");
            let parsed = descriptor.parse(structure.as_ref()).unwrap();
            let mut packet_expected = expected.clone();
            packet_expected.is_first_packet = index == 0;
            packet_expected.is_last_packet = index + 1 == packets.len();
            if index != 0 {
                packet_expected.attached_structure = None;
            }
            assert_eq!(parsed, packet_expected);
            assert_eq!(
                receiver.receive(descriptor),
                ReceivedDependencyDescriptor::Parsed {
                    frame_number: 42,
                    descriptor: packet_expected,
                }
            );
        }
        let mut first_descriptor = raw;
        first_descriptor.set_packet_flags(true, packets.len() == 1);
        assert_eq!(
            frames[0].ext_vals.user_values.get::<DependencyDescriptor>(),
            Some(&first_descriptor),
            "frame metadata must retain the first packet's structure and custom fields",
        );
    }
    Ok(())
}

#[test]
fn dependency_descriptor_frames_pass_libwebrtc_receive_checks() -> Result<(), RtcError> {
    // As libwebrtc sends: a key frame attaches the structure, and each frame uses the template
    // with its layers that needs the fewest custom fields. Frame numbers wrap.
    let (mut l, mut r, mid) = sdp_pair()?;
    let pt = l.params_vp8().pt();
    let last = l.last;
    let template = |diffs: Vec<u16>| SharedStructureTemplate {
        spatial_layer_id: 0,
        temporal_layer_id: 0,
        decode_target_indication_by_decode_target_index: vec![DecodeTargetIndication::Switch],
        referred_relative_frame_numbers: diffs,
        previous_relative_frame_number_by_chain_index: vec![],
    };
    let structure =
        SharedStructure::new(13, vec![template(vec![]), template(vec![1])], &[], None).unwrap();
    let frame_numbers = [0xffff_u16, 0, 1];
    for (index, frame_number) in frame_numbers.into_iter().enumerate() {
        let key = index == 0;
        let frame = &structure.template_by_id_minus_offset()[usize::from(!key)];
        let mut descriptor =
            ParsedDependencyDescriptor::for_frame(&structure, frame, frame_number, u32::MAX)
                .unwrap();
        if key {
            descriptor.attached_structure = Some(structure.clone());
        }
        let descriptor = descriptor.serialize(Some(&structure)).unwrap();
        let rtp_time = MediaTime::new(3000 * index as u64, Frequency::NINETY_KHZ);
        l.writer(mid)
            .unwrap()
            .user_extension_value(descriptor)
            .write(pt, last, rtp_time, vec![0xaa; 3000])?;
    }
    let media_data_count = |r: &TestRtc| {
        r.events
            .iter()
            .filter(|(_, event)| matches!(event, Event::MediaData(_)))
            .count()
    };
    for _ in 0..100 {
        progress(&mut l, &mut r)?;
        if media_data_count(&r) == frame_numbers.len() {
            break;
        }
    }
    assert_eq!(media_data_count(&r), frame_numbers.len());

    let mut receiver = DependencyDescriptorReceiver::default();
    let mut received = Vec::new();
    for (_, event) in &r.events {
        let header = match event.as_raw_packet() {
            Some(RawPacket::RtpRx(header, _)) if header.payload_type == pt => header,
            _ => continue,
        };
        let descriptor = header
            .ext_vals
            .user_values
            .get::<DependencyDescriptor>()
            .expect("DD on every packet");
        match receiver.receive(descriptor) {
            ReceivedDependencyDescriptor::Parsed {
                frame_number,
                descriptor,
            } => {
                // Only the first packet of the key frame attaches the structure.
                assert_eq!(descriptor.attached_structure.is_some(), received.is_empty());
                received.push(frame_number);
            }
            other => panic!("packet failed libwebrtc's receive checks: {other:?}"),
        }
    }
    assert!(received.len() > frame_numbers.len());
    received.dedup();
    assert_eq!(received, [0xffff, 0x1_0000, 0x1_0001]);
    assert_eq!(receiver.latest_shared_structure(), Some(&structure));
    Ok(())
}

#[test]
fn dependency_descriptor_bytes_come_out_of_the_payload() -> Result<(), RtcError> {
    let largest_packet = |descriptor| -> Result<usize, RtcError> {
        let SentFrame { frames, packets } = send_frame(descriptor, 5000)?;
        assert_eq!(frames.len(), 1);
        Ok(packets.iter().map(|(_, size)| *size).max().unwrap())
    };
    let baseline = largest_packet(None)?;
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
    for descriptor in descriptors {
        let len = descriptor.as_bytes().len();
        let largest = largest_packet(Some(descriptor))?;
        assert!(
            largest <= baseline,
            "{largest} > {baseline} with a {len}-byte DD"
        );
    }
    Ok(())
}

#[test]
fn dependency_descriptor_not_set_is_absent() -> Result<(), RtcError> {
    let SentFrame { frames, packets } = send_frame(None, 5000)?;
    assert_eq!(frames.len(), 1);
    assert_eq!(&frames[0].data[..], [0xaa; 5000].as_slice());
    assert!(
        frames[0]
            .ext_vals
            .user_values
            .get::<DependencyDescriptor>()
            .is_none()
    );
    assert!(packets.iter().all(|(header, _)| {
        header
            .ext_vals
            .user_values
            .get::<DependencyDescriptor>()
            .is_none()
    }));
    Ok(())
}

#[test]
fn dependency_descriptor_malformed_structure_is_rejected_by_write() -> Result<(), RtcError> {
    let (mut l, mut r, mid) = sdp_pair()?;
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
    for _ in 0..100 {
        progress(&mut l, &mut r)?;
        if r.events
            .iter()
            .any(|(_, event)| matches!(event, Event::MediaData(_)))
        {
            break;
        }
    }
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
