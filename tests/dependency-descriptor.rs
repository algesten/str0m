use std::net::Ipv4Addr;
use std::time::Instant;

use netem::{NetemConfig, Probability, RandomLoss};
use str0m::change::{SdpAnswer, SdpOffer};
use str0m::error::PacketError;
use str0m::media::{Direction, Frequency, MediaData, MediaKind, MediaTime, Mid};
use str0m::rtp::dependency_descriptor::{DecodeTargetIndication, DependencyDescriptor, URI};
use str0m::rtp::dependency_descriptor::{DependencyDescriptorError, DependencyDescriptorReceiver};
use str0m::rtp::dependency_descriptor::{ParsedDependencyDescriptor, ReceivedDependencyDescriptor};
use str0m::rtp::dependency_descriptor::{Serializer, SharedStructure, SharedStructureTemplate};
use str0m::rtp::{Extension, ExtensionMap, ExtensionValues, RawPacket, RtpHeader, RtpWrite, Ssrc};
use str0m::{Event, Rtc, RtcError};
use tracing::info_span;

mod common;
use common::{TestRtc, connect_l_r_with_rtc, init_crypto_default, init_log, progress};

/// One decode target, one switch template, no chains, with the structure attached.
fn descriptor() -> DependencyDescriptor {
    DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80, 0, 0xe0]).unwrap()
}

/// A pair in RTP mode, with one video stream from the left to the right, optionally with RTX.
fn rtp_mode_pair(ssrc: Ssrc, rtx: Option<Ssrc>) -> (TestRtc, TestRtc) {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let config = || {
        Rtc::builder()
            .set_rtp_mode(true)
            .enable_raw_packets(true)
            .set_extension(14, Extension::with_serializer(URI, Serializer))
    };
    let (mut l, mut r) = connect_l_r_with_rtc(config().build(now), config().build(now));
    let mid = "vid".into();
    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api().declare_stream_tx(ssrc, rtx, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api().expect_stream_rx(ssrc, rtx, mid, None);
    (l, r)
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

#[test]
fn dependency_descriptor_rtp_mode_preserves_wire_bytes() -> Result<(), RtcError> {
    let ssrc: Ssrc = 1000.into();
    let (mut l, mut r) = rtp_mode_pair(ssrc, None);
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

#[test]
fn dependency_descriptor_sfu_forwards_one_spatial_layer_in_rtp_mode() -> Result<(), RtcError> {
    use DecodeTargetIndication::{NotPresent, Required, Switch};

    // A publisher sends two spatial layers to an SFU, which forwards only spatial layer 0 to a
    // subscriber. Each hop is its own peer connection in RTP mode.
    let (in_ssrc, out_ssrc): (Ssrc, Ssrc) = (1000.into(), 2000.into());
    let (mut publisher, mut sfu_in) = rtp_mode_pair(in_ssrc, None);
    let (mut sfu_out, mut subscriber) = rtp_mode_pair(out_ssrc, None);

    // L2T1, as libwebrtc structures it. Decode target 0 is spatial layer 0, and decode target 1
    // adds spatial layer 1. Each decode target has its own chain.
    let template = |spatial_layer_id, dtis: [DecodeTargetIndication; 2], fdiffs: &[u16], chains| {
        SharedStructureTemplate {
            spatial_layer_id,
            temporal_layer_id: 0,
            decode_target_indication_by_decode_target_index: dtis.to_vec(),
            referred_relative_frame_numbers: fdiffs.to_vec(),
            previous_relative_frame_number_by_chain_index: Vec::from(chains),
        }
    };
    let structure = SharedStructure::new(
        0,
        vec![
            template(0, [Switch, Switch], &[], [0, 0]),
            template(0, [Switch, Required], &[2], [2, 1]),
            template(1, [NotPresent, Switch], &[1], [1, 1]),
            template(1, [NotPresent, Required], &[1, 2], [1, 1]),
        ],
        &[0, 1],
        None,
    )
    .unwrap();

    // Two temporal units, each with a one-packet frame per spatial layer: (template ID, frame
    // number, RTP time). Frame numbers wrap.
    let frames: [(u8, u16, u32); 4] = [
        (0, 0xfffe, 0),
        (2, 0xffff, 0),
        (1, 0x0000, 3000),
        (3, 0x0001, 3000),
    ];
    let pt = publisher.params_vp8().pt();
    let wallclock = publisher.last;
    for (index, (template_id, frame_number, rtp_time)) in frames.into_iter().enumerate() {
        let mut descriptor =
            ParsedDependencyDescriptor::from_template(&structure, template_id, frame_number)
                .unwrap();
        // The key frame attaches the structure.
        if index == 0 {
            descriptor.attached_structure = Some(structure.clone());
        }
        let mut ext_vals = ExtensionValues::default();
        ext_vals
            .user_values
            .set(descriptor.serialize(Some(&structure)).unwrap());
        publisher
            .direct_api()
            .stream_tx(&in_ssrc)
            .unwrap()
            .write_rtp(
                RtpWrite::new(
                    pt,
                    (100 + index as u64).into(),
                    rtp_time,
                    wallclock,
                    vec![index as u8; 20],
                )
                // Spatial layer 1 ends each temporal unit.
                .marker(index % 2 == 1)
                .ext_vals(ext_vals),
            );
    }

    // The SFU keeps frame numbers, which dependencies refer to, and signals the forwarded decode
    // targets in the active decode targets bitmask. It rewrites RTP sequence numbers instead, so
    // the subscriber sees no gaps where spatial layer 1 was dropped.
    let forwarded_targets = structure
        .decode_targets()
        .iter()
        .enumerate()
        .filter(|(_, decode_target)| decode_target.spatial_layer_id == 0)
        .fold(0, |bitmask, (index, _)| bitmask | (1 << index));
    let mut incoming = DependencyDescriptorReceiver::default();
    let out_pt = sfu_out.params_vp8().pt();
    let mut out_seq_no = 500_u64;
    let mut received_by_sfu = 0;
    for _ in 0..100 {
        progress(&mut publisher, &mut sfu_in)?;
        for (_, event) in sfu_in.events.drain(..) {
            let Event::RtpPacket(packet) = event else {
                continue;
            };
            received_by_sfu += 1;
            let descriptor = packet
                .header
                .ext_vals
                .user_values
                .get::<DependencyDescriptor>()
                .expect("DD on every packet");
            let ReceivedDependencyDescriptor::Parsed {
                descriptor: mut parsed,
                ..
            } = incoming.receive(descriptor)
            else {
                panic!("published DD failed the receive checks");
            };
            let latest_structure = incoming.latest_shared_structure().expect("key frame first");
            let template = latest_structure.template(parsed.template_id).unwrap();
            if template.spatial_layer_id > 0 {
                continue;
            }
            parsed.active_decode_targets_bitmask = Some(forwarded_targets);
            let mut ext_vals = ExtensionValues::default();
            ext_vals
                .user_values
                .set(parsed.serialize(Some(latest_structure)).unwrap());
            let wallclock = sfu_out.last;
            sfu_out
                .direct_api()
                .stream_tx(&out_ssrc)
                .unwrap()
                .write_rtp(
                    RtpWrite::new(
                        out_pt,
                        out_seq_no.into(),
                        packet.header.timestamp,
                        wallclock,
                        packet.payload.clone(),
                    )
                    // Spatial layer 0 now ends each temporal unit.
                    .marker(parsed.is_last_packet)
                    .ext_vals(ext_vals),
                );
            out_seq_no += 1;
        }
        if received_by_sfu == frames.len() {
            break;
        }
    }
    assert_eq!(received_by_sfu, frames.len());

    let mut outgoing = DependencyDescriptorReceiver::default();
    let mut received = Vec::new();
    for _ in 0..100 {
        progress(&mut sfu_out, &mut subscriber)?;
        for (_, event) in subscriber.events.drain(..) {
            let Event::RtpPacket(packet) = event else {
                continue;
            };
            let descriptor = packet
                .header
                .ext_vals
                .user_values
                .get::<DependencyDescriptor>()
                .expect("DD on every forwarded packet");
            match outgoing.receive(descriptor) {
                ReceivedDependencyDescriptor::Parsed {
                    frame_number,
                    descriptor,
                } => received.push((packet, frame_number, descriptor)),
                other => panic!("forwarded DD failed the receive checks: {other:?}"),
            }
        }
        if received.len() == 2 {
            break;
        }
    }
    // Only spatial layer 0 arrives, with its original frame numbers across the wrap.
    let frame_numbers: Vec<_> = received.iter().map(|(_, number, _)| *number).collect();
    assert_eq!(frame_numbers, [0xfffe, 0x1_0000]);
    for (index, (packet, frame_number, descriptor)) in received.iter().enumerate() {
        assert_eq!(*packet.seq_no, 500 + index as u64);
        assert!(packet.header.marker);
        assert_eq!(packet.payload.as_ref(), &[2 * index as u8; 20]);
        assert_eq!(descriptor.attached_structure.is_some(), index == 0);
        assert_eq!(
            descriptor.updated_active_decode_targets_bitmask(),
            Some(forwarded_targets)
        );
        // Every frame that a forwarded frame depends on was forwarded too.
        for fdiff in &descriptor.referred_relative_frame_numbers {
            assert!(frame_numbers.contains(&(frame_number - i64::from(*fdiff))));
        }
    }
    assert_eq!(outgoing.latest_shared_structure(), Some(&structure));
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
    sdp_pair_with(true)
}

/// A pair negotiated with SDP, where the left offers DD on video, and the right supports it if
/// `right_supports_dd`.
fn sdp_pair_with(right_supports_dd: bool) -> Result<(TestRtc, TestRtc, Mid), RtcError> {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let rtc_l = Rtc::builder()
        .enable_raw_packets(true)
        .set_extension(14, Extension::with_serializer(URI, Serializer))
        .build(now);
    let mut builder_r = Rtc::builder().enable_raw_packets(true);
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
    let answer_sdp = answer.to_sdp_string();
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

fn send_frame(
    descriptor: Option<DependencyDescriptor>,
    size: usize,
) -> Result<SentFrame, RtcError> {
    send_frame_to(true, descriptor, size)
}

/// Write a frame to a peer that supports DD if `supports_dd`.
fn send_frame_to(
    supports_dd: bool,
    descriptor: Option<DependencyDescriptor>,
    size: usize,
) -> Result<SentFrame, RtcError> {
    let (mut l, mut r, mid) = sdp_pair_with(supports_dd)?;
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
                Some((header.clone(), buf.clone()))
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
        Ok(packets.iter().map(|(_, bytes)| bytes.len()).max().unwrap())
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

/// The SDP without DD on the m-line of `mid`, as from a remote that doesn't negotiate it there.
fn without_dd_on_m_line(sdp: &str, mid: Mid) -> String {
    let mid_line = format!("a=mid:{mid}");
    // The session description, and then one section per m-line.
    let mut sections: Vec<Vec<&str>> = vec![vec![]];
    for line in sdp.split("\r\n") {
        if line.starts_with("m=") {
            sections.push(vec![]);
        }
        sections.last_mut().unwrap().push(line);
    }
    sections
        .iter()
        .flat_map(|lines| {
            let drop_dd = lines.contains(&mid_line.as_str());
            lines
                .iter()
                .filter(move |line| !(drop_dd && line.contains(URI)))
        })
        .copied()
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Whether each RTP packet that `rtc` sent on the m-line of `mid` carried DD on the wire.
fn sent_dd(rtc: &mut TestRtc, mid: Mid) -> Vec<bool> {
    let ssrc = rtc.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    rtc.events
        .iter()
        .filter_map(|(_, event)| match event.as_raw_packet() {
            Some(RawPacket::RtpTx(header, bytes)) if header.ssrc == ssrc => {
                Some(on_wire_descriptor(bytes).is_some())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn dependency_descriptor_is_negotiated_per_m_line() -> Result<(), RtcError> {
    // A remote can negotiate DD on some m-lines only, as a browser does for a transceiver that
    // disables it with setHeaderExtensionsToNegotiate(). The offer only has DD on the first of
    // two video m-lines, so each side sends DD there only. The left side writes frames, and the
    // right side writes RTP packets.
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let builder = || {
        Rtc::builder()
            .enable_raw_packets(true)
            .set_extension(14, Extension::with_serializer(URI, Serializer))
    };
    let mut l = TestRtc::new_with_rtc(info_span!("L"), builder().build(now));
    let mut r = TestRtc::new_with_rtc(info_span!("R"), builder().set_rtp_mode(true).build(now));
    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());
    let mut change = l.sdp_api();
    let with_dd = change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let without_dd = change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    assert_eq!(offer.to_sdp_string().matches(URI).count(), 2);
    let offer_sdp = without_dd_on_m_line(&offer.to_sdp_string(), without_dd);
    assert_eq!(offer_sdp.matches(URI).count(), 1);
    let offer = SdpOffer::from_sdp_string(&offer_sdp).unwrap();
    let answer_sdp = r.sdp_api().accept_offer(offer)?.to_sdp_string();
    // The answer only has DD where the offer has it.
    assert_eq!(answer_sdp.matches(URI).count(), 1);
    let answer = SdpAnswer::from_sdp_string(&answer_sdp).unwrap();
    l.sdp_api().accept_answer(pending, answer)?;
    for rtc in [&l, &r] {
        assert_eq!(dd_id(rtc, with_dd), Some(14));
        assert_eq!(dd_id(rtc, without_dd), None);
    }
    finish_connecting(&mut l, &mut r)?;

    // Each side sets a descriptor on both m-lines.
    let (l_pt, r_pt) = (l.params_vp8().pt(), r.params_vp8().pt());
    for mid in [with_dd, without_dd] {
        let last = l.last;
        l.writer(mid)
            .unwrap()
            .user_extension_value(descriptor())
            .write(l_pt, last, MediaTime::ZERO, vec![0xaa; 10])?;
        let mut ext_vals = ExtensionValues::default();
        ext_vals.user_values.set(descriptor());
        // A whole VP8 frame: the payload descriptor starts partition 0.
        let mut payload = vec![0xaa; 11];
        payload[0] = 0x10;
        let last = r.last;
        let mut direct = r.direct_api();
        direct.stream_tx_by_mid(mid, None).unwrap().write_rtp(
            RtpWrite::new(r_pt, 1.into(), 0, last, payload)
                .marker(true)
                .ext_vals(ext_vals),
        );
    }
    let l_ssrcs = [with_dd, without_dd].map(|mid| {
        let mut direct = l.direct_api();
        direct.stream_tx_by_mid(mid, None).unwrap().ssrc()
    });
    let count = |rtc: &TestRtc, is_media: fn(&Event) -> bool| {
        rtc.events
            .iter()
            .filter(|(_, event)| is_media(event))
            .count()
    };
    progress_until(&mut l, &mut r, |l, r| {
        count(l, |event| matches!(event, Event::MediaData(_))) == 2
            && count(r, |event| matches!(event, Event::RtpPacket(_))) == 2
    })?;

    for ((mid, negotiated), l_ssrc) in [(with_dd, true), (without_dd, false)]
        .into_iter()
        .zip(l_ssrcs)
    {
        assert_eq!(sent_dd(&mut l, mid), [negotiated], "frame on {mid}");
        assert_eq!(sent_dd(&mut r, mid), [negotiated], "RTP packet on {mid}");
        let received_by_l = l.events.iter().find_map(|(_, event)| match event {
            Event::MediaData(data) if data.mid == mid => Some(&data.ext_vals),
            _ => None,
        });
        let received_by_r = r.events.iter().find_map(|(_, event)| match event {
            Event::RtpPacket(packet) if packet.header.ssrc == l_ssrc => {
                Some(&packet.header.ext_vals)
            }
            _ => None,
        });
        for received in [received_by_l, received_by_r] {
            let ext_vals = received.expect("one on each m-line");
            assert_eq!(
                ext_vals.user_values.get::<DependencyDescriptor>().is_some(),
                negotiated,
                "received on {mid}"
            );
        }
    }
    Ok(())
}

#[test]
fn dependency_descriptor_survives_retransmission() -> Result<(), RtcError> {
    // A lost packet is resent over RTX with its descriptor, and the receiver reports the
    // repaired packet with it.
    let (ssrc, rtx): (Ssrc, Ssrc) = (1000.into(), 1001.into());
    let (mut l, mut r) = rtp_mode_pair(ssrc, Some(rtx));
    let params = l.params_vp8();
    let (pt, rtx_pt) = (params.pt(), params.resend().expect("VP8 has an RTX PT"));
    // Only the first frame attaches the structure.
    let descriptors: Vec<_> = (0..3_u16)
        .map(|frame_number| {
            let mut bytes = descriptor().as_bytes().to_vec();
            if frame_number > 0 {
                bytes.truncate(3);
            }
            bytes[1..3].copy_from_slice(&frame_number.to_be_bytes());
            DependencyDescriptor::from_bytes(bytes).unwrap()
        })
        .collect();
    let write = |l: &mut TestRtc, index: usize| {
        let mut ext_vals = ExtensionValues::default();
        ext_vals.user_values.set(descriptors[index].clone());
        let wallclock = l.last;
        l.direct_api().stream_tx(&ssrc).unwrap().write_rtp(
            RtpWrite::new(
                pt,
                (100 + index as u64).into(),
                3000 * index as u32,
                wallclock,
                vec![index as u8; 20],
            )
            .marker(true)
            .nackable(true)
            .ext_vals(ext_vals),
        );
    };
    let sent = |l: &TestRtc, sequence_number: u16| {
        l.events.iter().any(|(_, event)| {
            matches!(event.as_raw_packet(), Some(RawPacket::RtpTx(header, _))
                if header.payload_type == pt && header.sequence_number == sequence_number)
        })
    };
    let received = |r: &TestRtc, seq_no: u64| {
        r.events
            .iter()
            .any(|(_, event)| matches!(event, Event::RtpPacket(packet) if *packet.seq_no == seq_no))
    };

    write(&mut l, 0);
    progress_until(&mut l, &mut r, |_, r| received(r, 100))?;
    // The second packet is lost on the way.
    r.set_netem(NetemConfig::new().loss(RandomLoss::new(Probability::ONE)));
    write(&mut l, 1);
    progress_until(&mut l, &mut r, |l, _| sent(l, 101))?;
    r.set_netem(NetemConfig::new());
    // The third reveals the gap, so the receiver asks for the second, which is resent.
    write(&mut l, 2);
    progress_until(&mut l, &mut r, |_, r| received(r, 101))?;

    let raw_received: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, event)| match event.as_raw_packet() {
            Some(RawPacket::RtpRx(header, payload)) => Some((header, payload)),
            _ => None,
        })
        .collect();
    assert!(
        !raw_received
            .iter()
            .any(|(header, _)| header.payload_type == pt && header.sequence_number == 101),
        "the original of the second packet must be lost"
    );
    // The resend carries the descriptor on the wire, after the original sequence number.
    let resent: Vec<_> = raw_received
        .iter()
        .filter(|(header, payload)| {
            header.payload_type == rtx_pt && payload.starts_with(&101_u16.to_be_bytes())
        })
        .map(|(header, _)| header.ext_vals.user_values.get::<DependencyDescriptor>())
        .collect();
    assert!(!resent.is_empty());
    assert!(resent.iter().all(|resent| *resent == Some(&descriptors[1])));

    // Every packet is reported with the descriptor that it was sent with.
    let mut reported: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::RtpPacket(packet) => Some((
                *packet.seq_no,
                packet
                    .header
                    .ext_vals
                    .user_values
                    .get::<DependencyDescriptor>(),
            )),
            _ => None,
        })
        .collect();
    reported.sort_by_key(|(seq_no, _)| *seq_no);
    let expected: Vec<_> = (100..).zip(descriptors.iter().map(Some)).collect();
    assert_eq!(reported, expected);
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
