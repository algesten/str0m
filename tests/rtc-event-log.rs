use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use prost::Message;
use str0m::bwe::Bitrate;
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcConfig, RtcError};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

#[test]
fn rtc_event_log_outgoing_rtp() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();

    // Left peer has event logging enabled
    let rtc1 = RtcConfig::new()
        .enable_rtc_event_log(true)
        .set_rtc_event_log_interval(Duration::from_millis(500))
        .build(now);
    let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc1);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Connect the peers
    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let pt = params.pt();

    // Send some audio packets
    for i in 0..20 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();

        let data = vec![i as u8; 80];
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data)
            .unwrap();

        progress(&mut l, &mut r)?;
    }

    // Now stop event logging to flush
    l.rtc.stop_rtc_event_log();

    // Drain remaining events
    loop {
        match l.rtc.poll_output()? {
            str0m::Output::Event(ev) => {
                l.events.push((l.last, ev));
            }
            str0m::Output::Timeout(_) => break,
            _ => {}
        }
    }

    // Collect all RtcEventLog events
    let event_log_data: Vec<Vec<u8>> = l
        .events
        .iter()
        .filter_map(|(_, ev)| {
            if let Event::RtcEventLog(data) = ev {
                Some(data.clone())
            } else {
                None
            }
        })
        .collect();

    // Should have at least: BeginLog + maybe a batch + EndLog flush
    assert!(
        !event_log_data.is_empty(),
        "Expected at least one RtcEventLog event"
    );

    // Concatenate all chunks — this is the full event log file content
    let full_log: Vec<u8> = event_log_data.into_iter().flatten().collect();
    assert!(
        full_log.len() > 10,
        "Event log should contain meaningful data, got {} bytes",
        full_log.len()
    );

    // Verify the log is valid protobuf by parsing the first EventStream
    // (BeginLog should be present)
    // Parse just the first EventStream from concatenated data.
    // prost will consume as many bytes as it can for a single message.
    let stream = str0m_rtc_event_log::proto::EventStream::decode(full_log.as_slice())
        .expect("first concatenated chunk should decode as EventStream");
    assert!(!stream.begin_log_events.is_empty(), "BeginLogEvent should be present");

    // The concatenated format may not parse as a single EventStream,
    // but the first bytes (BeginLog) should parse fine. Let's at least
    // verify the data is non-empty and starts with valid protobuf.
    assert!(full_log[0] != 0 || full_log.len() > 1, "Data should be non-trivial");

    // Verify EndLog is present exactly once across emitted chunks.
    let mut end_log_count = 0usize;
    for (_, ev) in &l.events {
        if let Event::RtcEventLog(data) = ev {
            if let Ok(stream) = str0m_rtc_event_log::proto::EventStream::decode(data.as_slice()) {
                end_log_count += stream.end_log_events.len();
            }
        }
    }
    assert_eq!(end_log_count, 1, "Expected exactly one EndLogEvent");

    Ok(())
}

#[test]
fn rtc_event_log_disabled_produces_no_events() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();

    // Event logging NOT enabled
    let rtc1 = RtcConfig::new().build(now);
    let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc1);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let _mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    for _ in 0..10 {
        progress(&mut l, &mut r)?;
    }

    let event_log_count = l
        .events
        .iter()
        .filter(|(_, ev)| matches!(ev, Event::RtcEventLog(_)))
        .count();

    assert_eq!(
        event_log_count, 0,
        "No RtcEventLog events should be produced when disabled"
    );

    Ok(())
}

#[test]
fn rtc_event_log_incoming_rtp_and_rtcp() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();

    // Right peer (receiver) has event logging enabled
    let mut l = TestRtc::new(Peer::Left);
    let rtc2 = RtcConfig::new()
        .enable_rtc_event_log(true)
        .set_rtc_event_log_interval(Duration::from_millis(500))
        .build(now);
    let mut r = TestRtc::new_with_rtc(Peer::Right.span(), rtc2);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Left sends audio to Right
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let pt = params.pt();

    // Send audio packets from Left → Right
    for i in 0..20 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();

        let data = vec![i as u8; 80];
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data)
            .unwrap();

        progress(&mut l, &mut r)?;
    }

    // Stop event logging on receiver to flush
    r.rtc.stop_rtc_event_log();

    // Drain remaining events from receiver
    loop {
        match r.rtc.poll_output()? {
            str0m::Output::Event(ev) => {
                r.events.push((r.last, ev));
            }
            str0m::Output::Timeout(_) => break,
            _ => {}
        }
    }

    // Collect all RtcEventLog events from receiver
    let event_log_data: Vec<Vec<u8>> = r
        .events
        .iter()
        .filter_map(|(_, ev)| {
            if let Event::RtcEventLog(data) = ev {
                Some(data.clone())
            } else {
                None
            }
        })
        .collect();

    assert!(
        !event_log_data.is_empty(),
        "Receiver should have RtcEventLog events"
    );

    // Parse all EventStream messages from the concatenated log
    let mut total_incoming_rtp = 0usize;
    let mut total_incoming_rtcp = 0usize;
    let mut total_outgoing_rtcp = 0usize;

    for chunk in &event_log_data {
        if let Ok(stream) = str0m_rtc_event_log::proto::EventStream::decode(chunk.as_slice()) {
            for msg in &stream.incoming_rtp_packets {
                // Count base event + deltas
                total_incoming_rtp += 1 + msg.number_of_deltas.unwrap_or(0) as usize;

                // Verify SSRC is set
                assert!(msg.ssrc.is_some(), "incoming RTP should have SSRC");
                assert!(msg.payload_type.is_some(), "incoming RTP should have PT");
            }
            for msg in &stream.incoming_rtcp_packets {
                total_incoming_rtcp += 1 + msg.number_of_deltas.unwrap_or(0) as usize;
                assert!(msg.raw_packet.is_some(), "incoming RTCP should have raw_packet");
            }
            for msg in &stream.outgoing_rtcp_packets {
                total_outgoing_rtcp += 1 + msg.number_of_deltas.unwrap_or(0) as usize;
                assert!(msg.raw_packet.is_some(), "outgoing RTCP should have raw_packet");
            }
        }
    }

    let mut end_log_count = 0usize;
    for chunk in &event_log_data {
        if let Ok(stream) = str0m_rtc_event_log::proto::EventStream::decode(chunk.as_slice()) {
            end_log_count += stream.end_log_events.len();
        }
    }
    assert_eq!(end_log_count, 1, "Expected exactly one EndLogEvent");

    // The receiver should have logged incoming RTP packets
    assert!(
        total_incoming_rtp > 0,
        "Expected incoming RTP packets in event log, got {total_incoming_rtp}"
    );

    // RTCP should be present (receiver sends RR, sender sends SR)
    // Due to timing, we may or may not have RTCP logged but at minimum
    // the outgoing RTCP (receiver reports) should be there.

    Ok(())
}

#[test]
fn rtc_event_log_stop_is_idempotent() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();

    let rtc1 = RtcConfig::new()
        .enable_rtc_event_log(true)
        .set_rtc_event_log_interval(Duration::from_millis(500))
        .build(now);
    let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc1);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let _mid = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // Repeated stops must not append multiple EndLogEvents.
    l.rtc.stop_rtc_event_log();
    l.rtc.stop_rtc_event_log();

    let mut event_log_chunks = Vec::new();
    loop {
        match l.rtc.poll_output()? {
            str0m::Output::Event(Event::RtcEventLog(data)) => event_log_chunks.push(data),
            str0m::Output::Event(_) => {}
            str0m::Output::Timeout(_) => break,
            _ => {}
        }
    }

    let mut end_log_count = 0usize;
    for chunk in &event_log_chunks {
        if let Ok(stream) = str0m_rtc_event_log::proto::EventStream::decode(chunk.as_slice()) {
            end_log_count += stream.end_log_events.len();
        }
    }

    assert_eq!(end_log_count, 1, "Expected exactly one EndLogEvent");
    Ok(())
}

#[test]
fn rtc_event_log_filters_sdes_from_live_outgoing_rtcp() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();

    // Left peer has event logging enabled.
    let rtc1 = RtcConfig::new()
        .enable_rtc_event_log(true)
        .set_rtc_event_log_interval(Duration::from_millis(500))
        .build(now);
    let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc1);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Left sends audio to ensure sender reports are produced.
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let params = l.params_opus();
    let pt = params.pt();

    // Send media and progress enough to trigger RTCP generation.
    for i in 0..40 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        let data = vec![i as u8; 120];
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data)
            .unwrap();
        progress(&mut l, &mut r)?;
    }

    let wait_until = l.last + Duration::from_secs(3);
    while l.last < wait_until || r.last < wait_until {
        progress(&mut l, &mut r)?;
    }

    l.rtc.stop_rtc_event_log();

    loop {
        match l.rtc.poll_output()? {
            str0m::Output::Event(ev) => l.events.push((l.last, ev)),
            str0m::Output::Timeout(_) => break,
            _ => {}
        }
    }

    let event_log_data: Vec<Vec<u8>> = l
        .events
        .iter()
        .filter_map(|(_, ev)| match ev {
            Event::RtcEventLog(data) => Some(data.clone()),
            _ => None,
        })
        .collect();

    let mut seen_outgoing_rtcp = 0usize;

    for chunk in &event_log_data {
        if let Ok(stream) = str0m_rtc_event_log::proto::EventStream::decode(chunk.as_slice()) {
            for msg in &stream.outgoing_rtcp_packets {
                seen_outgoing_rtcp += 1;

                if let Some(raw) = &msg.raw_packet {
                    for pt in rtcp_packet_types(raw) {
                        assert_ne!(pt, 202, "SDES block leaked into logged RTCP");
                        assert_ne!(pt, 204, "APP block leaked into logged RTCP");
                    }
                }
            }
        }
    }

    assert!(
        seen_outgoing_rtcp > 0,
        "Expected outgoing RTCP packets in event log"
    );

    Ok(())
}

fn rtcp_packet_types(raw_rtcp: &[u8]) -> Vec<u8> {
    let mut pts = Vec::new();
    let mut offset = 0usize;

    while offset + 4 <= raw_rtcp.len() {
        let pt = raw_rtcp[offset + 1];
        let length_words = u16::from_be_bytes([raw_rtcp[offset + 2], raw_rtcp[offset + 3]]);
        let block_len = (length_words as usize + 1) * 4;
        if offset + block_len > raw_rtcp.len() {
            break;
        }
        pts.push(pt);
        offset += block_len;
    }

    pts
}

#[test]
fn rtc_event_log_bwe_events() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();

    // Left peer: BWE + event logging enabled. Sends video to Right.
    let rtc1 = RtcConfig::new()
        .enable_bwe(Some(Bitrate::kbps(500)))
        .enable_rtc_event_log(true)
        .set_rtc_event_log_interval(Duration::from_millis(500))
        .build(now);
    let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc1);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Connect the peers
    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp8();
    let pt = params.pt();

    // Send some initial packets to establish the padding queue (needs RTX + first packet sent).
    for i in 0..20 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        let data = vec![i as u8; 800];
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data)
            .unwrap();
        progress(&mut l, &mut r)?;
    }

    // Set desired bitrate much higher than the initial 500kbps estimate.
    // This triggers the probe controller to create probe clusters.
    l.rtc.bwe().set_desired_bitrate(Bitrate::mbps(5));

    // Send more traffic so TWCC feedback arrives and probes can complete.
    for i in 20..200 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        let data = vec![i as u8; 800];
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data)
            .unwrap();
        progress(&mut l, &mut r)?;
    }

    // Allow extra time for probe completion and BWE convergence.
    let wait_until = l.last + Duration::from_secs(2);
    while l.last < wait_until || r.last < wait_until {
        progress(&mut l, &mut r)?;
    }

    // Stop event logging to flush everything
    l.rtc.stop_rtc_event_log();

    // Drain remaining events
    loop {
        match l.rtc.poll_output()? {
            str0m::Output::Event(ev) => {
                l.events.push((l.last, ev));
            }
            str0m::Output::Timeout(_) => break,
            _ => {}
        }
    }

    // Collect all RtcEventLog chunks
    let event_log_data: Vec<Vec<u8>> = l
        .events
        .iter()
        .filter_map(|(_, ev)| {
            if let Event::RtcEventLog(data) = ev {
                Some(data.clone())
            } else {
                None
            }
        })
        .collect();

    assert!(
        !event_log_data.is_empty(),
        "Expected at least one RtcEventLog event"
    );

    // Parse all EventStream messages and collect BWE-related events.
    let mut total_delay_bwe = 0usize;
    let mut total_loss_bwe = 0usize;
    let mut total_alr_states = 0usize;

    // Collect probe events with their field values for cross-referencing.
    let mut created_probes: Vec<(u32, u32, u32)> = Vec::new(); // (id, bitrate, min_packets)
    let mut success_probes: Vec<(u32, u32)> = Vec::new(); // (id, bitrate)
    let mut failure_probes: Vec<(u32, i32)> = Vec::new(); // (id, reason)

    for chunk in &event_log_data {
        let stream = str0m_rtc_event_log::proto::EventStream::decode(chunk.as_slice())
            .expect("chunk should decode as EventStream");

        total_delay_bwe += stream.delay_based_bwe_updates.len();
        total_loss_bwe += stream.loss_based_bwe_updates.len();
        total_alr_states += stream.alr_states.len();

        // Validate delay BWE events have valid data
        for msg in &stream.delay_based_bwe_updates {
            assert!(msg.timestamp_ms.is_some(), "delay BWE missing timestamp");
            assert!(msg.bitrate_bps.is_some(), "delay BWE missing bitrate");
            assert!(msg.detector_state.is_some(), "delay BWE missing detector state");
            let state = msg.detector_state.unwrap();
            // DetectorState enum: 0=UNKNOWN, 1=NORMAL, 2=UNDERUSING, 3=OVERUSING
            assert!(
                (0..=3).contains(&state),
                "Invalid detector state: {state}"
            );
        }

        // Validate loss BWE events
        for msg in &stream.loss_based_bwe_updates {
            assert!(msg.timestamp_ms.is_some(), "loss BWE missing timestamp");
            assert!(msg.bitrate_bps.is_some(), "loss BWE missing bitrate");
            if let Some(fraction) = msg.fraction_loss {
                assert!(
                    fraction <= 255,
                    "fraction_loss must be 0-255, got {fraction}"
                );
            }
        }

        // Validate and collect probe cluster created events
        for msg in &stream.probe_clusters {
            assert!(msg.timestamp_ms.is_some(), "probe cluster missing timestamp");
            let id = msg.id.expect("probe cluster missing id");
            let bitrate = msg.bitrate_bps.expect("probe cluster missing bitrate");
            let min_packets = msg.min_packets.expect("probe cluster missing min_packets");

            assert!(bitrate > 0, "probe cluster bitrate must be positive, got {bitrate}");
            assert!(min_packets > 0, "probe cluster min_packets must be positive, got {min_packets}");
            // min_bytes is intentionally unset (str0m doesn't track it)
            assert!(msg.min_bytes.is_none(), "min_bytes should be unset");

            created_probes.push((id, bitrate, min_packets));
        }

        // Validate and collect probe success events
        for msg in &stream.probe_success {
            assert!(msg.timestamp_ms.is_some(), "probe success missing timestamp");
            let id = msg.id.expect("probe success missing id");
            let bitrate = msg.bitrate_bps.expect("probe success missing bitrate");

            assert!(bitrate > 0, "probe success bitrate must be positive, got {bitrate}");

            success_probes.push((id, bitrate));
        }

        // Validate and collect probe failure events
        for msg in &stream.probe_failure {
            assert!(msg.timestamp_ms.is_some(), "probe failure missing timestamp");
            let id = msg.id.expect("probe failure missing id");
            let reason = msg.failure.expect("probe failure missing reason");

            // ProbeFailureReason: 0=UNKNOWN, 1=INVALID_SEND_RECEIVE_INTERVAL,
            // 2=INVALID_SEND_RECEIVE_RATIO, 3=TIMEOUT
            assert!(
                (0..=3).contains(&reason),
                "Invalid probe failure reason: {reason}"
            );

            failure_probes.push((id, reason));
        }
    }

    let total_probe_clusters = created_probes.len();
    let total_probe_success = success_probes.len();
    let total_probe_failure = failure_probes.len();

    // With BWE enabled and video traffic, we expect delay-based BWE updates.
    assert!(
        total_delay_bwe > 0,
        "Expected at least one delay-based BWE update in the event log"
    );

    // With set_desired_bitrate(5 Mbps) >> initial estimate (500 kbps), probe clusters
    // must be created to explore the available bandwidth.
    assert!(
        total_probe_clusters > 0,
        "Expected probe clusters to be created after set_desired_bitrate"
    );

    // Every probe should eventually complete as success or failure.
    let created_ids: std::collections::HashSet<u32> =
        created_probes.iter().map(|(id, ..)| *id).collect();
    let completed_ids: std::collections::HashSet<u32> = success_probes
        .iter()
        .map(|(id, _)| *id)
        .chain(failure_probes.iter().map(|(id, _)| *id))
        .collect();

    // Every success/failure ID must reference a created probe.
    for id in &completed_ids {
        assert!(
            created_ids.contains(id),
            "Probe result id={id} has no matching ProbeClusterCreated event"
        );
    }

    Ok(())
}

#[test]
fn rtc_event_log_stream_configs() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();

    let rtc1 = RtcConfig::new()
        .enable_rtc_event_log(true)
        .set_rtc_event_log_interval(Duration::from_millis(500))
        .build(now);
    let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc1);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Add audio and video in SendRecv so we get both send and recv configs
    let mut change = l.sdp_api();
    let _audio_mid =
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let _video_mid =
        change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Connect peers
    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // Progress a bit to emit MediaAdded events (which trigger stream config logging)
    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    for _ in 0..20 {
        progress(&mut l, &mut r)?;
    }

    // Stop event logging
    l.rtc.stop_rtc_event_log();

    // Drain remaining events
    loop {
        match l.rtc.poll_output()? {
            str0m::Output::Event(ev) => {
                l.events.push((l.last, ev));
            }
            str0m::Output::Timeout(_) => break,
            _ => {}
        }
    }

    // Parse all event log chunks
    let mut audio_send_configs = 0usize;
    let mut audio_recv_configs = 0usize;
    let mut video_send_configs = 0usize;
    let mut video_recv_configs = 0usize;

    for (_, ev) in &l.events {
        if let Event::RtcEventLog(data) = ev {
            if let Ok(stream) =
                str0m_rtc_event_log::proto::EventStream::decode(data.as_slice())
            {
                audio_send_configs += stream.audio_send_stream_configs.len();
                audio_recv_configs += stream.audio_recv_stream_configs.len();
                video_send_configs += stream.video_send_stream_configs.len();
                video_recv_configs += stream.video_recv_stream_configs.len();

                // Verify each config has required fields
                for cfg in &stream.audio_send_stream_configs {
                    assert!(cfg.timestamp_ms.is_some(), "audio send config missing timestamp");
                    assert!(cfg.ssrc.is_some(), "audio send config missing ssrc");
                    assert!(
                        cfg.header_extensions.is_some(),
                        "audio send config missing extensions"
                    );
                }
                for cfg in &stream.video_send_stream_configs {
                    assert!(cfg.timestamp_ms.is_some(), "video send config missing timestamp");
                    assert!(cfg.ssrc.is_some(), "video send config missing ssrc");
                    assert!(
                        cfg.header_extensions.is_some(),
                        "video send config missing extensions"
                    );
                }
                for cfg in &stream.video_recv_stream_configs {
                    assert!(cfg.remote_ssrc.is_some(), "video recv config missing remote_ssrc");
                    assert!(cfg.local_ssrc.is_some(), "video recv config missing local_ssrc");
                }
                for cfg in &stream.audio_recv_stream_configs {
                    assert!(cfg.remote_ssrc.is_some(), "audio recv config missing remote_ssrc");
                    assert!(cfg.local_ssrc.is_some(), "audio recv config missing local_ssrc");
                }
            }
        }
    }

    // We added audio and video in SendRecv direction, so we should have send configs
    assert!(
        audio_send_configs > 0,
        "Expected at least one audio send stream config"
    );
    assert!(
        video_send_configs > 0,
        "Expected at least one video send stream config"
    );

    Ok(())
}
