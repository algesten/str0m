use std::collections::BTreeMap;

use prost::Message;

use crate::delta::{encode_blobs, encode_deltas};
use crate::events::{
    AlrStateEvent, AudioRecvStreamConfig, AudioSendStreamConfig, DelayBasedBweUpdate,
    IncomingRtcp, IncomingRtp, LossBasedBweUpdate, OutgoingRtcp, OutgoingRtp,
    ProbeClusterCreated, ProbeClusterFailure, ProbeClusterSuccess, RtcEvent,
    VideoRecvStreamConfig, VideoSendStreamConfig,
};
use crate::filter::filter_rtcp;
use crate::proto;

/// Encodes RTC events into the WebRTC event log v2 protobuf format.
///
/// Events are batched by type and delta-encoded for compression.
/// The output is a sequence of serialized `EventStream` protobuf messages
/// that can be concatenated into a single file.
///
/// The encoder is stateless — delta encoding is computed within each batch,
/// not across batches.
pub struct RtcEventLogEncoder;

impl RtcEventLogEncoder {
    pub fn new() -> Self {
        RtcEventLogEncoder
    }

    /// Encode a BeginLogEvent as a standalone EventStream.
    /// This must be the first bytes written to the output file.
    pub fn encode_log_start(&self, timestamp_ms: i64, utc_time_ms: i64) -> Vec<u8> {
        let event = proto::BeginLogEvent {
            timestamp_ms: Some(timestamp_ms),
            version: Some(2),
            utc_time_ms: Some(utc_time_ms),
        };

        let stream = proto::EventStream {
            begin_log_events: vec![event],
            ..Default::default()
        };

        stream.encode_to_vec()
    }

    /// Encode an EndLogEvent as a standalone EventStream.
    /// This must be the last bytes written to the output file.
    pub fn encode_log_end(&self, timestamp_ms: i64) -> Vec<u8> {
        let event = proto::EndLogEvent {
            timestamp_ms: Some(timestamp_ms),
        };

        let stream = proto::EventStream {
            end_log_events: vec![event],
            ..Default::default()
        };

        stream.encode_to_vec()
    }

    /// Encode a batch of events into a serialized EventStream.
    ///
    /// Events are grouped by type. RTP events are further sub-grouped by SSRC
    /// for effective delta compression (one proto message per SSRC).
    pub fn encode_batch(&self, events: &[RtcEvent]) -> Vec<u8> {
        let mut stream = proto::EventStream::default();

        // Collect events by type. RTP events are sub-grouped by SSRC.
        let mut outgoing_rtp_by_ssrc: BTreeMap<u32, Vec<&OutgoingRtp>> = BTreeMap::new();
        let mut incoming_rtp_by_ssrc: BTreeMap<u32, Vec<&IncomingRtp>> = BTreeMap::new();
        let mut incoming_rtcp: Vec<&IncomingRtcp> = Vec::new();
        let mut outgoing_rtcp: Vec<&OutgoingRtcp> = Vec::new();
        let mut loss_bwe: Vec<&LossBasedBweUpdate> = Vec::new();
        let mut delay_bwe: Vec<&DelayBasedBweUpdate> = Vec::new();

        for event in events {
            match event {
                RtcEvent::OutgoingRtp(rtp) => {
                    outgoing_rtp_by_ssrc
                        .entry(rtp.ssrc)
                        .or_default()
                        .push(rtp);
                }
                RtcEvent::IncomingRtp(rtp) => {
                    incoming_rtp_by_ssrc
                        .entry(rtp.ssrc)
                        .or_default()
                        .push(rtp);
                }
                RtcEvent::IncomingRtcp(rtcp) => {
                    incoming_rtcp.push(rtcp);
                }
                RtcEvent::OutgoingRtcp(rtcp) => {
                    outgoing_rtcp.push(rtcp);
                }
                RtcEvent::LossBasedBweUpdate(e) => {
                    loss_bwe.push(e);
                }
                RtcEvent::DelayBasedBweUpdate(e) => {
                    delay_bwe.push(e);
                }
                // Individually-serialized events are handled below.
                RtcEvent::ProbeClusterCreated(e) => {
                    stream.probe_clusters.push(encode_probe_cluster_created(e));
                }
                RtcEvent::ProbeClusterSuccess(e) => {
                    stream.probe_success.push(encode_probe_success(e));
                }
                RtcEvent::ProbeClusterFailure(e) => {
                    stream.probe_failure.push(encode_probe_failure(e));
                }
                RtcEvent::AlrStateEvent(e) => {
                    stream.alr_states.push(encode_alr_state(e));
                }
                RtcEvent::AudioRecvStreamConfig(e) => {
                    stream
                        .audio_recv_stream_configs
                        .push(encode_audio_recv_stream_config(e));
                }
                RtcEvent::AudioSendStreamConfig(e) => {
                    stream
                        .audio_send_stream_configs
                        .push(encode_audio_send_stream_config(e));
                }
                RtcEvent::VideoRecvStreamConfig(e) => {
                    stream
                        .video_recv_stream_configs
                        .push(encode_video_recv_stream_config(e));
                }
                RtcEvent::VideoSendStreamConfig(e) => {
                    stream
                        .video_send_stream_configs
                        .push(encode_video_send_stream_config(e));
                }
                // BeginLog and EndLog are handled by encode_log_start/encode_log_end
                RtcEvent::BeginLog(_) | RtcEvent::EndLog(_) => {}
            }
        }

        // Encode each SSRC group as a separate RtpPackets message.
        // Sort each group by timestamp to ensure correct delta encoding,
        // even if events were recorded slightly out of order.
        // This is O(n) for already-sorted data (common case).
        for (_ssrc, mut group) in outgoing_rtp_by_ssrc {
            group.sort_by_key(|e| e.timestamp_ms);
            if let Some(msg) = encode_outgoing_rtp_batch(&group) {
                stream.outgoing_rtp_packets.push(msg);
            }
        }

        for (_ssrc, mut group) in incoming_rtp_by_ssrc {
            group.sort_by_key(|e| e.timestamp_ms);
            if let Some(msg) = encode_incoming_rtp_batch(&group) {
                stream.incoming_rtp_packets.push(msg);
            }
        }

        // RTCP events are batched together (not grouped by SSRC).
        if !incoming_rtcp.is_empty() {
            incoming_rtcp.sort_by_key(|e| e.timestamp_ms);
            if let Some(msg) = encode_incoming_rtcp_batch(&incoming_rtcp) {
                stream.incoming_rtcp_packets.push(msg);
            }
        }

        if !outgoing_rtcp.is_empty() {
            outgoing_rtcp.sort_by_key(|e| e.timestamp_ms);
            if let Some(msg) = encode_outgoing_rtcp_batch(&outgoing_rtcp) {
                stream.outgoing_rtcp_packets.push(msg);
            }
        }

        // Delta-encoded BWE updates.
        if !loss_bwe.is_empty() {
            loss_bwe.sort_by_key(|e| e.timestamp_ms);
            if let Some(msg) = encode_loss_bwe_batch(&loss_bwe) {
                stream.loss_based_bwe_updates.push(msg);
            }
        }

        if !delay_bwe.is_empty() {
            delay_bwe.sort_by_key(|e| e.timestamp_ms);
            if let Some(msg) = encode_delay_bwe_batch(&delay_bwe) {
                stream.delay_based_bwe_updates.push(msg);
            }
        }

        stream.encode_to_vec()
    }
}

impl Default for RtcEventLogEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a batch of OutgoingRtp events (same SSRC) into a protobuf message.
fn encode_outgoing_rtp_batch(events: &[&OutgoingRtp]) -> Option<proto::OutgoingRtpPackets> {
    let first = events.first()?;

    let mut msg = proto::OutgoingRtpPackets {
        // Base event fields
        timestamp_ms: Some(first.timestamp_ms),
        marker: Some(first.marker),
        payload_type: Some(first.payload_type),
        sequence_number: Some(first.sequence_number),
        rtp_timestamp: Some(first.rtp_timestamp),
        ssrc: Some(first.ssrc),
        payload_size: Some(first.payload_size),
        header_size: Some(first.header_size),
        padding_size: Some(first.padding_size),
        transport_sequence_number: first.transport_sequence_number,
        transmission_time_offset: first.transmission_time_offset.map(|v| v as i32),
        absolute_send_time: first.absolute_send_time,
        video_rotation: first.video_rotation,
        audio_level: first.audio_level,
        voice_activity: first.voice_activity,
        rtx_original_sequence_number: first.rtx_original_sequence_number,
        probe_cluster_id: first.probe_cluster_id,
        ..Default::default()
    };

    if events.len() <= 1 {
        return Some(msg);
    }

    // Delta encode subsequent events
    let number_of_deltas = (events.len() - 1) as u32;
    msg.number_of_deltas = Some(number_of_deltas);

    let rest = &events[1..];

    // Each field is delta-encoded independently with its own value_width_bits.
    // If encode_deltas returns empty, we leave the _deltas field unset (parser
    // interprets missing field as "all values equal to base").

    // timestamp_ms (value_width=64, never wraps)
    set_deltas(
        &mut msg.timestamp_ms_deltas,
        Some(first.timestamp_ms as u64),
        &collect_required(rest, |e| e.timestamp_ms as u64),
        64,
    );

    // marker (value_width=64, boolean as u64)
    set_deltas(
        &mut msg.marker_deltas,
        Some(first.marker as u64),
        &collect_required(rest, |e| e.marker as u64),
        64,
    );

    // payload_type (value_width=64)
    set_deltas(
        &mut msg.payload_type_deltas,
        Some(first.payload_type as u64),
        &collect_required(rest, |e| e.payload_type as u64),
        64,
    );

    // sequence_number (value_width=16, wraps)
    set_deltas(
        &mut msg.sequence_number_deltas,
        Some(first.sequence_number as u64),
        &collect_required(rest, |e| e.sequence_number as u64),
        16,
    );

    // rtp_timestamp (value_width=32, wraps)
    set_deltas(
        &mut msg.rtp_timestamp_deltas,
        Some(first.rtp_timestamp as u64),
        &collect_required(rest, |e| e.rtp_timestamp as u64),
        32,
    );

    // ssrc (value_width=32) — same SSRC in batch, but encode anyway
    set_deltas(
        &mut msg.ssrc_deltas,
        Some(first.ssrc as u64),
        &collect_required(rest, |e| e.ssrc as u64),
        32,
    );

    // payload_size (value_width=64)
    set_deltas(
        &mut msg.payload_size_deltas,
        Some(first.payload_size as u64),
        &collect_required(rest, |e| e.payload_size as u64),
        64,
    );

    // header_size (value_width=64)
    set_deltas(
        &mut msg.header_size_deltas,
        Some(first.header_size as u64),
        &collect_required(rest, |e| e.header_size as u64),
        64,
    );

    // padding_size (value_width=64)
    set_deltas(
        &mut msg.padding_size_deltas,
        Some(first.padding_size as u64),
        &collect_required(rest, |e| e.padding_size as u64),
        64,
    );

    // transport_sequence_number (optional, value_width=16)
    set_deltas(
        &mut msg.transport_sequence_number_deltas,
        first.transport_sequence_number.map(|v| v as u64),
        &collect_optional(rest, |e| e.transport_sequence_number.map(|v| v as u64)),
        16,
    );

    // transmission_time_offset (optional, value_width=32)
    set_deltas(
        &mut msg.transmission_time_offset_deltas,
        first.transmission_time_offset.map(|v| v as u64),
        &collect_optional(rest, |e| e.transmission_time_offset.map(|v| v as u64)),
        32,
    );

    // absolute_send_time (optional, value_width=24)
    set_deltas(
        &mut msg.absolute_send_time_deltas,
        first.absolute_send_time.map(|v| v as u64),
        &collect_optional(rest, |e| e.absolute_send_time.map(|v| v as u64)),
        24,
    );

    // video_rotation (optional, value_width=64)
    set_deltas(
        &mut msg.video_rotation_deltas,
        first.video_rotation.map(|v| v as u64),
        &collect_optional(rest, |e| e.video_rotation.map(|v| v as u64)),
        64,
    );

    // audio_level (optional, value_width=64)
    set_deltas(
        &mut msg.audio_level_deltas,
        first.audio_level.map(|v| v as u64),
        &collect_optional(rest, |e| e.audio_level.map(|v| v as u64)),
        64,
    );

    // voice_activity (optional, value_width=64)
    set_deltas(
        &mut msg.voice_activity_deltas,
        first.voice_activity.map(|v| v as u64),
        &collect_optional(rest, |e| e.voice_activity.map(|v| v as u64)),
        64,
    );

    // rtx_original_sequence_number (optional, value_width=16)
    set_deltas(
        &mut msg.rtx_original_sequence_number_deltas,
        first.rtx_original_sequence_number.map(|v| v as u64),
        &collect_optional(rest, |e| {
            e.rtx_original_sequence_number.map(|v| v as u64)
        }),
        16,
    );

    // probe_cluster_id (optional, value_width=64, signed stored as unsigned)
    set_deltas(
        &mut msg.probe_cluster_id_deltas,
        first.probe_cluster_id.map(|v| v as u32 as u64),
        &collect_optional(rest, |e| e.probe_cluster_id.map(|v| v as u32 as u64)),
        64,
    );

    Some(msg)
}

/// Encode a batch of IncomingRtp events (same SSRC) into a protobuf message.
fn encode_incoming_rtp_batch(events: &[&IncomingRtp]) -> Option<proto::IncomingRtpPackets> {
    let first = events.first()?;

    let mut msg = proto::IncomingRtpPackets {
        timestamp_ms: Some(first.timestamp_ms),
        marker: Some(first.marker),
        payload_type: Some(first.payload_type),
        sequence_number: Some(first.sequence_number),
        rtp_timestamp: Some(first.rtp_timestamp),
        ssrc: Some(first.ssrc),
        payload_size: Some(first.payload_size),
        header_size: Some(first.header_size),
        padding_size: Some(first.padding_size),
        transport_sequence_number: first.transport_sequence_number,
        transmission_time_offset: first.transmission_time_offset.map(|v| v as i32),
        absolute_send_time: first.absolute_send_time,
        video_rotation: first.video_rotation,
        audio_level: first.audio_level,
        voice_activity: first.voice_activity,
        rtx_original_sequence_number: first.rtx_original_sequence_number,
        ..Default::default()
    };

    if events.len() <= 1 {
        return Some(msg);
    }

    let number_of_deltas = (events.len() - 1) as u32;
    msg.number_of_deltas = Some(number_of_deltas);

    let rest = &events[1..];

    set_deltas(
        &mut msg.timestamp_ms_deltas,
        Some(first.timestamp_ms as u64),
        &collect_required(rest, |e| e.timestamp_ms as u64),
        64,
    );
    set_deltas(
        &mut msg.marker_deltas,
        Some(first.marker as u64),
        &collect_required(rest, |e| e.marker as u64),
        64,
    );
    set_deltas(
        &mut msg.payload_type_deltas,
        Some(first.payload_type as u64),
        &collect_required(rest, |e| e.payload_type as u64),
        64,
    );
    set_deltas(
        &mut msg.sequence_number_deltas,
        Some(first.sequence_number as u64),
        &collect_required(rest, |e| e.sequence_number as u64),
        16,
    );
    set_deltas(
        &mut msg.rtp_timestamp_deltas,
        Some(first.rtp_timestamp as u64),
        &collect_required(rest, |e| e.rtp_timestamp as u64),
        32,
    );
    set_deltas(
        &mut msg.ssrc_deltas,
        Some(first.ssrc as u64),
        &collect_required(rest, |e| e.ssrc as u64),
        32,
    );
    set_deltas(
        &mut msg.payload_size_deltas,
        Some(first.payload_size as u64),
        &collect_required(rest, |e| e.payload_size as u64),
        64,
    );
    set_deltas(
        &mut msg.header_size_deltas,
        Some(first.header_size as u64),
        &collect_required(rest, |e| e.header_size as u64),
        64,
    );
    set_deltas(
        &mut msg.padding_size_deltas,
        Some(first.padding_size as u64),
        &collect_required(rest, |e| e.padding_size as u64),
        64,
    );
    set_deltas(
        &mut msg.transport_sequence_number_deltas,
        first.transport_sequence_number.map(|v| v as u64),
        &collect_optional(rest, |e| e.transport_sequence_number.map(|v| v as u64)),
        16,
    );
    set_deltas(
        &mut msg.transmission_time_offset_deltas,
        first.transmission_time_offset.map(|v| v as u64),
        &collect_optional(rest, |e| e.transmission_time_offset.map(|v| v as u64)),
        32,
    );
    set_deltas(
        &mut msg.absolute_send_time_deltas,
        first.absolute_send_time.map(|v| v as u64),
        &collect_optional(rest, |e| e.absolute_send_time.map(|v| v as u64)),
        24,
    );
    set_deltas(
        &mut msg.video_rotation_deltas,
        first.video_rotation.map(|v| v as u64),
        &collect_optional(rest, |e| e.video_rotation.map(|v| v as u64)),
        64,
    );
    set_deltas(
        &mut msg.audio_level_deltas,
        first.audio_level.map(|v| v as u64),
        &collect_optional(rest, |e| e.audio_level.map(|v| v as u64)),
        64,
    );
    set_deltas(
        &mut msg.voice_activity_deltas,
        first.voice_activity.map(|v| v as u64),
        &collect_optional(rest, |e| e.voice_activity.map(|v| v as u64)),
        64,
    );
    set_deltas(
        &mut msg.rtx_original_sequence_number_deltas,
        first.rtx_original_sequence_number.map(|v| v as u64),
        &collect_optional(rest, |e| {
            e.rtx_original_sequence_number.map(|v| v as u64)
        }),
        16,
    );

    Some(msg)
}

/// Encode a batch of IncomingRtcp events into a protobuf message.
fn encode_incoming_rtcp_batch(events: &[&IncomingRtcp]) -> Option<proto::IncomingRtcpPackets> {
    let first = events.first()?;

    let filtered_first = filter_rtcp(&first.raw_packet);

    let mut msg = proto::IncomingRtcpPackets {
        timestamp_ms: Some(first.timestamp_ms),
        raw_packet: Some(filtered_first),
        ..Default::default()
    };

    if events.len() <= 1 {
        return Some(msg);
    }

    let number_of_deltas = (events.len() - 1) as u32;
    msg.number_of_deltas = Some(number_of_deltas);

    let rest = &events[1..];

    set_deltas(
        &mut msg.timestamp_ms_deltas,
        Some(first.timestamp_ms as u64),
        &collect_required(rest, |e| e.timestamp_ms as u64),
        64,
    );

    let filtered_rest: Vec<Vec<u8>> = rest.iter().map(|e| filter_rtcp(&e.raw_packet)).collect();
    msg.raw_packet_blobs = Some(encode_blobs(&filtered_rest));

    Some(msg)
}

/// Encode a batch of OutgoingRtcp events into a protobuf message.
fn encode_outgoing_rtcp_batch(events: &[&OutgoingRtcp]) -> Option<proto::OutgoingRtcpPackets> {
    let first = events.first()?;

    let filtered_first = filter_rtcp(&first.raw_packet);

    let mut msg = proto::OutgoingRtcpPackets {
        timestamp_ms: Some(first.timestamp_ms),
        raw_packet: Some(filtered_first),
        ..Default::default()
    };

    if events.len() <= 1 {
        return Some(msg);
    }

    let number_of_deltas = (events.len() - 1) as u32;
    msg.number_of_deltas = Some(number_of_deltas);

    let rest = &events[1..];

    set_deltas(
        &mut msg.timestamp_ms_deltas,
        Some(first.timestamp_ms as u64),
        &collect_required(rest, |e| e.timestamp_ms as u64),
        64,
    );

    let filtered_rest: Vec<Vec<u8>> = rest.iter().map(|e| filter_rtcp(&e.raw_packet)).collect();
    msg.raw_packet_blobs = Some(encode_blobs(&filtered_rest));

    Some(msg)
}

/// If encoded deltas are non-empty, set the proto field.
fn set_deltas(
    field: &mut Option<Vec<u8>>,
    base: Option<u64>,
    values: &[Option<u64>],
    value_width_bits: u64,
) {
    if values.is_empty() {
        return;
    }
    let encoded = encode_deltas(base, values, value_width_bits);
    if !encoded.is_empty() {
        *field = Some(encoded);
    }
}

/// Collect required (always-present) field values from a slice of events.
fn collect_required<T, F>(events: &[&T], f: F) -> Vec<Option<u64>>
where
    F: Fn(&T) -> u64,
{
    events.iter().map(|e| Some(f(e))).collect()
}

/// Collect optional field values from a slice of events.
fn collect_optional<T, F>(events: &[&T], f: F) -> Vec<Option<u64>>
where
    F: Fn(&T) -> Option<u64>,
{
    events.iter().map(|e| f(e)).collect()
}

/// Encode a batch of LossBasedBweUpdate events (delta-encoded).
fn encode_loss_bwe_batch(events: &[&LossBasedBweUpdate]) -> Option<proto::LossBasedBweUpdates> {
    let first = events.first()?;

    let mut msg = proto::LossBasedBweUpdates {
        timestamp_ms: Some(first.timestamp_ms),
        bitrate_bps: Some(first.bitrate_bps),
        fraction_loss: Some(first.fraction_loss),
        total_packets: Some(first.total_packets),
        ..Default::default()
    };

    if events.len() <= 1 {
        return Some(msg);
    }

    let number_of_deltas = (events.len() - 1) as u32;
    msg.number_of_deltas = Some(number_of_deltas);

    let rest = &events[1..];

    set_deltas(
        &mut msg.timestamp_ms_deltas,
        Some(first.timestamp_ms as u64),
        &collect_required(rest, |e| e.timestamp_ms as u64),
        64,
    );
    set_deltas(
        &mut msg.bitrate_bps_deltas,
        Some(first.bitrate_bps as u64),
        &collect_required(rest, |e| e.bitrate_bps as u64),
        64,
    );
    set_deltas(
        &mut msg.fraction_loss_deltas,
        Some(first.fraction_loss as u64),
        &collect_required(rest, |e| e.fraction_loss as u64),
        64,
    );
    set_deltas(
        &mut msg.total_packets_deltas,
        Some(first.total_packets as u64),
        &collect_required(rest, |e| e.total_packets as u64),
        64,
    );

    Some(msg)
}

/// Encode a batch of DelayBasedBweUpdate events (delta-encoded).
fn encode_delay_bwe_batch(events: &[&DelayBasedBweUpdate]) -> Option<proto::DelayBasedBweUpdates> {
    let first = events.first()?;

    let mut msg = proto::DelayBasedBweUpdates {
        timestamp_ms: Some(first.timestamp_ms),
        bitrate_bps: Some(first.bitrate_bps),
        detector_state: Some(first.detector_state as i32),
        ..Default::default()
    };

    if events.len() <= 1 {
        return Some(msg);
    }

    let number_of_deltas = (events.len() - 1) as u32;
    msg.number_of_deltas = Some(number_of_deltas);

    let rest = &events[1..];

    set_deltas(
        &mut msg.timestamp_ms_deltas,
        Some(first.timestamp_ms as u64),
        &collect_required(rest, |e| e.timestamp_ms as u64),
        64,
    );
    set_deltas(
        &mut msg.bitrate_bps_deltas,
        Some(first.bitrate_bps as u64),
        &collect_required(rest, |e| e.bitrate_bps as u64),
        64,
    );
    set_deltas(
        &mut msg.detector_state_deltas,
        Some(first.detector_state as i32 as u64),
        &collect_required(rest, |e| e.detector_state as i32 as u64),
        64,
    );

    Some(msg)
}

/// Encode a ProbeClusterCreated event as a proto message (individually serialized).
fn encode_probe_cluster_created(e: &ProbeClusterCreated) -> proto::BweProbeCluster {
    proto::BweProbeCluster {
        timestamp_ms: Some(e.timestamp_ms),
        id: Some(e.id),
        bitrate_bps: Some(e.bitrate_bps),
        min_packets: Some(e.min_packets),
        min_bytes: None, // str0m doesn't track min_bytes
    }
}

/// Encode a ProbeClusterSuccess event as a proto message (individually serialized).
fn encode_probe_success(e: &ProbeClusterSuccess) -> proto::BweProbeResultSuccess {
    proto::BweProbeResultSuccess {
        timestamp_ms: Some(e.timestamp_ms),
        id: Some(e.id),
        bitrate_bps: Some(e.bitrate_bps),
    }
}

/// Encode a ProbeClusterFailure event as a proto message (individually serialized).
fn encode_probe_failure(e: &ProbeClusterFailure) -> proto::BweProbeResultFailure {
    proto::BweProbeResultFailure {
        timestamp_ms: Some(e.timestamp_ms),
        id: Some(e.id),
        failure: Some(e.failure_reason as i32),
    }
}

/// Encode an AlrStateEvent as a proto message (individually serialized).
fn encode_alr_state(e: &AlrStateEvent) -> proto::AlrState {
    proto::AlrState {
        timestamp_ms: Some(e.timestamp_ms),
        in_alr: Some(e.in_alr),
    }
}

fn encode_header_extensions(
    ext: &crate::events::RtpHeaderExtensionConfig,
) -> proto::RtpHeaderExtensionConfig {
    proto::RtpHeaderExtensionConfig {
        transmission_time_offset_id: ext.transmission_time_offset_id,
        absolute_send_time_id: ext.absolute_send_time_id,
        transport_sequence_number_id: ext.transport_sequence_number_id,
        video_rotation_id: ext.video_rotation_id,
        audio_level_id: ext.audio_level_id,
        dependency_descriptor_id: None,
    }
}

fn encode_audio_recv_stream_config(
    e: &AudioRecvStreamConfig,
) -> proto::AudioRecvStreamConfig {
    proto::AudioRecvStreamConfig {
        timestamp_ms: Some(e.timestamp_ms),
        remote_ssrc: Some(e.remote_ssrc),
        local_ssrc: Some(e.local_ssrc),
        header_extensions: Some(encode_header_extensions(&e.header_extensions)),
    }
}

fn encode_audio_send_stream_config(
    e: &AudioSendStreamConfig,
) -> proto::AudioSendStreamConfig {
    proto::AudioSendStreamConfig {
        timestamp_ms: Some(e.timestamp_ms),
        ssrc: Some(e.ssrc),
        header_extensions: Some(encode_header_extensions(&e.header_extensions)),
    }
}

fn encode_video_recv_stream_config(
    e: &VideoRecvStreamConfig,
) -> proto::VideoRecvStreamConfig {
    proto::VideoRecvStreamConfig {
        timestamp_ms: Some(e.timestamp_ms),
        remote_ssrc: Some(e.remote_ssrc),
        local_ssrc: Some(e.local_ssrc),
        rtx_ssrc: e.rtx_ssrc,
        header_extensions: Some(encode_header_extensions(&e.header_extensions)),
    }
}

fn encode_video_send_stream_config(
    e: &VideoSendStreamConfig,
) -> proto::VideoSendStreamConfig {
    proto::VideoSendStreamConfig {
        timestamp_ms: Some(e.timestamp_ms),
        ssrc: Some(e.ssrc),
        rtx_ssrc: e.rtx_ssrc,
        header_extensions: Some(encode_header_extensions(&e.header_extensions)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::OutgoingRtp;

    fn make_outgoing_rtp(ts: i64, seq: u32, ssrc: u32) -> OutgoingRtp {
        OutgoingRtp {
            timestamp_ms: ts,
            ssrc,
            sequence_number: seq,
            rtp_timestamp: (ts * 90) as u32, // 90kHz clock
            payload_type: 111,
            marker: false,
            payload_size: 1000,
            header_size: 12,
            padding_size: 0,
            transport_sequence_number: Some(seq),
            absolute_send_time: None,
            transmission_time_offset: None,
            audio_level: None,
            voice_activity: None,
            video_rotation: None,
            rtx_original_sequence_number: None,
            probe_cluster_id: None,
        }
    }

    #[test]
    fn encode_begin_end() {
        let encoder = RtcEventLogEncoder::new();
        let start = encoder.encode_log_start(1000, 1704067200000);
        let end = encoder.encode_log_end(5000);

        // Both should be valid protobuf
        let start_stream = proto::EventStream::decode(start.as_slice()).unwrap();
        assert_eq!(start_stream.begin_log_events.len(), 1);
        assert_eq!(start_stream.begin_log_events[0].version, Some(2));
        assert_eq!(start_stream.begin_log_events[0].timestamp_ms, Some(1000));

        let end_stream = proto::EventStream::decode(end.as_slice()).unwrap();
        assert_eq!(end_stream.end_log_events.len(), 1);
        assert_eq!(end_stream.end_log_events[0].timestamp_ms, Some(5000));
    }

    #[test]
    fn encode_single_rtp() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![RtcEvent::OutgoingRtp(make_outgoing_rtp(1000, 1, 0x12345678))];
        let data = encoder.encode_batch(&events);

        let stream = proto::EventStream::decode(data.as_slice()).unwrap();
        assert_eq!(stream.outgoing_rtp_packets.len(), 1);
        let msg = &stream.outgoing_rtp_packets[0];
        assert_eq!(msg.ssrc, Some(0x12345678));
        assert_eq!(msg.sequence_number, Some(1));
        assert!(msg.number_of_deltas.is_none());
    }

    #[test]
    fn encode_batch_same_ssrc() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::OutgoingRtp(make_outgoing_rtp(1000, 1, 0xAABBCCDD)),
            RtcEvent::OutgoingRtp(make_outgoing_rtp(1020, 2, 0xAABBCCDD)),
            RtcEvent::OutgoingRtp(make_outgoing_rtp(1040, 3, 0xAABBCCDD)),
        ];
        let data = encoder.encode_batch(&events);

        let stream = proto::EventStream::decode(data.as_slice()).unwrap();
        assert_eq!(stream.outgoing_rtp_packets.len(), 1);
        let msg = &stream.outgoing_rtp_packets[0];
        assert_eq!(msg.number_of_deltas, Some(2));
        assert!(msg.timestamp_ms_deltas.is_some());
        assert!(msg.sequence_number_deltas.is_some());
    }

    #[test]
    fn encode_batch_multiple_ssrc() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::OutgoingRtp(make_outgoing_rtp(1000, 1, 0x11111111)),
            RtcEvent::OutgoingRtp(make_outgoing_rtp(1010, 1, 0x22222222)),
            RtcEvent::OutgoingRtp(make_outgoing_rtp(1020, 2, 0x11111111)),
        ];
        let data = encoder.encode_batch(&events);

        let stream = proto::EventStream::decode(data.as_slice()).unwrap();
        // Two separate messages — one per SSRC
        assert_eq!(stream.outgoing_rtp_packets.len(), 2);
    }

    #[test]
    fn full_pipeline() {
        let encoder = RtcEventLogEncoder::new();
        let mut output = Vec::new();

        // BeginLog
        output.extend(encoder.encode_log_start(0, 1704067200000));

        // Batch of packets
        let events: Vec<RtcEvent> = (0..10)
            .map(|i| {
                RtcEvent::OutgoingRtp(make_outgoing_rtp(
                    1000 + i * 20,
                    i as u32 + 1,
                    0xDEADBEEF,
                ))
            })
            .collect();
        output.extend(encoder.encode_batch(&events));

        // EndLog
        output.extend(encoder.encode_log_end(2000));

        // The output should be parseable as concatenated EventStream messages
        assert!(!output.is_empty());
    }

    fn make_incoming_rtp(ts: i64, seq: u32, ssrc: u32) -> IncomingRtp {
        IncomingRtp {
            timestamp_ms: ts,
            ssrc,
            sequence_number: seq,
            rtp_timestamp: (ts * 90) as u32,
            payload_type: 111,
            marker: false,
            payload_size: 1000,
            header_size: 12,
            padding_size: 0,
            transport_sequence_number: Some(seq),
            absolute_send_time: None,
            transmission_time_offset: None,
            audio_level: None,
            voice_activity: None,
            video_rotation: None,
            rtx_original_sequence_number: None,
        }
    }

    #[test]
    fn encode_incoming_rtp_single() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![RtcEvent::IncomingRtp(make_incoming_rtp(1000, 1, 0x12345678))];
        let data = encoder.encode_batch(&events);

        let stream = proto::EventStream::decode(data.as_slice()).unwrap();
        assert_eq!(stream.incoming_rtp_packets.len(), 1);
        let msg = &stream.incoming_rtp_packets[0];
        assert_eq!(msg.ssrc, Some(0x12345678));
        assert_eq!(msg.sequence_number, Some(1));
        assert!(msg.number_of_deltas.is_none());
    }

    #[test]
    fn encode_incoming_rtp_batch() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::IncomingRtp(make_incoming_rtp(1000, 1, 0xAABBCCDD)),
            RtcEvent::IncomingRtp(make_incoming_rtp(1020, 2, 0xAABBCCDD)),
            RtcEvent::IncomingRtp(make_incoming_rtp(1040, 3, 0xAABBCCDD)),
        ];
        let data = encoder.encode_batch(&events);

        let stream = proto::EventStream::decode(data.as_slice()).unwrap();
        assert_eq!(stream.incoming_rtp_packets.len(), 1);
        let msg = &stream.incoming_rtp_packets[0];
        assert_eq!(msg.number_of_deltas, Some(2));
        assert!(msg.timestamp_ms_deltas.is_some());
        assert!(msg.sequence_number_deltas.is_some());
    }

    #[test]
    fn encode_incoming_rtcp_single() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![RtcEvent::IncomingRtcp(IncomingRtcp {
            timestamp_ms: 1000,
            raw_packet: vec![0x80, 200, 0, 1, 1, 2, 3, 4],
        })];
        let data = encoder.encode_batch(&events);

        let stream = proto::EventStream::decode(data.as_slice()).unwrap();
        assert_eq!(stream.incoming_rtcp_packets.len(), 1);
        let msg = &stream.incoming_rtcp_packets[0];
        assert_eq!(msg.timestamp_ms, Some(1000));
        assert_eq!(msg.raw_packet, Some(vec![0x80, 200, 0, 1, 1, 2, 3, 4]));
        assert!(msg.number_of_deltas.is_none());
    }

    #[test]
    fn encode_incoming_rtcp_batch_with_blobs() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::IncomingRtcp(IncomingRtcp {
                timestamp_ms: 1000,
                raw_packet: vec![0x80, 200, 0, 0],
            }),
            RtcEvent::IncomingRtcp(IncomingRtcp {
                timestamp_ms: 1100,
                raw_packet: vec![0x80, 201, 0, 1, 0, 0, 0, 0],
            }),
            RtcEvent::IncomingRtcp(IncomingRtcp {
                timestamp_ms: 1200,
                raw_packet: vec![0x80, 200, 0, 0],
            }),
        ];
        let data = encoder.encode_batch(&events);

        let stream = proto::EventStream::decode(data.as_slice()).unwrap();
        assert_eq!(stream.incoming_rtcp_packets.len(), 1);
        let msg = &stream.incoming_rtcp_packets[0];
        assert_eq!(msg.number_of_deltas, Some(2));
        assert!(msg.timestamp_ms_deltas.is_some());
        assert!(msg.raw_packet_blobs.is_some());
    }

    #[test]
    fn encode_outgoing_rtcp_batch() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::OutgoingRtcp(OutgoingRtcp {
                timestamp_ms: 1000,
                raw_packet: vec![0x80, 201, 0, 1, 0, 0, 0, 0],
            }),
            RtcEvent::OutgoingRtcp(OutgoingRtcp {
                timestamp_ms: 1100,
                raw_packet: vec![0x80, 201, 0, 1, 0, 0, 0, 0],
            }),
        ];
        let data = encoder.encode_batch(&events);

        let stream = proto::EventStream::decode(data.as_slice()).unwrap();
        assert_eq!(stream.outgoing_rtcp_packets.len(), 1);
        let msg = &stream.outgoing_rtcp_packets[0];
        assert_eq!(msg.number_of_deltas, Some(1));
    }

    #[test]
    fn encode_mixed_rtp_and_rtcp() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::OutgoingRtp(make_outgoing_rtp(1000, 1, 0x11111111)),
            RtcEvent::IncomingRtp(make_incoming_rtp(1010, 1, 0x22222222)),
            RtcEvent::IncomingRtcp(IncomingRtcp {
                timestamp_ms: 1020,
                raw_packet: vec![0x80, 200, 0, 0],
            }),
            RtcEvent::OutgoingRtcp(OutgoingRtcp {
                timestamp_ms: 1030,
                raw_packet: vec![0x80, 201, 0, 0],
            }),
        ];
        let data = encoder.encode_batch(&events);

        let stream = proto::EventStream::decode(data.as_slice()).unwrap();
        assert_eq!(stream.outgoing_rtp_packets.len(), 1);
        assert_eq!(stream.incoming_rtp_packets.len(), 1);
        assert_eq!(stream.incoming_rtcp_packets.len(), 1);
        assert_eq!(stream.outgoing_rtcp_packets.len(), 1);
    }

    #[test]
    fn encode_rtcp_keeps_event_when_filtered_empty() {
        let encoder = RtcEventLogEncoder::new();
        // SDES-only packet: filtered output should be empty, but event must remain.
        let events = vec![RtcEvent::IncomingRtcp(IncomingRtcp {
            timestamp_ms: 1000,
            raw_packet: vec![0x80, 202, 0, 0],
        })];

        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        assert_eq!(stream.incoming_rtcp_packets.len(), 1);
        let msg = &stream.incoming_rtcp_packets[0];
        assert_eq!(msg.timestamp_ms, Some(1000));
        assert_eq!(msg.raw_packet, Some(Vec::new()));
    }

    #[test]
    fn encode_delay_bwe_updates() {
        use crate::events::DetectorState;

        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::DelayBasedBweUpdate(DelayBasedBweUpdate {
                timestamp_ms: 1000,
                bitrate_bps: 500_000,
                detector_state: DetectorState::Normal,
            }),
            RtcEvent::DelayBasedBweUpdate(DelayBasedBweUpdate {
                timestamp_ms: 1500,
                bitrate_bps: 600_000,
                detector_state: DetectorState::Overusing,
            }),
        ];
        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        assert_eq!(stream.delay_based_bwe_updates.len(), 1);
        let msg = &stream.delay_based_bwe_updates[0];
        assert_eq!(msg.timestamp_ms, Some(1000));
        assert_eq!(msg.bitrate_bps, Some(500_000));
        assert_eq!(msg.detector_state, Some(1)); // BWE_NORMAL
        assert_eq!(msg.number_of_deltas, Some(1));
    }

    #[test]
    fn encode_loss_bwe_updates() {
        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::LossBasedBweUpdate(LossBasedBweUpdate {
                timestamp_ms: 2000,
                bitrate_bps: 400_000,
                fraction_loss: 25,
                total_packets: 100,
            }),
        ];
        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        assert_eq!(stream.loss_based_bwe_updates.len(), 1);
        let msg = &stream.loss_based_bwe_updates[0];
        assert_eq!(msg.timestamp_ms, Some(2000));
        assert_eq!(msg.bitrate_bps, Some(400_000));
        assert_eq!(msg.fraction_loss, Some(25));
        assert_eq!(msg.total_packets, Some(100));
    }

    #[test]
    fn encode_probe_events() {
        use crate::events::{ProbeClusterCreated, ProbeClusterSuccess, ProbeClusterFailure, ProbeFailureReason};

        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::ProbeClusterCreated(ProbeClusterCreated {
                timestamp_ms: 3000,
                id: 1,
                bitrate_bps: 1_000_000,
                min_packets: 5,
            }),
            RtcEvent::ProbeClusterSuccess(ProbeClusterSuccess {
                timestamp_ms: 3100,
                id: 1,
                bitrate_bps: 950_000,
            }),
            RtcEvent::ProbeClusterFailure(ProbeClusterFailure {
                timestamp_ms: 3200,
                id: 2,
                failure_reason: ProbeFailureReason::InvalidSendReceiveRatio,
            }),
        ];
        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        assert_eq!(stream.probe_clusters.len(), 1);
        let msg = &stream.probe_clusters[0];
        assert_eq!(msg.id, Some(1));
        assert_eq!(msg.bitrate_bps, Some(1_000_000));
        assert_eq!(msg.min_packets, Some(5));
        assert_eq!(msg.min_bytes, None);

        assert_eq!(stream.probe_success.len(), 1);
        let msg = &stream.probe_success[0];
        assert_eq!(msg.id, Some(1));
        assert_eq!(msg.bitrate_bps, Some(950_000));

        assert_eq!(stream.probe_failure.len(), 1);
        let msg = &stream.probe_failure[0];
        assert_eq!(msg.id, Some(2));
        assert_eq!(msg.failure, Some(2)); // INVALID_SEND_RECEIVE_RATIO
    }

    #[test]
    fn encode_alr_state() {
        use crate::events::AlrStateEvent;

        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::AlrStateEvent(AlrStateEvent {
                timestamp_ms: 4000,
                in_alr: true,
            }),
            RtcEvent::AlrStateEvent(AlrStateEvent {
                timestamp_ms: 5000,
                in_alr: false,
            }),
        ];
        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        assert_eq!(stream.alr_states.len(), 2);
        assert_eq!(stream.alr_states[0].in_alr, Some(true));
        assert_eq!(stream.alr_states[1].in_alr, Some(false));
    }

    #[test]
    fn encode_probe_cluster_id_zero_in_rtp_batch() {
        // Verify that probe_cluster_id=0 is correctly encoded in a batch
        // where the base is None (first packet has no probe) and some
        // subsequent packets have cluster_id=0 via delta encoding.
        let encoder = RtcEventLogEncoder::new();

        let ssrc = 0xAABBCCDD;
        let mut events = Vec::new();

        // 3 packets without probe_cluster_id, then 3 with cluster_id=0
        for i in 0..6u32 {
            let mut rtp = make_outgoing_rtp(1000 + i as i64, i + 1, ssrc);
            if i >= 3 {
                rtp.probe_cluster_id = Some(0);
            }
            events.push(RtcEvent::OutgoingRtp(rtp));
        }

        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        assert_eq!(stream.outgoing_rtp_packets.len(), 1);
        let msg = &stream.outgoing_rtp_packets[0];

        // Base probe_cluster_id should be None (first packet has no probe)
        assert_eq!(msg.probe_cluster_id, None,
            "base probe_cluster_id should be None for first non-probe packet");

        // Deltas should exist because some packets have probe_cluster_id
        assert!(msg.probe_cluster_id_deltas.is_some(),
            "probe_cluster_id_deltas should be present when packets have mixed cluster ids");

        // number_of_deltas should be 5 (6 packets total, 5 deltas)
        assert_eq!(msg.number_of_deltas, Some(5));
    }

    #[test]
    fn encode_probe_cluster_id_base_zero() {
        // Verify that probe_cluster_id=0 as the BASE field is correctly
        // round-tripped: it should be Some(0), not None.
        let encoder = RtcEventLogEncoder::new();

        let ssrc = 0x11223344;
        let mut events = Vec::new();

        // All packets have cluster_id=0
        for i in 0..5u32 {
            let mut rtp = make_outgoing_rtp(1000 + i as i64, i + 1, ssrc);
            rtp.probe_cluster_id = Some(0);
            events.push(RtcEvent::OutgoingRtp(rtp));
        }

        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        assert_eq!(stream.outgoing_rtp_packets.len(), 1);
        let msg = &stream.outgoing_rtp_packets[0];

        // Base probe_cluster_id should be Some(0), NOT None!
        // This is critical: protobuf2 should distinguish "not set" from "set to 0"
        assert_eq!(msg.probe_cluster_id, Some(0),
            "probe_cluster_id=0 must be explicitly set, not confused with absence");

        // All identical to base → no deltas needed
        assert!(msg.probe_cluster_id_deltas.is_none(),
            "all-same cluster_id should produce no deltas");
    }

    #[test]
    fn encode_probe_cluster_id_mixed_clusters_in_batch() {
        // Verify that a single SSRC batch containing packets from multiple
        // probe clusters (e.g., 0 and 1) correctly delta-encodes both IDs.
        let encoder = RtcEventLogEncoder::new();

        let ssrc = 0xDEADBEEF;
        let mut events = Vec::new();

        // 2 non-probe packets, 3 from cluster 0, 3 from cluster 1
        for i in 0..8u32 {
            let mut rtp = make_outgoing_rtp(1000 + i as i64, i + 1, ssrc);
            rtp.probe_cluster_id = match i {
                0..=1 => None,
                2..=4 => Some(0),
                _ => Some(1),
            };
            events.push(RtcEvent::OutgoingRtp(rtp));
        }

        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        assert_eq!(stream.outgoing_rtp_packets.len(), 1);
        let msg = &stream.outgoing_rtp_packets[0];

        // Base is None (first packet has no cluster)
        assert_eq!(msg.probe_cluster_id, None);
        // Deltas must exist because subsequent packets have cluster IDs
        assert!(msg.probe_cluster_id_deltas.is_some(),
            "deltas must be present for mixed None/0/1 values");
        assert_eq!(msg.number_of_deltas, Some(7));
    }

    #[test]
    fn encode_probe_cluster_id_nonzero_base() {
        // Verify that probe_cluster_id > 0 as base works correctly.
        let encoder = RtcEventLogEncoder::new();

        let ssrc = 0xCAFEBABE;
        let mut events = Vec::new();

        // All packets belong to cluster 5
        for i in 0..4u32 {
            let mut rtp = make_outgoing_rtp(1000 + i as i64, i + 1, ssrc);
            rtp.probe_cluster_id = Some(5);
            events.push(RtcEvent::OutgoingRtp(rtp));
        }

        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        assert_eq!(stream.outgoing_rtp_packets.len(), 1);
        let msg = &stream.outgoing_rtp_packets[0];

        assert_eq!(msg.probe_cluster_id, Some(5));
        // All identical to base → no deltas
        assert!(msg.probe_cluster_id_deltas.is_none());
    }

    #[test]
    fn encode_probe_cluster_id_two_ssrcs_different_clusters() {
        // Verify that two SSRCs with different probe cluster IDs produce
        // separate RTP batch messages, each with the correct base.
        let encoder = RtcEventLogEncoder::new();

        let ssrc_main = 0x11111111;
        let ssrc_rtx  = 0x22222222;
        let mut events = Vec::new();

        // Main SSRC: no probe
        for i in 0..3u32 {
            events.push(RtcEvent::OutgoingRtp(make_outgoing_rtp(1000 + i as i64, i + 1, ssrc_main)));
        }
        // RTX SSRC: all cluster 0 (probe padding)
        for i in 0..3u32 {
            let mut rtp = make_outgoing_rtp(1000 + i as i64, 100 + i + 1, ssrc_rtx);
            rtp.probe_cluster_id = Some(0);
            events.push(RtcEvent::OutgoingRtp(rtp));
        }

        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        // BTreeMap ordering: ssrc_main (0x11111111) before ssrc_rtx (0x22222222)
        assert_eq!(stream.outgoing_rtp_packets.len(), 2);

        let main_msg = &stream.outgoing_rtp_packets[0];
        assert_eq!(main_msg.ssrc, Some(ssrc_main));
        assert_eq!(main_msg.probe_cluster_id, None,
            "main SSRC should have no probe_cluster_id");

        let rtx_msg = &stream.outgoing_rtp_packets[1];
        assert_eq!(rtx_msg.ssrc, Some(ssrc_rtx));
        assert_eq!(rtx_msg.probe_cluster_id, Some(0),
            "RTX SSRC probe padding should have cluster_id=0");
    }

    #[test]
    fn encode_probe_events_with_id_zero() {
        // Verify ProbeClusterCreated/Success/Failure events with id=0 encode correctly.
        use crate::events::{ProbeClusterCreated, ProbeClusterSuccess, ProbeClusterFailure, ProbeFailureReason};

        let encoder = RtcEventLogEncoder::new();
        let events = vec![
            RtcEvent::ProbeClusterCreated(ProbeClusterCreated {
                timestamp_ms: 3000,
                id: 0,
                bitrate_bps: 1_500_000,
                min_packets: 5,
            }),
            RtcEvent::ProbeClusterSuccess(ProbeClusterSuccess {
                timestamp_ms: 3050,
                id: 0,
                bitrate_bps: 1_400_000,
            }),
            RtcEvent::ProbeClusterCreated(ProbeClusterCreated {
                timestamp_ms: 3060,
                id: 1,
                bitrate_bps: 3_000_000,
                min_packets: 5,
            }),
            RtcEvent::ProbeClusterFailure(ProbeClusterFailure {
                timestamp_ms: 3200,
                id: 1,
                failure_reason: ProbeFailureReason::Timeout,
            }),
        ];
        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        // Two created probes
        assert_eq!(stream.probe_clusters.len(), 2);
        assert_eq!(stream.probe_clusters[0].id, Some(0));
        assert_eq!(stream.probe_clusters[0].bitrate_bps, Some(1_500_000));
        assert_eq!(stream.probe_clusters[1].id, Some(1));

        // One success for id=0
        assert_eq!(stream.probe_success.len(), 1);
        assert_eq!(stream.probe_success[0].id, Some(0));
        assert_eq!(stream.probe_success[0].bitrate_bps, Some(1_400_000));

        // One failure for id=1
        assert_eq!(stream.probe_failure.len(), 1);
        assert_eq!(stream.probe_failure[0].id, Some(1));
        assert_eq!(stream.probe_failure[0].failure, Some(3)); // TIMEOUT
    }

    #[test]
    fn encode_stream_config_events() {
        use crate::events::{
            AudioRecvStreamConfig, AudioSendStreamConfig, RtpHeaderExtensionConfig,
            VideoRecvStreamConfig, VideoSendStreamConfig,
        };

        let encoder = RtcEventLogEncoder::new();

        let ext_config = RtpHeaderExtensionConfig {
            transmission_time_offset_id: Some(14),
            absolute_send_time_id: Some(2),
            transport_sequence_number_id: Some(3),
            video_rotation_id: Some(13),
            audio_level_id: Some(1),
        };

        let events = vec![
            RtcEvent::VideoSendStreamConfig(VideoSendStreamConfig {
                timestamp_ms: 1000,
                ssrc: 1111,
                rtx_ssrc: Some(2222),
                header_extensions: RtpHeaderExtensionConfig {
                    transmission_time_offset_id: Some(14),
                    absolute_send_time_id: Some(2),
                    transport_sequence_number_id: Some(3),
                    video_rotation_id: Some(13),
                    audio_level_id: None,
                },
            }),
            RtcEvent::VideoRecvStreamConfig(VideoRecvStreamConfig {
                timestamp_ms: 1000,
                remote_ssrc: 3333,
                local_ssrc: 4444,
                rtx_ssrc: Some(5555),
                header_extensions: RtpHeaderExtensionConfig {
                    transmission_time_offset_id: Some(14),
                    absolute_send_time_id: Some(2),
                    transport_sequence_number_id: Some(3),
                    video_rotation_id: Some(13),
                    audio_level_id: None,
                },
            }),
            RtcEvent::AudioSendStreamConfig(AudioSendStreamConfig {
                timestamp_ms: 1000,
                ssrc: 6666,
                header_extensions: ext_config,
            }),
            RtcEvent::AudioRecvStreamConfig(AudioRecvStreamConfig {
                timestamp_ms: 1000,
                remote_ssrc: 7777,
                local_ssrc: 8888,
                header_extensions: RtpHeaderExtensionConfig {
                    transmission_time_offset_id: None,
                    absolute_send_time_id: Some(2),
                    transport_sequence_number_id: Some(3),
                    video_rotation_id: None,
                    audio_level_id: Some(1),
                },
            }),
        ];

        let data = encoder.encode_batch(&events);
        let stream = proto::EventStream::decode(data.as_slice()).unwrap();

        // Video send config
        assert_eq!(stream.video_send_stream_configs.len(), 1);
        let vsc = &stream.video_send_stream_configs[0];
        assert_eq!(vsc.timestamp_ms, Some(1000));
        assert_eq!(vsc.ssrc, Some(1111));
        assert_eq!(vsc.rtx_ssrc, Some(2222));
        let ext = vsc.header_extensions.as_ref().unwrap();
        assert_eq!(ext.transport_sequence_number_id, Some(3));
        assert_eq!(ext.video_rotation_id, Some(13));
        assert_eq!(ext.audio_level_id, None);

        // Video recv config
        assert_eq!(stream.video_recv_stream_configs.len(), 1);
        let vrc = &stream.video_recv_stream_configs[0];
        assert_eq!(vrc.remote_ssrc, Some(3333));
        assert_eq!(vrc.local_ssrc, Some(4444));
        assert_eq!(vrc.rtx_ssrc, Some(5555));

        // Audio send config
        assert_eq!(stream.audio_send_stream_configs.len(), 1);
        let asc = &stream.audio_send_stream_configs[0];
        assert_eq!(asc.ssrc, Some(6666));
        let ext = asc.header_extensions.as_ref().unwrap();
        assert_eq!(ext.audio_level_id, Some(1));
        assert_eq!(ext.absolute_send_time_id, Some(2));

        // Audio recv config
        assert_eq!(stream.audio_recv_stream_configs.len(), 1);
        let arc = &stream.audio_recv_stream_configs[0];
        assert_eq!(arc.remote_ssrc, Some(7777));
        assert_eq!(arc.local_ssrc, Some(8888));
        let ext = arc.header_extensions.as_ref().unwrap();
        assert_eq!(ext.audio_level_id, Some(1));
        assert_eq!(ext.video_rotation_id, None);
    }
}
