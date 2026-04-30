use std::collections::VecDeque;
use std::time::{Duration, Instant};

use str0m_rtc_event_log::encoder::RtcEventLogEncoder;
use str0m_rtc_event_log::events::{
    AlrStateEvent, AudioRecvStreamConfig, AudioSendStreamConfig, DelayBasedBweUpdate,
    IncomingRtcp, IncomingRtp, LossBasedBweUpdate, OutgoingRtcp, OutgoingRtp,
    ProbeClusterCreated, ProbeClusterFailure, ProbeClusterSuccess, RtcEvent,
    RtpHeaderExtensionConfig, VideoRecvStreamConfig, VideoSendStreamConfig,
};

use crate::bwe_::{BandwidthUsage, ProbeFailureReason as BweProbeFailureReason};
use crate::rtp_::{Extension, ExtensionMap, RtpHeader};
use crate::util::InstantExt;

/// Default flush interval for event log batches.
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum events before forcing a flush (safety measure against unbounded growth).
const MAX_EVENTS: usize = 10_000;

/// Collects RTC events and serializes them on a flush interval.
///
/// Events are recorded via cheap `Vec::push()` calls during packet processing.
/// Serialization happens when `flush()` is called by the timeout system.
///
/// The `BeginLogEvent` is serialized eagerly at construction time and pushed
/// to `pending_output` immediately, guaranteeing it is always the first bytes
/// returned by `poll()`.
pub(crate) struct RtcEventLogCollector {
    /// Buffered events waiting to be encoded.
    events: Vec<RtcEvent>,

    /// Interval between flushes.
    flush_interval: Duration,

    /// Instant of next scheduled flush.
    next_flush: Instant,

    /// The encoder (stateless — delta chains reset per batch).
    encoder: RtcEventLogEncoder,

    /// Serialized bytes ready to be delivered via poll_output().
    pending_output: VecDeque<Vec<u8>>,

    /// Whether stop was requested and EndLogEvent has already been queued.
    stopped: bool,
}

impl RtcEventLogCollector {
    /// Create a new collector.
    ///
    /// The `BeginLogEvent` (with version=2 and UTC wall-clock time) is serialized
    /// immediately and queued in `pending_output`. The first call to `poll()`
    /// will return these bytes.
    pub fn new(now: Instant, flush_interval: Duration) -> Self {
        let encoder = RtcEventLogEncoder::new();
        let timestamp_ms = to_timestamp_ms(now);
        let utc_time_ms = timestamp_ms;

        let begin_data = encoder.encode_log_start(timestamp_ms, utc_time_ms);

        let mut pending_output = VecDeque::new();
        pending_output.push_back(begin_data);

        RtcEventLogCollector {
            events: Vec::with_capacity(256),
            flush_interval,
            next_flush: now + flush_interval,
            encoder,
            pending_output,
            stopped: false,
        }
    }

    /// Create with default flush interval (2 seconds).
    pub fn with_defaults(now: Instant) -> Self {
        Self::new(now, DEFAULT_FLUSH_INTERVAL)
    }

    /// Record an outgoing RTP packet.
    ///
    /// Captures header fields and sizes. This is a cheap `Vec::push()`.
    pub fn record_outgoing_rtp(
        &mut self,
        now: Instant,
        header: &RtpHeader,
        payload_size: usize,
        cluster_id: Option<i32>,
        rtx_osn: Option<u16>,
    ) {
        if self.stopped {
            return;
        }

        let event = OutgoingRtp {
            timestamp_ms: to_timestamp_ms(now),
            ssrc: *header.ssrc,
            sequence_number: header.sequence_number as u32,
            rtp_timestamp: header.timestamp,
            payload_type: *header.payload_type as u32,
            marker: header.marker,
            payload_size: payload_size as u32,
            header_size: header.header_len as u32,
            padding_size: 0,
            transport_sequence_number: header.ext_vals.transport_cc.map(|v| v as u32),
            // str0m decodes abs_send_time into an Instant, discarding the raw 24-bit
            // fixed-point u32. Re-encoding would be a lossy round-trip, so we omit it.
            absolute_send_time: None,
            transmission_time_offset: header.ext_vals.tx_time_offs,
            audio_level: header.ext_vals.audio_level.map(|v| (-v) as u8 as u32),
            voice_activity: header.ext_vals.voice_activity,
            video_rotation: header
                .ext_vals
                .video_orientation
                .map(|v| v as u32),
            rtx_original_sequence_number: rtx_osn.map(|v| v as u32),
            probe_cluster_id: cluster_id,
        };

        self.events.push(RtcEvent::OutgoingRtp(event));
    }

    /// Record an incoming RTP packet.
    ///
    /// Called from `handle_rtp()` after SRTP decrypt, before un_rtx.
    /// `padding_size` is read from the last byte of the decrypted payload
    /// before unpadding. `rtx_osn` is the original sequence number extracted
    /// from the first 2 bytes of RTX payloads.
    pub fn record_incoming_rtp(
        &mut self,
        now: Instant,
        header: &RtpHeader,
        payload_size: usize,
        padding_size: usize,
        rtx_osn: Option<u16>,
    ) {
        if self.stopped {
            return;
        }

        let event = IncomingRtp {
            timestamp_ms: to_timestamp_ms(now),
            ssrc: *header.ssrc,
            sequence_number: header.sequence_number as u32,
            rtp_timestamp: header.timestamp,
            payload_type: *header.payload_type as u32,
            marker: header.marker,
            payload_size: payload_size as u32,
            header_size: header.header_len as u32,
            padding_size: padding_size as u32,
            transport_sequence_number: header.ext_vals.transport_cc.map(|v| v as u32),
            // str0m decodes abs_send_time into an Instant, discarding the raw 24-bit
            // fixed-point u32. Re-encoding would be a lossy round-trip, so we omit it.
            absolute_send_time: None,
            transmission_time_offset: header.ext_vals.tx_time_offs,
            audio_level: header.ext_vals.audio_level.map(|v| (-v) as u8 as u32),
            voice_activity: header.ext_vals.voice_activity,
            video_rotation: header.ext_vals.video_orientation.map(|v| v as u32),
            rtx_original_sequence_number: rtx_osn.map(|v| v as u32),
        };

        self.events.push(RtcEvent::IncomingRtp(event));
    }

    /// Record an incoming RTCP packet (after SRTP decrypt).
    ///
    /// Raw bytes are stored as-is and filtered at encode-time (WebRTC parity).
    pub fn record_incoming_rtcp(&mut self, now: Instant, raw: &[u8]) {
        if self.stopped {
            return;
        }
        let event = IncomingRtcp {
            timestamp_ms: to_timestamp_ms(now),
            raw_packet: raw.to_vec(),
        };
        self.events.push(RtcEvent::IncomingRtcp(event));
    }

    /// Record an outgoing RTCP packet (before SRTP protect).
    ///
    /// Raw bytes are stored as-is and filtered at encode-time (WebRTC parity).
    pub fn record_outgoing_rtcp(&mut self, now: Instant, raw: &[u8]) {
        if self.stopped {
            return;
        }
        let event = OutgoingRtcp {
            timestamp_ms: to_timestamp_ms(now),
            raw_packet: raw.to_vec(),
        };
        self.events.push(RtcEvent::OutgoingRtcp(event));
    }

    /// Record a delay-based BWE update.
    pub fn record_delay_based_bwe(
        &mut self,
        now: Instant,
        bitrate_bps: u32,
        detector_state: BandwidthUsage,
    ) {
        if self.stopped {
            return;
        }
        let state = match detector_state {
            BandwidthUsage::Normal => str0m_rtc_event_log::events::DetectorState::Normal,
            BandwidthUsage::Underuse => str0m_rtc_event_log::events::DetectorState::Underusing,
            BandwidthUsage::Overuse => str0m_rtc_event_log::events::DetectorState::Overusing,
        };
        self.events
            .push(RtcEvent::DelayBasedBweUpdate(DelayBasedBweUpdate {
                timestamp_ms: to_timestamp_ms(now),
                bitrate_bps,
                detector_state: state,
            }));
    }

    /// Record a loss-based BWE update.
    pub fn record_loss_based_bwe(
        &mut self,
        now: Instant,
        bitrate_bps: u32,
        fraction_loss: u32,
        total_packets: u32,
    ) {
        if self.stopped {
            return;
        }
        self.events
            .push(RtcEvent::LossBasedBweUpdate(LossBasedBweUpdate {
                timestamp_ms: to_timestamp_ms(now),
                bitrate_bps,
                fraction_loss,
                total_packets,
            }));
    }

    /// Record a probe cluster being created (bandwidth probe started).
    pub fn record_probe_cluster_created(
        &mut self,
        now: Instant,
        id: u32,
        bitrate_bps: u32,
        min_packets: u32,
    ) {
        if self.stopped {
            return;
        }
        self.events
            .push(RtcEvent::ProbeClusterCreated(ProbeClusterCreated {
                timestamp_ms: to_timestamp_ms(now),
                id,
                bitrate_bps,
                min_packets,
            }));
    }

    /// Record a successful probe cluster result.
    pub fn record_probe_cluster_success(
        &mut self,
        now: Instant,
        id: u32,
        bitrate_bps: u32,
    ) {
        if self.stopped {
            return;
        }
        self.events
            .push(RtcEvent::ProbeClusterSuccess(ProbeClusterSuccess {
                timestamp_ms: to_timestamp_ms(now),
                id,
                bitrate_bps,
            }));
    }

    /// Record a failed probe cluster result.
    pub fn record_probe_cluster_failure(
        &mut self,
        now: Instant,
        id: u32,
        reason: BweProbeFailureReason,
    ) {
        if self.stopped {
            return;
        }
        let failure_reason = match reason {
            BweProbeFailureReason::InvalidSendReceiveInterval => {
                str0m_rtc_event_log::events::ProbeFailureReason::InvalidSendReceiveInterval
            }
            BweProbeFailureReason::InvalidSendReceiveRatio => {
                str0m_rtc_event_log::events::ProbeFailureReason::InvalidSendReceiveRatio
            }
            BweProbeFailureReason::Timeout => {
                str0m_rtc_event_log::events::ProbeFailureReason::Timeout
            }
        };
        self.events
            .push(RtcEvent::ProbeClusterFailure(ProbeClusterFailure {
                timestamp_ms: to_timestamp_ms(now),
                id,
                failure_reason,
            }));
    }

    /// Record an ALR state change.
    pub fn record_alr_state(&mut self, now: Instant, in_alr: bool) {
        if self.stopped {
            return;
        }
        self.events
            .push(RtcEvent::AlrStateEvent(AlrStateEvent {
                timestamp_ms: to_timestamp_ms(now),
                in_alr,
            }));
    }

    /// Record a video receive stream configuration.
    pub fn record_video_recv_stream_config(
        &mut self,
        now: Instant,
        remote_ssrc: u32,
        local_ssrc: u32,
        rtx_ssrc: Option<u32>,
        exts: &ExtensionMap,
    ) {
        if self.stopped {
            return;
        }
        self.events
            .push(RtcEvent::VideoRecvStreamConfig(VideoRecvStreamConfig {
                timestamp_ms: to_timestamp_ms(now),
                remote_ssrc,
                local_ssrc,
                rtx_ssrc,
                header_extensions: ext_config_from_map(exts),
            }));
    }

    /// Record a video send stream configuration.
    pub fn record_video_send_stream_config(
        &mut self,
        now: Instant,
        ssrc: u32,
        rtx_ssrc: Option<u32>,
        exts: &ExtensionMap,
    ) {
        if self.stopped {
            return;
        }
        self.events
            .push(RtcEvent::VideoSendStreamConfig(VideoSendStreamConfig {
                timestamp_ms: to_timestamp_ms(now),
                ssrc,
                rtx_ssrc,
                header_extensions: ext_config_from_map(exts),
            }));
    }

    /// Record an audio receive stream configuration.
    pub fn record_audio_recv_stream_config(
        &mut self,
        now: Instant,
        remote_ssrc: u32,
        local_ssrc: u32,
        exts: &ExtensionMap,
    ) {
        if self.stopped {
            return;
        }
        self.events
            .push(RtcEvent::AudioRecvStreamConfig(AudioRecvStreamConfig {
                timestamp_ms: to_timestamp_ms(now),
                remote_ssrc,
                local_ssrc,
                header_extensions: ext_config_from_map(exts),
            }));
    }

    /// Record an audio send stream configuration.
    pub fn record_audio_send_stream_config(
        &mut self,
        now: Instant,
        ssrc: u32,
        exts: &ExtensionMap,
    ) {
        if self.stopped {
            return;
        }
        self.events
            .push(RtcEvent::AudioSendStreamConfig(AudioSendStreamConfig {
                timestamp_ms: to_timestamp_ms(now),
                ssrc,
                header_extensions: ext_config_from_map(exts),
            }));
    }

    /// Returns the next time a flush should happen.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.events.is_empty() && self.pending_output.is_empty() {
            None
        } else {
            Some(self.next_flush)
        }
    }

    /// Flush buffered events if the interval has elapsed or buffer is full.
    pub fn flush(&mut self, now: Instant) {
        if self.stopped {
            return;
        }

        if now >= self.next_flush || self.events.len() >= MAX_EVENTS {
            if !self.events.is_empty() {
                let data = self.encoder.encode_batch(&self.events);
                self.pending_output.push_back(data);
                self.events.clear();
            }
            self.next_flush = now + self.flush_interval;
        }
    }

    /// Drain the next chunk of serialized bytes for delivery.
    pub fn poll(&mut self) -> Option<Vec<u8>> {
        self.pending_output.pop_front()
    }

    /// Flush all remaining events and produce the EndLogEvent.
    pub fn finish(&mut self, now: Instant) {
        if self.stopped {
            return;
        }

        // Flush remaining events
        if !self.events.is_empty() {
            let data = self.encoder.encode_batch(&self.events);
            self.pending_output.push_back(data);
            self.events.clear();
        }

        // Produce EndLogEvent
        let end_data = self.encoder.encode_log_end(to_timestamp_ms(now));
        self.pending_output.push_back(end_data);
        self.stopped = true;
    }
}

/// Convert an Instant to absolute wall-clock timestamp_ms.
/// Uses str0m's `InstantExt::to_unix_duration()`.
fn to_timestamp_ms(instant: Instant) -> i64 {
    instant.to_unix_duration().as_millis() as i64
}

/// Build an `RtpHeaderExtensionConfig` from an `ExtensionMap`.
///
/// Looks up the IDs of the extensions relevant for BWE analysis.
fn ext_config_from_map(exts: &ExtensionMap) -> RtpHeaderExtensionConfig {
    RtpHeaderExtensionConfig {
        transmission_time_offset_id: exts
            .id_of(Extension::TransmissionTimeOffset)
            .map(|id| id as i32),
        absolute_send_time_id: exts
            .id_of(Extension::AbsoluteSendTime)
            .map(|id| id as i32),
        transport_sequence_number_id: exts
            .id_of(Extension::TransportSequenceNumber)
            .map(|id| id as i32),
        video_rotation_id: exts
            .id_of(Extension::VideoOrientation)
            .map(|id| id as i32),
        audio_level_id: exts.id_of(Extension::AudioLevel).map(|id| id as i32),
    }
}
