/// A single RTC event ready for encoding.
///
/// Each variant maps directly to a protobuf message in rtc_event_log2.proto.
/// Events carry only metadata — never media payloads.
pub enum RtcEvent {
    /// Log session started. Must be the first event.
    BeginLog(BeginLog),
    /// Log session ended. Must be the last event.
    EndLog(EndLog),
    /// An RTP packet received from the network.
    IncomingRtp(IncomingRtp),
    /// An RTP packet sent to the network.
    OutgoingRtp(OutgoingRtp),
    /// An RTCP packet received from the network.
    ///
    /// SDES/APP filtering is applied at encode-time.
    IncomingRtcp(IncomingRtcp),
    /// An RTCP packet sent to the network.
    ///
    /// SDES/APP filtering is applied at encode-time.
    OutgoingRtcp(OutgoingRtcp),
    /// Loss-based BWE update.
    LossBasedBweUpdate(LossBasedBweUpdate),
    /// Delay-based BWE update.
    DelayBasedBweUpdate(DelayBasedBweUpdate),
    /// Probe cluster created (starting a bandwidth probe).
    ProbeClusterCreated(ProbeClusterCreated),
    /// Probe cluster completed successfully.
    ProbeClusterSuccess(ProbeClusterSuccess),
    /// Probe cluster failed.
    ProbeClusterFailure(ProbeClusterFailure),
    /// ALR (Application Limited Region) state change.
    AlrStateEvent(AlrStateEvent),
    /// Audio receive stream configuration.
    AudioRecvStreamConfig(AudioRecvStreamConfig),
    /// Audio send stream configuration.
    AudioSendStreamConfig(AudioSendStreamConfig),
    /// Video receive stream configuration.
    VideoRecvStreamConfig(VideoRecvStreamConfig),
    /// Video send stream configuration.
    VideoSendStreamConfig(VideoSendStreamConfig),
}

pub struct BeginLog {
    pub timestamp_ms: i64,
    pub utc_time_ms: i64,
}

pub struct EndLog {
    pub timestamp_ms: i64,
}

/// Logged outgoing RTP packet (no payload).
pub struct OutgoingRtp {
    pub timestamp_ms: i64,
    pub ssrc: u32,
    pub sequence_number: u32,
    pub rtp_timestamp: u32,
    pub payload_type: u32,
    pub marker: bool,
    pub payload_size: u32,
    pub header_size: u32,
    pub padding_size: u32,
    pub transport_sequence_number: Option<u32>,
    pub absolute_send_time: Option<u32>,
    /// Signed 24-bit value, stored as u32 via reinterpret (i32 as u32).
    pub transmission_time_offset: Option<u32>,
    pub audio_level: Option<u32>,
    pub voice_activity: Option<bool>,
    pub video_rotation: Option<u32>,
    pub rtx_original_sequence_number: Option<u32>,
    /// Which probe cluster this packet belongs to, if any.
    pub probe_cluster_id: Option<i32>,
}

/// Logged incoming RTP packet (no payload).
pub struct IncomingRtp {
    pub timestamp_ms: i64,
    pub ssrc: u32,
    pub sequence_number: u32,
    pub rtp_timestamp: u32,
    pub payload_type: u32,
    pub marker: bool,
    pub payload_size: u32,
    pub header_size: u32,
    pub padding_size: u32,
    pub transport_sequence_number: Option<u32>,
    pub absolute_send_time: Option<u32>,
    /// Signed 24-bit value, stored as u32 via reinterpret (i32 as u32).
    pub transmission_time_offset: Option<u32>,
    pub audio_level: Option<u32>,
    pub voice_activity: Option<bool>,
    pub video_rotation: Option<u32>,
    pub rtx_original_sequence_number: Option<u32>,
}

/// Logged RTCP packet (raw bytes as observed on the wire).
///
/// SDES/APP filtering is applied at encode-time.
pub struct IncomingRtcp {
    pub timestamp_ms: i64,
    pub raw_packet: Vec<u8>,
}

/// Logged RTCP packet (raw bytes as observed on the wire).
///
/// SDES/APP filtering is applied at encode-time.
pub struct OutgoingRtcp {
    pub timestamp_ms: i64,
    pub raw_packet: Vec<u8>,
}

/// Loss-based bandwidth estimate update.
pub struct LossBasedBweUpdate {
    pub timestamp_ms: i64,
    /// Bandwidth estimate in bits per second after the update.
    pub bitrate_bps: u32,
    /// Fraction of lost packets (0-255 range, where 255 = 100% loss).
    pub fraction_loss: u32,
    /// Total number of packets that this BWE update is based on.
    pub total_packets: u32,
}

/// Delay-based bandwidth estimate update.
pub struct DelayBasedBweUpdate {
    pub timestamp_ms: i64,
    /// Bandwidth estimate in bits per second after the update.
    pub bitrate_bps: u32,
    /// Detector state at the time of the update.
    pub detector_state: DetectorState,
}

/// Detector state for delay-based BWE, matching the proto enum values.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorState {
    Unknown = 0,
    Normal = 1,
    Underusing = 2,
    Overusing = 3,
}

/// Probe cluster created — a bandwidth probe was initiated.
pub struct ProbeClusterCreated {
    pub timestamp_ms: i64,
    /// Unique probe cluster ID.
    pub id: u32,
    /// Target bitrate in bits per second.
    pub bitrate_bps: u32,
    /// Minimum number of packets to send.
    pub min_packets: u32,
    // Note: the proto's min_bytes field (BweProbeCluster field 5) is left unset.
    // str0m doesn't track min_bytes separately — it uses min_packet_count +
    // min_probe_delta to determine probe completion.
}

/// Probe cluster completed successfully with a measured bitrate.
pub struct ProbeClusterSuccess {
    pub timestamp_ms: i64,
    /// Probe cluster ID.
    pub id: u32,
    /// Measured bitrate in bits per second.
    pub bitrate_bps: u32,
}

/// Probe cluster failed.
pub struct ProbeClusterFailure {
    pub timestamp_ms: i64,
    /// Probe cluster ID.
    pub id: u32,
    /// Reason for failure.
    pub failure_reason: ProbeFailureReason,
}

/// Probe failure reason, matching the proto enum values.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailureReason {
    Unknown = 0,
    InvalidSendReceiveInterval = 1,
    InvalidSendReceiveRatio = 2,
    Timeout = 3,
}

/// ALR (Application Limited Region) state change.
pub struct AlrStateEvent {
    pub timestamp_ms: i64,
    /// True if the application is now in ALR (sending less than capacity).
    pub in_alr: bool,
}

/// RTP header extension IDs for stream config events.
///
/// Maps extension types to their negotiated 4-bit IDs.
/// Only extensions relevant for BWE analysis are included.
pub struct RtpHeaderExtensionConfig {
    pub transmission_time_offset_id: Option<i32>,
    pub absolute_send_time_id: Option<i32>,
    pub transport_sequence_number_id: Option<i32>,
    pub video_rotation_id: Option<i32>,
    pub audio_level_id: Option<i32>,
}

/// Audio receive stream configuration.
pub struct AudioRecvStreamConfig {
    pub timestamp_ms: i64,
    /// Remote SSRC being received.
    pub remote_ssrc: u32,
    /// Local SSRC used for sending RTCP (e.g. receiver reports).
    pub local_ssrc: u32,
    /// Header extension IDs negotiated for this stream.
    pub header_extensions: RtpHeaderExtensionConfig,
}

/// Audio send stream configuration.
pub struct AudioSendStreamConfig {
    pub timestamp_ms: i64,
    /// SSRC for the outgoing audio stream.
    pub ssrc: u32,
    /// Header extension IDs negotiated for this stream.
    pub header_extensions: RtpHeaderExtensionConfig,
}

/// Video receive stream configuration.
pub struct VideoRecvStreamConfig {
    pub timestamp_ms: i64,
    /// Remote SSRC being received.
    pub remote_ssrc: u32,
    /// Local SSRC used for sending RTCP (e.g. receiver reports).
    pub local_ssrc: u32,
    /// RTX SSRC for retransmissions, if configured.
    pub rtx_ssrc: Option<u32>,
    /// Header extension IDs negotiated for this stream.
    pub header_extensions: RtpHeaderExtensionConfig,
}

/// Video send stream configuration.
pub struct VideoSendStreamConfig {
    pub timestamp_ms: i64,
    /// SSRC for the outgoing video stream.
    pub ssrc: u32,
    /// RTX SSRC for retransmissions, if configured.
    pub rtx_ssrc: Option<u32>,
    /// Header extension IDs negotiated for this stream.
    pub header_extensions: RtpHeaderExtensionConfig,
}
