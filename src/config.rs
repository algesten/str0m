use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::DtlsCert;
use crate::crypto::dtls::DtlsVersion;
use crate::crypto::CryptoProvider;
use crate::format::CodecConfig;
use crate::ice::IceCreds;
use crate::rtp_::{Bitrate, Extension, ExtensionMap};
use crate::Rtc;

/// Customized config for creating an [`Rtc`] instance.
///
/// ```
/// # #[cfg(feature = "openssl")] {
/// use std::time::Instant;
/// use str0m::RtcConfig;
///
/// let rtc = RtcConfig::new()
///     .set_ice_lite(true)
///     .build(Instant::now());
/// # }
/// ```
///
/// Configs implement [`Clone`] to help create multiple `Rtc` instances.
#[derive(Debug, Clone)]
pub struct RtcConfig {
    pub(crate) local_ice_credentials: Option<IceCreds>,
    pub(crate) crypto_provider: Option<Arc<CryptoProvider>>,
    pub(crate) dtls_cert: Option<DtlsCert>,
    pub(crate) fingerprint_verification: bool,
    pub(crate) ice_lite: bool,
    pub(crate) initial_stun_rto: Option<Duration>,
    pub(crate) max_stun_rto: Option<Duration>,
    pub(crate) max_stun_retransmits: Option<usize>,
    pub(crate) codec_config: CodecConfig,
    pub(crate) exts: ExtensionMap,
    pub(crate) stats_interval: Option<Duration>,
    pub(crate) bwe_config: Option<BweConfig>,
    pub(crate) reordering_size_audio: usize,
    pub(crate) reordering_size_video: usize,
    pub(crate) send_buffer_audio: usize,
    pub(crate) send_buffer_video: usize,
    pub(crate) rtp_mode: bool,
    pub(crate) enable_raw_packets: bool,
    pub(crate) dtls_version: DtlsVersion,
}

#[derive(Debug, Clone)]
pub(crate) struct BweConfig {
    pub(crate) initial_bitrate: Bitrate,
}

impl RtcConfig {
    /// Creates a new default config.
    pub fn new() -> Self {
        RtcConfig::default()
    }

    /// Get the local ICE credentials, if set.
    ///
    /// If not specified, local credentials will be randomly generated when
    /// building the [`Rtc`] instance.
    pub fn local_ice_credentials(&self) -> &Option<IceCreds> {
        &self.local_ice_credentials
    }

    /// Explicitly sets local ICE credentials.
    pub fn set_local_ice_credentials(mut self, local_ice_credentials: IceCreds) -> Self {
        self.local_ice_credentials = Some(local_ice_credentials);
        self
    }

    /// Set the crypto provider.
    ///
    /// This overrides what is set in [`crate::crypto::CryptoProvider::install_process_default()`].
    pub fn set_crypto_provider(mut self, p: Arc<CryptoProvider>) -> Self {
        self.crypto_provider = Some(p);
        self
    }

    /// The configured crypto provider, if explicitly set.
    ///
    /// Returns `None` if not explicitly set via [`Self::set_crypto_provider()`].
    /// When `None`, the process default will be checked when building the [`Rtc`] instance.
    pub fn crypto_provider(&self) -> Option<&Arc<CryptoProvider>> {
        self.crypto_provider.as_ref()
    }

    /// Returns the configured DTLS certificate, if set.
    ///
    /// If not set, a certificate will be generated automatically.
    pub fn dtls_cert(&self) -> Option<&DtlsCert> {
        self.dtls_cert.as_ref()
    }

    /// Set a pregenerated DTLS certificate.
    ///
    /// If not set, a certificate will be generated automatically using
    /// the configured crypto provider.
    ///
    /// ```
    /// # use str0m::RtcConfig;
    /// # use str0m::crypto;
    ///
    /// let provider = crypto::from_feature_flags();
    /// let cert = provider.dtls_provider.generate_certificate().unwrap();
    /// let rtc_config = RtcConfig::default()
    ///     .set_dtls_cert(cert);
    /// ```
    pub fn set_dtls_cert(mut self, cert: DtlsCert) -> Self {
        self.dtls_cert = Some(cert);
        self
    }

    /// Toggle ice lite. Ice lite is a mode for WebRTC servers with public IP address.
    /// An [`Rtc`] instance in ice lite mode will not make STUN binding requests, but only
    /// answer to requests from the remote peer.
    ///
    /// See [ICE RFC][1]
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc8445#page-13
    pub fn set_ice_lite(mut self, enabled: bool) -> Self {
        self.ice_lite = enabled;
        self
    }

    /// Sets the initial STUN retransmission timeout (RTO).
    ///
    /// This is the initial wait time before a STUN request is retransmitted.
    /// The timeout will double with each retry, starting from this value.
    ///
    /// Defaults to 250ms.
    pub fn set_initial_stun_rto(&mut self, rto: Duration) {
        self.initial_stun_rto = Some(rto);
    }

    /// Sets the maximum STUN retransmission timeout for the ICE agent.
    ///
    /// This is the upper bound for how long to wait between retransmissions.
    /// It also controls how often successful bindings are checked.
    ///
    /// Defaults to 3000ms.
    pub fn set_max_stun_rto(&mut self, rto: Duration) {
        self.max_stun_rto = Some(rto);
    }

    /// Sets the maximum number of retransmits for STUN messages.
    ///
    /// Defaults to 9.
    pub fn set_max_stun_retransmits(&mut self, num: usize) {
        self.max_stun_retransmits = Some(num);
    }

    /// Get fingerprint verification mode.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to true.
    /// assert!(config.fingerprint_verification());
    /// ```
    pub fn fingerprint_verification(&self) -> bool {
        self.fingerprint_verification
    }

    /// Toggle certificate fingerprint verification.
    ///
    /// By default the certificate fingerprint is verified.
    pub fn set_fingerprint_verification(mut self, enabled: bool) -> Self {
        self.fingerprint_verification = enabled;
        self
    }

    /// Tells whether ice lite is enabled.
    ///
    /// ```
    /// # #[cfg(feature = "openssl")] {
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to false.
    /// assert_eq!(config.ice_lite(), false);
    /// # }
    /// ```
    pub fn ice_lite(&self) -> bool {
        self.ice_lite
    }

    /// Lower level access to precise configuration of codecs (payload types).
    pub fn codec_config(&mut self) -> &mut CodecConfig {
        &mut self.codec_config
    }

    /// Clear all configured codecs.
    ///
    /// ```
    /// # #[cfg(feature = "openssl")] {
    /// # use std::time::Instant;
    /// # use str0m::RtcConfig;
    /// // For the session to use only OPUS and VP8.
    /// let mut rtc = RtcConfig::default()
    ///     .clear_codecs()
    ///     .enable_opus(true)
    ///     .enable_vp8(true)
    ///     .build(Instant::now());
    /// # }
    /// ```
    pub fn clear_codecs(mut self) -> Self {
        self.codec_config.clear();
        self
    }

    /// Enable opus audio codec.
    ///
    /// Enabled by default.
    pub fn enable_opus(mut self, enabled: bool) -> Self {
        self.codec_config.enable_opus(enabled);
        self
    }

    /// Enable PCM μ-law audio codec.
    ///
    /// This is 14-bit audio compressed to 8-bit as specified by G.711
    pub fn enable_pcmu(mut self, enabled: bool) -> Self {
        self.codec_config.enable_pcmu(enabled);
        self
    }

    /// Enable PCM a-law audio codec.
    ///
    /// This is 13-bit audio compressed to 8-bit as specified by G.711
    pub fn enable_pcma(mut self, enabled: bool) -> Self {
        self.codec_config.enable_pcma(enabled);
        self
    }

    /// Enable VP8 video codec.
    ///
    /// Enabled by default.
    pub fn enable_vp8(mut self, enabled: bool) -> Self {
        self.codec_config.enable_vp8(enabled);
        self
    }

    /// Enable H264 video codec.
    ///
    /// Enabled by default.
    pub fn enable_h264(mut self, enabled: bool) -> Self {
        self.codec_config.enable_h264(enabled);
        self
    }

    /// Enable H265 video codec.
    ///
    /// Enabled by default.
    pub fn enable_h265(mut self, enabled: bool) -> Self {
        self.codec_config.enable_h265(enabled);
        self
    }

    /// Enable VP9 video codec.
    ///
    /// Enabled by default.
    pub fn enable_vp9(mut self, enabled: bool) -> Self {
        self.codec_config.enable_vp9(enabled);
        self
    }

    /// Enable AV1 video codec.
    ///
    /// Enabled by default.
    pub fn enable_av1(mut self, enabled: bool) -> Self {
        self.codec_config.enable_av1(enabled);
        self
    }

    /// Configure the RTP extension mappings.
    ///
    /// The default extension map is
    ///
    /// ```
    /// # use str0m::rtp::{Extension, ExtensionMap};
    /// let exts = ExtensionMap::standard();
    ///
    /// assert_eq!(exts.id_of(Extension::AudioLevel), Some(1));
    /// assert_eq!(exts.id_of(Extension::AbsoluteSendTime), Some(2));
    /// assert_eq!(exts.id_of(Extension::TransportSequenceNumber), Some(3));
    /// assert_eq!(exts.id_of(Extension::RtpMid), Some(4));
    /// assert_eq!(exts.id_of(Extension::RtpStreamId), Some(10));
    /// assert_eq!(exts.id_of(Extension::RepairedRtpStreamId), Some(11));
    /// assert_eq!(exts.id_of(Extension::VideoOrientation), Some(13));
    /// ```
    pub fn extension_map(&mut self) -> &mut ExtensionMap {
        &mut self.exts
    }

    /// Set the extension map replacing the existing.
    pub fn set_extension_map(mut self, exts: ExtensionMap) -> Self {
        self.exts = exts;
        self
    }

    /// Clear out the standard extension mappings.
    pub fn clear_extension_map(mut self) -> Self {
        self.exts.clear();

        self
    }

    /// Set an extension mapping on session level.
    ///
    /// The media level will be capped by the extension enabled on session level.
    ///
    /// The id must be 1-14 inclusive (1-indexed).
    pub fn set_extension(mut self, id: u8, ext: Extension) -> Self {
        self.exts.set(id, ext);
        self
    }

    /// Set the interval between statistics events.
    ///
    /// None turns off the stats events.
    ///
    /// This includes [`MediaEgressStats`][crate::stats::MediaEgressStats],
    /// [`MediaIngressStats`][crate::stats::MediaIngressStats]
    pub fn set_stats_interval(mut self, interval: Option<Duration>) -> Self {
        self.stats_interval = interval;
        self
    }

    /// The configured statistics interval.
    ///
    /// None means statistics are disabled.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// # use std::time::Duration;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to None.
    /// assert_eq!(config.stats_interval(), None);
    /// ```
    pub fn stats_interval(&self) -> Option<Duration> {
        self.stats_interval
    }

    /// Enables estimation of available bandwidth (BWE).
    ///
    /// None disables the BWE. This is an estimation of the send bandwidth, not receive.
    ///
    /// This includes setting the initial estimate to start with.
    pub fn enable_bwe(mut self, initial_estimate: Option<Bitrate>) -> Self {
        match initial_estimate {
            Some(b) => {
                let conf = self.bwe_config.get_or_insert(BweConfig::new(b));
                conf.initial_bitrate = b;
            }
            None => {
                self.bwe_config = None;
            }
        }

        self
    }

    /// The initial bitrate as set by [`Self::enable_bwe()`].
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to None - BWE off.
    /// assert_eq!(config.bwe_initial_bitrate(), None);
    /// ```
    pub fn bwe_initial_bitrate(&self) -> Option<Bitrate> {
        self.bwe_config.as_ref().map(|c| c.initial_bitrate)
    }

    /// Sets the number of packets held back for reordering audio packets.
    ///
    /// Str0m tries to deliver the frames in order. This number determines how many
    /// packets to "wait" before releasing media
    /// [`contiguous: false`][crate::media::MediaData::contiguous].
    ///
    /// This setting is ignored in [RTP mode][`RtcConfig::set_rtp_mode()`] where RTP
    /// packets can arrive out of order.
    pub fn set_reordering_size_audio(mut self, size: usize) -> Self {
        self.reordering_size_audio = size;

        self
    }

    /// Returns the setting for audio reordering size.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to 15.
    /// assert_eq!(config.reordering_size_audio(), 15);
    /// ```
    ///
    /// This setting is ignored in [RTP mode][`RtcConfig::set_rtp_mode()`] where RTP
    /// packets can arrive out of order.
    pub fn reordering_size_audio(&self) -> usize {
        self.reordering_size_audio
    }

    /// Sets the number of packets held back for reordering video packets.
    ///
    /// Str0m tries to deliver the frames in order. This number determines how many
    /// packets to "wait" before releasing media with gaps.
    ///
    /// This must be at least as big as the number of packets the biggest keyframe
    /// can be split over.
    ///
    /// WARNING: video is very different to audio. Setting this value too low will result in
    /// missing video data. The 0 (as described for audio) is not relevant for video.
    ///
    /// Default: 30
    ///
    /// This setting is ignored in [RTP mode][`RtcConfig::set_rtp_mode()`] where RTP
    /// packets can arrive out of order.
    pub fn set_reordering_size_video(mut self, size: usize) -> Self {
        self.reordering_size_video = size;

        self
    }

    /// Returns the setting for video reordering size.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to 30.
    /// assert_eq!(config.reordering_size_video(), 30);
    /// ```
    ///
    /// This setting is ignored in [RTP mode][`RtcConfig::set_rtp_mode()`] where RTP
    /// packets can arrive out of order.
    pub fn reordering_size_video(&self) -> usize {
        self.reordering_size_video
    }

    /// Sets the buffer size for outgoing audio packets.
    ///
    /// This must be larger than 0. The value configures an internal ring buffer used as a temporary
    /// holding space between calling [`Writer::write`][crate::media::Writer::write()] and
    /// [`Rtc::poll_output`].
    ///
    /// For audio one call to `write()` typically results in one RTP packet since the entire
    /// payload fits in one. If you can guarantee that every `write()` is a single RTP packet,
    /// and is always followed by a `poll_output()`, it might be possible to set this value to 1.
    /// But that would give no margins for unexpected patterns.
    ///
    /// panics if set to 0.
    pub fn set_send_buffer_audio(mut self, size: usize) -> Self {
        assert!(size > 0);
        self.send_buffer_audio = size;
        self
    }

    /// Returns the setting for audio resend size.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to 50.
    /// assert_eq!(config.send_buffer_audio(), 50);
    /// ```
    pub fn send_buffer_audio(&self) -> usize {
        self.send_buffer_audio
    }

    /// Sets the buffer size for outgoing video packets and resends.
    ///
    /// This must be larger than 0. The value configures an internal ring buffer that is both
    /// used as a temporary holding space between calling
    /// [`Writer::write`][crate::media::Writer::write()] and [`Rtc::poll_output`] as well as for
    /// fulfilling resends.
    ///
    /// For video, this buffer is used for more than for audio. First, a call to `write()` often
    /// results in multiple RTP packets since large frames don't fit in one payload. That means
    /// the buffer must be at least as large to hold all those packets. Second, when the remote
    /// requests resends (NACK), those are fulfilled from this buffer. Third, for Bandwidth
    /// Estimation (BWE), when probing for available bandwidth, packets from this buffer are used
    /// to do "spurious resends", i.e. we do resends for packets that were not asked for.
    pub fn set_send_buffer_video(mut self, size: usize) -> Self {
        self.send_buffer_video = size;
        self
    }

    /// Returns the setting for video resend size.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to 1000.
    /// assert_eq!(config.send_buffer_video(), 1000);
    /// ```
    pub fn send_buffer_video(&self) -> usize {
        self.send_buffer_video
    }

    /// Make the entire Rtc be in RTP mode.
    ///
    /// This means all media, read from [`RtpPacket`][crate::rtp::RtpPacket] and written to
    /// [`StreamTx::write_rtp`][crate::rtp::StreamTx::write_rtp] are RTP packetized.
    /// It bypasses all internal packetization/depacketization inside str0m.
    ///
    /// WARNING: This is a low level API and is not str0m's primary use case.
    pub fn set_rtp_mode(mut self, enabled: bool) -> Self {
        self.rtp_mode = enabled;

        self
    }

    /// Checks if RTP mode is set.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to false.
    /// assert_eq!(config.rtp_mode(), false);
    /// ```
    pub fn rtp_mode(&self) -> bool {
        self.rtp_mode
    }

    /// Enable the [`Event::RawPacket`][crate::Event::RawPacket] event.
    ///
    /// This clones data, and is therefore expensive.
    /// Should not be enabled outside of tests and troubleshooting.
    pub fn enable_raw_packets(mut self, enabled: bool) -> Self {
        self.enable_raw_packets = enabled;
        self
    }

    /// Set which DTLS version to use.
    ///
    /// Defaults to [`DtlsVersion::Dtls12`].
    pub fn set_dtls_version(mut self, version: DtlsVersion) -> Self {
        self.dtls_version = version;
        self
    }

    /// Get the configured DTLS version.
    pub fn dtls_version(&self) -> DtlsVersion {
        self.dtls_version
    }

    /// Create a [`Rtc`] from the configuration.
    pub fn build(self, start: Instant) -> Rtc {
        Rtc::new_from_config(self, start).expect("Failed to create Rtc from config")
    }
}

impl BweConfig {
    fn new(initial_bitrate: Bitrate) -> Self {
        Self { initial_bitrate }
    }
}

impl Default for RtcConfig {
    fn default() -> Self {
        Self {
            local_ice_credentials: None,
            crypto_provider: None,
            dtls_cert: None,
            fingerprint_verification: true,
            ice_lite: false,
            initial_stun_rto: None,
            max_stun_rto: None,
            max_stun_retransmits: None,
            codec_config: CodecConfig::new_with_defaults(),
            exts: ExtensionMap::standard(),
            stats_interval: None,
            bwe_config: None,
            reordering_size_audio: 15,
            reordering_size_video: 30,
            send_buffer_audio: 50,
            send_buffer_video: 1000,
            rtp_mode: false,
            enable_raw_packets: false,
            dtls_version: DtlsVersion::Dtls12,
        }
    }
}
