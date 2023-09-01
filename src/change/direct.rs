use crate::channel::ChannelId;
use crate::dtls::Fingerprint;
use crate::ice::IceCreds;
use crate::media::{Media, MediaKind};
use crate::rtp_::{Mid, Rid, Ssrc};
use crate::sctp::ChannelConfig;
use crate::streams::{StreamRx, StreamTx, DEFAULT_RTX_CACHE_DURATION};
use crate::Rtc;
use crate::RtcError;

/// Direct change strategy.
///
/// Makes immediate changes to the Rtc session without any Sdp OFFER/ANSWER.
///
/// <div class="warning"><b>This is a low level API.</b>
///
///  str0m normally guarantees that user input cannot cause panics.
///  However as an exception, the Direct API does allow the user to configure the
///  session in a way that is internally inconsistent. Such situations can
///  result in panics.
/// </div>
pub struct DirectApi<'a> {
    rtc: &'a mut Rtc,
}

impl<'a> DirectApi<'a> {
    /// Creates a new instance of the `DirectApi` struct with the specified `Rtc` instance.
    ///
    /// The `DirectApi` struct provides a high-level API for interacting with a WebRTC peer connection,
    /// and the `Rtc` instance provides low-level access to the underlying WebRTC functionality.
    pub fn new(rtc: &'a mut Rtc) -> Self {
        DirectApi { rtc }
    }

    /// Sets the ICE controlling flag for this peer connection.
    ///
    /// If `controlling` is `true`, this peer connection is set as the ICE controlling agent,
    /// meaning it will take the initiative to send connectivity checks and control the pace of
    /// connectivity checks sent between two peers during the ICE session.
    ///
    /// If `controlling` is `false`, this peer connection is set as the ICE controlled agent,
    /// meaning it will respond to connectivity checks sent by the controlling agent.
    pub fn set_ice_controlling(&mut self, controlling: bool) {
        self.rtc.ice.set_controlling(controlling);
    }

    /// Returns a reference to the local ICE credentials used by this peer connection.
    ///
    /// The ICE credentials consist of the username and password used by the ICE agent during
    /// the ICE session to authenticate and exchange connectivity checks with the remote peer.
    pub fn local_ice_credentials(&self) -> IceCreds {
        self.rtc.ice.local_credentials().clone()
    }

    /// Sets the local ICE credentials.
    pub fn set_local_ice_credentials(&mut self, local_ice_credentials: IceCreds) {
        self.rtc.ice.set_local_credentials(local_ice_credentials);
    }

    /// Sets the remote ICE credentials.
    pub fn set_remote_ice_credentials(&mut self, remote_ice_credentials: IceCreds) {
        self.rtc.ice.set_remote_credentials(remote_ice_credentials);
    }

    /// Returns a reference to the local DTLS fingerprint used by this peer connection.
    ///
    /// The DTLS fingerprint is a hash of the local SSL/TLS certificate used to authenticate the
    /// peer connection and establish a secure communication channel between the peers.
    pub fn local_dtls_fingerprint(&self) -> Fingerprint {
        self.rtc.dtls.local_fingerprint().clone()
    }

    /// Returns a reference to the remote DTLS fingerprint used by this peer connection.
    pub fn remote_dtls_fingerprint(&self) -> Option<Fingerprint> {
        self.rtc.dtls.remote_fingerprint().clone()
    }

    /// Sets the remote DTLS fingerprint.
    pub fn set_remote_fingerprint(&mut self, dtls_fingerprint: Fingerprint) {
        self.rtc.remote_fingerprint = Some(dtls_fingerprint);
    }

    /// Start the DTLS subsystem.
    pub fn start_dtls(&mut self, active: bool) -> Result<(), RtcError> {
        self.rtc.init_dtls(active)
    }

    /// Start the SCTP over DTLS.
    pub fn start_sctp(&mut self, client: bool) {
        self.rtc.init_sctp(client)
    }

    /// Create a new data channel.
    pub fn create_data_channel(&mut self, config: ChannelConfig) -> ChannelId {
        let id = self.rtc.chan.new_channel(&config);
        self.rtc.chan.confirm(id, config);
        id
    }

    /// Set whether to enable ice-lite.
    pub fn set_ice_lite(&mut self, ice_lite: bool) {
        self.rtc.ice.set_ice_lite(ice_lite);
    }

    /// Enable twcc feedback.
    pub fn enable_twcc_feedback(&mut self) {
        self.rtc.session.enable_twcc_feedback()
    }

    /// Generate a ssrc that is not already used in session
    pub fn new_ssrc(&self) -> Ssrc {
        self.rtc.session.streams.new_ssrc()
    }

    /// Get the str0m `ChannelId` by an `sctp_stream_id`.
    ///
    /// This is useful when using out of band negotiated sctp stream id in
    /// [`Self::create_data_channel()`]
    pub fn channel_id_by_sctp_stream_id(&self, id: u16) -> Option<ChannelId> {
        self.rtc.chan.channel_id_by_stream_id(id)
    }

    /// Get the `sctp_stream_id` from a str0m `ChannelId`.
    ///
    /// This is useful when using out of band negotiated sctp stream id in
    /// [`Self::create_data_channel()`]
    pub fn sctp_stream_id_by_channel_id(&self, id: ChannelId) -> Option<u16> {
        self.rtc.chan.stream_id_by_channel_id(id)
    }

    /// Create a new `Media`.
    ///
    /// All streams belong to a media identified by a `mid`. This creates the media without
    /// doing any SDP dance.
    pub fn declare_media(&mut self, mid: Mid, kind: MediaKind) -> &mut Media {
        let max_index = self.rtc.session.medias.iter().map(|m| m.index()).max();

        let next_index = if let Some(max_index) = max_index {
            max_index + 1
        } else {
            0
        };

        let exts = self.rtc.session.exts.cloned_with_type(kind.is_audio());
        let m = Media::from_direct_api(mid, next_index, kind, exts);

        self.rtc.session.medias.push(m);
        self.rtc.session.medias.last_mut().unwrap()
    }

    /// Remove `Media`.
    ///
    /// Removes media and all streams belong to a media identified by a `mid`.
    pub fn remove_media(&mut self, mid: Mid) {
        self.rtc.session.remove_media(mid);
    }

    /// Allow incoming traffic from remote peer for the given SSRC.
    ///
    /// Can be called multiple times if the `rtx` is discovered later via RTP header extensions.
    pub fn expect_stream_rx(
        &mut self,
        ssrc: Ssrc,
        rtx: Option<Ssrc>,
        mid: Mid,
        rid: Option<Rid>,
    ) -> &mut StreamRx {
        self.rtc
            .session
            .streams
            .expect_stream_rx(ssrc, rtx, mid, rid)
    }

    /// Remove the receive stream for the given SSRC.
    ///
    /// Returns true if stream existed and was removed.
    pub fn remove_stream_rx(&mut self, ssrc: Ssrc) -> bool {
        self.rtc.session.streams.remove_stream_rx(ssrc)
    }

    /// Obtain a receive stream.
    ///
    /// In RTP mode, the receive stream is used to signal keyframe requests.
    ///
    /// The stream must first be declared using [`DirectApi::expect_stream_rx`].
    pub fn stream_rx(&mut self, ssrc: &Ssrc) -> Option<&mut StreamRx> {
        self.rtc.session.streams.stream_rx(ssrc)
    }

    /// Obtain a recv stream by looking it up via mid/rid.
    pub fn stream_rx_by_mid(&mut self, mid: Mid, rid: Option<Rid>) -> Option<&mut StreamRx> {
        self.rtc.session.streams.rx_by_mid_rid(mid, rid)
    }

    /// Declare the intention to send data using the given SSRC.
    ///
    /// * The resend RTX is optional but necessary to do resends. str0m does not do
    ///   resends without RTX.
    ///
    /// Can be called multiple times without changing any internal state. However
    /// the RTX value is only picked up the first ever time we see a new SSRC.
    pub fn declare_stream_tx(
        &mut self,
        ssrc: Ssrc,
        rtx: Option<Ssrc>,
        mid: Mid,
        rid: Option<Rid>,
    ) -> &mut StreamTx {
        let Some(media) = self.rtc.session.media_by_mid(mid) else {
            panic!("No media declared for mid: {}", mid);
        };

        let is_audio = media.kind().is_audio();

        let stream = self
            .rtc
            .session
            .streams
            .declare_stream_tx(ssrc, rtx, mid, rid);

        let size = if is_audio {
            self.rtc.session.send_buffer_audio
        } else {
            self.rtc.session.send_buffer_video
        };

        stream.set_rtx_cache(size, DEFAULT_RTX_CACHE_DURATION);

        stream
    }

    /// Remove the transmit stream for the given SSRC.
    ///
    /// Returns true if stream existed and was removed.
    pub fn remove_stream_tx(&mut self, ssrc: Ssrc) -> bool {
        self.rtc.session.streams.remove_stream_tx(ssrc)
    }

    /// Obtain a send stream to write RTP data directly.
    ///
    /// The stream must first be declared using [`DirectApi::declare_stream_tx`].
    pub fn stream_tx(&mut self, ssrc: &Ssrc) -> Option<&mut StreamTx> {
        self.rtc.session.streams.stream_tx(ssrc)
    }

    /// Obtain a send stream by looking it up via mid/rid.
    pub fn stream_tx_by_mid(&mut self, mid: Mid, rid: Option<Rid>) -> Option<&mut StreamTx> {
        self.rtc.session.streams.tx_by_mid_rid(mid, rid)
    }
}
