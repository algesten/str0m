use crate::channel::ChannelId;
use crate::crypto::Fingerprint;
use crate::media::{Media, MediaKind};
use crate::rtp_::MidRid;
use crate::rtp_::{Mid, Rid, Ssrc};
use crate::sctp::ChannelConfig;
use crate::streams::{StreamRx, StreamTx, DEFAULT_RTX_CACHE_DURATION, DEFAULT_RTX_RATIO_CAP};
use crate::tx::{RtcTx, RtcTxInner};
use crate::IceCreds;
use crate::Rtc;
use crate::RtcError;
use crate::{Mutate, Poll};

/// Direct change strategy.
///
/// Makes immediate changes to the Rtc session without any SDP OFFER/ANSWER. This
/// is an alternative to `tx.sdp_api()` for use cases when you don't want to use SDP
/// (or when you want to write RTP directly).
///
/// To use the Direct API together with a browser client, you would need to make
/// the equivalent changes on the browser side by manually generating the correct
/// SDP OFFER/ANSWER to make the `RTCPeerConnection` match str0m's state.
///
/// To change str0m's state through the Direct API followed by the SDP API produce
/// an SDP OFFER is not a supported use case. Either pick SDP API and let str0m handle
/// the OFFER/ANSWER or use Direct API and deal with SDP manually. Not both.
///
/// <div class="warning"><b>This is a low level API.</b>
///
///  str0m normally guarantees that user input cannot cause panics.
///  However as an exception, the Direct API does allow the user to configure the
///  session in a way that is internally inconsistent. Such situations can
///  result in panics.
/// </div>
pub struct DirectApi<'a> {
    inner: RtcTxInner<'a>,
}

impl<'a> DirectApi<'a> {
    /// Creates a new instance of the `DirectApi` struct from a transaction.
    pub(crate) fn new(tx: RtcTx<'a, Mutate>) -> Self {
        DirectApi {
            inner: tx.into_inner(),
        }
    }

    /// Finish using the DirectApi and return to polling state.
    ///
    /// This must be called when done making changes to ensure the transaction
    /// is properly completed.
    pub fn finish(self) -> RtcTx<'a, Poll> {
        RtcTx::from_inner(self.inner)
    }

    /// Get a reference to the underlying Rtc.
    fn rtc(&self) -> &Rtc {
        self.inner.rtc
    }

    /// Get a mutable reference to the underlying Rtc.
    fn rtc_mut(&mut self) -> &mut Rtc {
        self.inner.rtc
    }

    #[allow(unused)]
    /// Get a reference to the inner state.
    fn inner(&self) -> &RtcTxInner<'a> {
        &self.inner
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
        self.rtc_mut().ice.set_controlling(controlling);
    }

    /// Returns a reference to the local ICE credentials used by this peer connection.
    ///
    /// The ICE credentials consist of the username and password used by the ICE agent during
    /// the ICE session to authenticate and exchange connectivity checks with the remote peer.
    pub fn local_ice_credentials(&self) -> IceCreds {
        self.rtc().ice.local_credentials().clone()
    }

    /// Sets the local ICE credentials.
    pub fn set_local_ice_credentials(&mut self, local_ice_credentials: IceCreds) {
        self.rtc_mut()
            .ice
            .set_local_credentials(local_ice_credentials);
    }

    /// Sets the remote ICE credentials.
    pub fn set_remote_ice_credentials(&mut self, remote_ice_credentials: IceCreds) {
        self.rtc_mut()
            .ice
            .set_remote_credentials(remote_ice_credentials);
    }

    /// Returns a reference to the local DTLS fingerprint used by this peer connection.
    ///
    /// The DTLS fingerprint is a hash of the local SSL/TLS certificate used to authenticate the
    /// peer connection and establish a secure communication channel between the peers.
    pub fn local_dtls_fingerprint(&self) -> &Fingerprint {
        self.rtc().dtls.local_fingerprint()
    }

    /// Returns a reference to the remote DTLS fingerprint used by this peer connection.
    pub fn remote_dtls_fingerprint(&self) -> Option<&Fingerprint> {
        self.rtc().dtls.remote_fingerprint()
    }

    /// Sets the remote DTLS fingerprint.
    pub fn set_remote_fingerprint(&mut self, dtls_fingerprint: Fingerprint) {
        self.rtc_mut().remote_fingerprint = Some(dtls_fingerprint);
    }

    /// Start the DTLS subsystem.
    pub fn start_dtls(&mut self, active: bool) -> Result<(), RtcError> {
        self.rtc_mut().init_dtls(active)
    }

    /// Start the SCTP over DTLS.
    pub fn start_sctp(&mut self, client: bool) {
        self.rtc_mut().init_sctp(client)
    }

    /// Create a new data channel.
    pub fn create_data_channel(&mut self, config: ChannelConfig) -> ChannelId {
        let id = self.rtc_mut().chan.new_channel(&config);
        self.rtc_mut().chan.confirm(id, config);
        id
    }

    /// Close a data channel.
    pub fn close_data_channel(&mut self, channel_id: ChannelId) {
        let rtc = self.rtc_mut();
        rtc.chan.close_channel(channel_id, &mut rtc.sctp);
    }

    /// Set whether to enable ice-lite.
    pub fn set_ice_lite(&mut self, ice_lite: bool) {
        self.rtc_mut().ice.set_ice_lite(ice_lite);
    }

    /// Enable twcc feedback.
    pub fn enable_twcc_feedback(&mut self) {
        self.rtc_mut().session.enable_twcc_feedback()
    }

    /// Generate a ssrc that is not already used in session
    pub fn new_ssrc(&mut self) -> Ssrc {
        self.rtc_mut().session.streams.new_ssrc()
    }

    /// Get the str0m `ChannelId` by an `sctp_stream_id`.
    ///
    /// This is useful when using out of band negotiated sctp stream id in
    /// [`Self::create_data_channel()`]
    pub fn channel_id_by_sctp_stream_id(&self, id: u16) -> Option<ChannelId> {
        self.rtc().chan.channel_id_by_stream_id(id)
    }

    /// Get the `sctp_stream_id` from a str0m `ChannelId`.
    ///
    /// This is useful when using out of band negotiated sctp stream id in
    /// [`Self::create_data_channel()`]
    pub fn sctp_stream_id_by_channel_id(&self, id: ChannelId) -> Option<u16> {
        self.rtc().chan.stream_id_by_channel_id(id)
    }

    /// Create a new `Media`.
    ///
    /// All streams belong to a media identified by a `mid`. This creates the media without
    /// doing any SDP dance.
    pub fn declare_media(&mut self, mid: Mid, kind: MediaKind) -> &mut Media {
        let max_index = self
            .rtc_mut()
            .session
            .medias
            .iter()
            .map(|m| m.index())
            .max();

        let next_index = if let Some(max_index) = max_index {
            max_index + 1
        } else {
            0
        };

        let exts = self
            .rtc_mut()
            .session
            .exts
            .cloned_with_type(kind.is_audio());
        let m = Media::from_direct_api(mid, next_index, kind, exts);

        self.rtc_mut().session.medias.push(m);
        self.rtc_mut().session.medias.last_mut().unwrap()
    }

    /// Remove `Media`.
    ///
    /// Removes media and all streams belong to a media identified by a `mid`.
    pub fn remove_media(&mut self, mid: Mid) {
        self.rtc_mut().session.remove_media(mid);
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
        let Some(_media) = self.rtc_mut().session.media_by_mid(mid) else {
            panic!("No media declared for mid: {}", mid);
        };

        // By default we do not suppress nacks, this has to be called explicitly by the user of direct API.
        let suppress_nack = false;

        let midrid = MidRid(mid, rid);

        self.rtc_mut()
            .session
            .streams
            .expect_stream_rx(ssrc, rtx, midrid, suppress_nack)
    }

    /// Remove the receive stream for the given SSRC.
    ///
    /// Returns true if stream existed and was removed.
    pub fn remove_stream_rx(&mut self, ssrc: Ssrc) -> bool {
        self.rtc_mut().session.streams.remove_stream_rx(ssrc)
    }

    /// Obtain a receive stream.
    ///
    /// In RTP mode, the receive stream is used to signal keyframe requests.
    ///
    /// The stream must first be declared using [`DirectApi::expect_stream_rx`].
    pub fn stream_rx(&mut self, ssrc: &Ssrc) -> Option<&mut StreamRx> {
        self.rtc_mut().session.streams.stream_rx(ssrc)
    }

    /// Obtain a recv stream by looking it up via mid/rid.
    pub fn stream_rx_by_mid(&mut self, mid: Mid, rid: Option<Rid>) -> Option<&mut StreamRx> {
        let midrid = MidRid(mid, rid);
        self.rtc_mut()
            .session
            .streams
            .stream_rx_by_midrid(midrid, true)
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
        let rtc = self.rtc_mut();

        let Some(media) = rtc.session.media_by_mid_mut(mid) else {
            panic!("No media declared for mid: {}", mid);
        };

        let is_audio = media.kind().is_audio();

        // If there is a RID tx, declare it so we can use it in Writer API
        if let Some(rid) = rid {
            media.add_to_rid_tx(rid);
        }

        let midrid = MidRid(mid, rid);

        let size = if is_audio {
            rtc.session.send_buffer_audio
        } else {
            rtc.session.send_buffer_video
        };

        let stream = rtc.session.streams.declare_stream_tx(ssrc, rtx, midrid);

        stream.set_rtx_cache(size, DEFAULT_RTX_CACHE_DURATION, DEFAULT_RTX_RATIO_CAP);

        stream
    }

    /// Remove the transmit stream for the given SSRC.
    ///
    /// Returns true if stream existed and was removed.
    pub fn remove_stream_tx(&mut self, ssrc: Ssrc) -> bool {
        self.rtc_mut().session.streams.remove_stream_tx(ssrc)
    }

    /// Obtain a send stream to write RTP data directly.
    ///
    /// The stream must first be declared using [`DirectApi::declare_stream_tx`].
    pub fn stream_tx(&mut self, ssrc: &Ssrc) -> Option<&mut StreamTx> {
        self.rtc_mut().session.streams.stream_tx(ssrc)
    }

    /// Obtain a send stream by looking it up via mid/rid.
    pub fn stream_tx_by_mid(&mut self, mid: Mid, rid: Option<Rid>) -> Option<&mut StreamTx> {
        let midrid = MidRid(mid, rid);
        self.rtc_mut().session.streams.stream_tx_by_midrid(midrid)
    }

    /// Reset a transmit stream to use a new SSRC and optionally a new RTX SSRC.
    ///
    /// This changes the SSRC of an existing stream and resets all relevant state.
    /// Use this when you need to change the SSRC of an existing stream without creating a new one.
    ///
    /// If the stream has an RTX SSRC, `new_rtx` must be provided. If the stream doesn't
    /// have an RTX SSRC, `new_rtx` is ignored.
    ///
    /// Returns a reference to the updated stream or None if:
    /// - No stream was found for the given mid/rid
    /// - The new SSRC is the same as the current one (no change needed)
    /// - The new RTX SSRC is the same as the current one (no change needed)
    pub fn reset_stream_tx(
        &mut self,
        mid: Mid,
        rid: Option<Rid>,
        new_ssrc: Ssrc,
        new_rtx: Option<Ssrc>,
    ) -> Option<&mut StreamTx> {
        let midrid = MidRid(mid, rid);

        // Find the stream by mid/rid to get the old SSRC
        let old_ssrc = {
            let stream = self.rtc_mut().session.streams.stream_tx_by_midrid(midrid)?;

            // Don't change to the same SSRC
            if stream.ssrc() == new_ssrc {
                return None;
            }

            // If the stream has an RTX SSRC, New RTX must be provided and differ.
            // But it is allowed to start or turn off RTX.
            if stream.rtx().is_some() && stream.rtx() == new_rtx {
                return None;
            }

            stream.ssrc()
        };

        // Re-index the stream with the new SSRC
        self.rtc_mut()
            .session
            .streams
            .reindex_stream_tx(old_ssrc, new_ssrc)?;

        // Find the stream again and reset its internal state
        let stream = self.rtc_mut().session.streams.stream_tx(&new_ssrc)?;
        stream.reset_ssrc(new_ssrc, new_rtx);

        Some(stream)
    }
}
