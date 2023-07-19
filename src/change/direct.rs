use std::time::Instant;

use crate::channel::ChannelId;
use crate::dtls::Fingerprint;
use crate::ice::IceCreds;
use crate::media::{MediaKind, RtpPacketToSend};
use crate::rtp::{Direction, Mid, Ssrc};
use crate::sctp::ChannelConfig;
use crate::{Rtc, RtcError};

/// Direct change strategy.
///
/// Makes immediate changes to the Rtc session without any Sdp OFFER/ANSWER.
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

    /// Sets the remote DTLS fingerprint.
    pub fn set_remote_fingerprint(&mut self, dtls_fingerprint: Fingerprint) {
        self.rtc.remote_fingerprint = Some(dtls_fingerprint);
    }

    /// Set direction on some media.
    pub fn set_direction(&mut self, mid: Mid, dir: Direction) -> Result<(), RtcError> {
        let media = self
            .rtc
            .session
            .media_by_mid_mut(mid)
            .ok_or_else(|| RtcError::Other(format!("No media for mid: {}", mid)))?;

        media.set_direction(dir);

        Ok(())
    }

    /// Enables transport-wide congestion control (TWCC) on the receive end
    /// so the remote end can do BWE using TWCC.
    pub fn enable_twcc_feedback(&mut self) {
        self.rtc.session.enable_twcc_feedback();
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

    /// Adds state to send RTP packets with the given MID using send_rtp_packet.
    /// Call it before calling send_rtp_packet with the given MID.
    /// Can fail if the MID is already being used.
    /// media_kind alters the Pacer's behavior.
    /// Uses the codecs from the config for RTX, so configure RTX PTs if you want RTX.
    /// For RTX to work, the RTX SSRC to use for any given primary SSRC must also be provided.
    /// max_retain is the maximum number of packets to keep in the send buffer,
    ///  both for RTX and for calls between send_rtp_packet and poll_output.
    /// 100 for audio and 1000 for video is probably a good idea.
    // video at 10mbps with 1200-byte packets is about 1000pps.
    // audio with 20ms p-time is about 50pps.
    pub fn add_rtp_packet_sender(
        &mut self,
        mid: Mid,
        media_kind: MediaKind,
        max_retain: usize,
        primary_to_rtx_ssrc_mapping: Vec<(Ssrc, Ssrc)>,
    ) -> Result<(), RtcError> {
        self.rtc.session.add_rtp_packet_sender(
            mid,
            media_kind,
            max_retain,
            primary_to_rtx_ssrc_mapping,
        )
    }

    /// Sends an RTP packet with the given MID.
    /// The MID need not be included in the header.
    /// Fails if add_rtp_packet_sender isn't called first.
    pub fn send_rtp_packet(
        &mut self,
        to_send: RtpPacketToSend,
        now: Instant,
    ) -> Result<(), RtcError> {
        self.rtc.session.send_rtp_packet(to_send, now)
    }

    /// Deletes state associated with sending RTP packets with the given MID.
    /// Call it once done calling send_rtp_packet to clear memory.
    /// Fails if MID wasn't added or it was already removed.
    pub fn remove_rtp_packet_sender(&mut self, mid: Mid) -> Result<(), RtcError> {
        self.rtc.session.remove_rtp_packet_sender(mid)
    }

    /// Adds state to receive RTP packets with the given MID.
    /// RTP packets will be provided via Event::RtpPacketReceived.
    /// Automatically sends RTCP feedback.
    /// The media_kind alters the Receiver Report interval.
    /// Can fail if the MID is already being used.
    /// Uses the codecs from the config for RTX and knowing clock rates.
    pub fn add_rtp_packet_receiver(
        &mut self,
        mid: Mid,
        media_kind: MediaKind,
        enable_nack: bool,
    ) -> Result<(), RtcError> {
        self.rtc
            .session
            .add_rtp_packet_receiver(mid, media_kind, enable_nack)
    }

    /// Deletes state associated with receiving RTP packets with the given MID.
    /// Call it once RTP packets with the given MID are no longer expected.
    /// Fails if MID wasn't added or it was already removed.
    pub fn remove_rtp_packet_receiver(&mut self, mid: Mid) -> Result<(), RtcError> {
        self.rtc.session.remove_rtp_packet_receiver(mid)
    }
}
