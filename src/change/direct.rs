use crate::channel::ChannelId;
use crate::dtls::Fingerprint;
use crate::ice::IceCreds;
use crate::rtp::Direction;
use crate::rtp::Mid;
use crate::Rtc;
use crate::RtcError;

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
    pub fn ice_controlling(&mut self, controlling: bool) {
        self.rtc.ice.set_controlling(controlling);
    }

    /// Returns a reference to the local ICE credentials used by this peer connection.
    ///
    /// The ICE credentials consist of the username and password used by the ICE agent during
    /// the ICE session to authenticate and exchange connectivity checks with the remote peer.
    pub fn local_ice_credentials(&self) -> &IceCreds {
        self.rtc.ice.local_credentials()
    }

    /// Sets the remote ICE credentials.
    pub fn remote_ice_credentials(&mut self, remote_ice_credentials: IceCreds) {
        self.rtc.ice.set_remote_credentials(remote_ice_credentials);
    }

    /// Returns a reference to the local DTLS fingerprint used by this peer connection.
    ///
    /// The DTLS fingerprint is a hash of the local SSL/TLS certificate used to authenticate the
    /// peer connection and establish a secure communication channel between the peers.
    pub fn local_dtls_fingerprint(&self) -> &Fingerprint {
        self.rtc.dtls.local_fingerprint()
    }

    /// Sets the remote DTLS fingerprint.
    pub fn remote_fingerprint(&mut self, dtls_fingerprint: &Fingerprint) {
        self.rtc.remote_fingerprint = Some(dtls_fingerprint.clone());
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

    ///
    pub fn add_prenegotiated_channel(&mut self, id: ChannelId) {
        self.rtc.sctp.open_prenegotiated_stream(*id);
    }

    /// Start the DTLS subsystem.
    pub fn start_dtls(&mut self, active: bool) -> Result<(), RtcError> {
        self.rtc.init_dtls(active)
    }

    /// Start the SCTP over DTLS.
    pub fn start_sctp(&mut self, client: bool) {
        self.rtc.init_sctp(client)
    }
}
