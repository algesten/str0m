use crate::channel::ChannelId;
use crate::dtls::Fingerprint;
use crate::format::PayloadParams;
use crate::ice::IceCreds;
use crate::io::Id;
use crate::media::MediaInner;
use crate::media::MediaKind;
use crate::rtp::Direction;
use crate::rtp::ExtensionMap;
use crate::rtp::Mid;
use crate::sctp::ChannelConfig;
use crate::sdp::Msid;
use crate::Rtc;
use crate::RtcError;

use super::AddMedia;

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

    /// create local media
    #[allow(clippy::too_many_arguments)] // TODO: clean up
    pub fn create_local_media(
        &mut self,
        mid: Mid,           // mid is needed
        kind: MediaKind,    // mediakind is needed
        dir: Direction,     // should we just do send and receive and ignore sendrecv?
        index: usize,       // is index needed?
        exts: ExtensionMap, // should we use this but without assigning ids? just have a vector of extensions?
        params: Vec<PayloadParams>,
        cname: Option<String>, // do we need this one?
    ) {
        let cname = if let Some(cname) = cname {
            fn is_token_char(c: &char) -> bool {
                // token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39
                // / %x41-5A / %x5E-7E
                let u = *c as u32;
                u == 0x21
                    || (0x23..=0x27).contains(&u)
                    || (0x2a..=0x2b).contains(&u)
                    || (0x2d..=0x2e).contains(&u)
                    || (0x30..=0x39).contains(&u)
                    || (0x41..=0x5a).contains(&u)
                    || (0x5e..0x7e).contains(&u)
            }
            // https://www.rfc-editor.org/rfc/rfc8830
            // msid-id = 1*64token-char
            cname.chars().filter(is_token_char).take(64).collect()
        } else {
            Id::<20>::random().to_string()
        };

        let ssrcs = {
            // For video we do RTX channels.
            let has_rtx = kind == MediaKind::Video;

            let ssrc_base = if has_rtx { 2 } else { 1 };

            // TODO: allow configuring simulcast
            let simulcast_count = 1;

            let ssrc_count = ssrc_base * simulcast_count;
            let mut v = Vec::with_capacity(ssrc_count);

            let mut prev = 0.into();
            for i in 0..ssrc_count {
                // Allocate SSRC that are not in use in the session already.
                let new_ssrc = self.rtc.new_ssrc();
                let is_rtx = has_rtx && i % 2 == 1;
                let repairs = if is_rtx { Some(prev) } else { None };
                v.push((new_ssrc, repairs));
                prev = new_ssrc;
            }

            v
        };

        let msid = Msid {
            stream_id: cname.clone(),
            track_id: Id::<30>::random().to_string(),
        };

        let add = AddMedia {
            mid,
            cname,
            msid,
            kind,
            dir,
            ssrcs,
            params,
            index,
        };

        let mut media = MediaInner::from_add_media(add, exts);
        media.need_open_event = true;
        self.rtc.session.add_media(media);
    }

    /// create remote media
    pub fn create_remote_media(
        &mut self,
        mid: Mid,
        kind: MediaKind,
        dir: Direction,
        index: usize,
        exts: ExtensionMap,
        params: Vec<PayloadParams>,
    ) {
        let media = MediaInner::new_from_remote(mid, kind, index, exts, dir, params);
        self.rtc.session.add_media(media);
        // TODO: not clear what's gonna happen here, my guess is that when it sees a rtp with Mid it will generate a open event
    }
}
