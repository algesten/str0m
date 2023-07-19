//! Strategy that amends the [`Rtc`] via SDP OFFER/ANSWER negotiation.

use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::channel::ChannelId;
use crate::dtls::Fingerprint;
use crate::format::CodecConfig;
use crate::format::PayloadParams;
use crate::ice::{Candidate, IceCreds};
use crate::io::Id;
use crate::media::MediaInner;
use crate::media::{MediaKind, Source};
use crate::rtp::{Direction, Extension, ExtensionMap, Mid, Pt, Ssrc};
use crate::sctp::ChannelConfig;
use crate::sdp::{self, MediaAttribute, MediaLine, MediaType, Msid, Sdp};
use crate::sdp::{Proto, SessionAttribute, Setup};
use crate::sdp::{SimulcastGroups, SimulcastOption};
use crate::session::Session;
use crate::Rtc;
use crate::RtcError;

pub use crate::sdp::{SdpAnswer, SdpOffer};

/// Changes to the Rtc via SDP Offer/Answer dance.
pub struct SdpApi<'a> {
    rtc: &'a mut Rtc,
    changes: Changes,
}

impl<'a> SdpApi<'a> {
    pub(crate) fn new(rtc: &'a mut Rtc) -> Self {
        SdpApi {
            rtc,
            changes: Changes::default(),
        }
    }

    /// Accept an [`SdpOffer`] from the remote peer. If this call returns successfully, the
    /// changes will have been made to the session. The resulting [`SdpAnswer`] should be
    /// sent to the remote peer.
    ///
    /// <b>Note. Pending changes from a previous non-completed [`SdpApi`][super::SdpApi] will be
    /// considered rolled back when calling this function.</b>
    ///
    /// The incoming SDP is validated in various ways which can cause this call to fail.
    /// Example of such problems would be an SDP without any m-lines, missing `a=fingerprint`
    /// or if `a=group` doesn't match the number of m-lines.
    ///
    /// ```no_run
    /// # use str0m::Rtc;
    /// # use str0m::change::{SdpOffer};
    /// // obtain offer from remote peer.
    /// let json_offer: &[u8] = todo!();
    /// let offer: SdpOffer = serde_json::from_slice(json_offer).unwrap();
    ///
    /// let mut rtc = Rtc::new();
    /// let answer = rtc.sdp_api().accept_offer(offer).unwrap();
    ///
    /// // send json_answer to remote peer.
    /// let json_answer = serde_json::to_vec(&answer).unwrap();
    /// ```
    pub fn accept_offer(self, offer: SdpOffer) -> Result<SdpAnswer, RtcError> {
        // Invalidate any outstanding PendingOffer.
        self.rtc.next_change_id();

        if offer.media_lines.is_empty() {
            return Err(RtcError::RemoteSdp("No m-lines in offer".into()));
        }

        add_ice_details(self.rtc, &offer)?;

        if self.rtc.remote_fingerprint.is_none() {
            if let Some(f) = offer.fingerprint() {
                self.rtc.remote_fingerprint = Some(f);
            } else {
                self.rtc.disconnect();
                return Err(RtcError::RemoteSdp("missing a=fingerprint".into()));
            }
        }

        if !self.rtc.dtls.is_inited() {
            // The side that makes the first offer is the controlling side.
            self.rtc.ice.set_controlling(false);
        }

        // Ensure setup=active/passive is corresponding remote and init dtls.
        init_dtls(self.rtc, &offer)?;

        // Modify session with offer
        apply_offer(&mut self.rtc.session, offer)?;

        // Handle potentially new m=application line.
        let client = self.rtc.dtls.is_active().expect("DTLS active to be set");
        if self.rtc.session.app().is_some() {
            self.rtc.init_sctp(client);
        }

        let params = AsSdpParams::new(self.rtc, None);
        let sdp = as_sdp(&self.rtc.session, params);

        Ok(sdp.into())
    }

    /// Accept an answer to a previously created [`SdpOffer`].
    ///
    /// This function returns an [`RtcError::ChangesOutOfOrder`] if we have created and applied another
    /// [`SdpApi`][super::SdpApi] before calling this. The same also happens if we use
    /// [`SdpApi::accept_offer()`] before using this pending instance.
    ///
    /// ```no_run
    /// # use str0m::Rtc;
    /// # use str0m::media::{MediaKind, Direction};
    /// # use str0m::change::SdpAnswer;
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.sdp_api();
    /// let mid = changes.add_media(MediaKind::Audio, Direction::SendOnly, None, None);
    /// let (offer, pending) = changes.apply().unwrap();
    ///
    /// // send offer to remote peer, receive answer back
    /// let answer: SdpAnswer = todo!();
    ///
    /// rtc.sdp_api().accept_answer(pending, answer).unwrap();
    /// ```
    pub fn accept_answer(
        self,
        mut pending: SdpPendingOffer,
        answer: SdpAnswer,
    ) -> Result<(), RtcError> {
        // Ensure we don't use the wrong changes below. We must use that of pending.
        drop(self.changes);

        if !self.rtc.is_correct_change_id(pending.change_id) {
            return Err(RtcError::ChangesOutOfOrder);
        }

        add_ice_details(self.rtc, &answer)?;

        // Ensure setup=active/passive is corresponding remote and init dtls.
        init_dtls(self.rtc, &answer)?;

        if self.rtc.remote_fingerprint.is_none() {
            if let Some(f) = answer.fingerprint() {
                self.rtc.remote_fingerprint = Some(f);
            } else {
                self.rtc.disconnect();
                return Err(RtcError::RemoteSdp("missing a=fingerprint".into()));
            }
        }

        // Split out new channels, since that is not handled by the Session.
        let new_channels = pending.changes.take_new_channels();

        // Modify session with answer
        apply_answer(&mut self.rtc.session, pending.changes, answer)?;

        // Handle potentially new m=application line.
        let client = self.rtc.dtls.is_active().expect("DTLS to be inited");
        if self.rtc.session.app().is_some() {
            self.rtc.init_sctp(client);
        }

        for (id, config) in new_channels {
            self.rtc.chan.confirm(id, config);
        }

        Ok(())
    }

    /// Test if any changes have been made.
    ///
    /// If changes have been made, nothing happens until we call [`SdpApi::apply()`].
    ///
    /// ```
    /// # use str0m::{Rtc, media::MediaKind, media::Direction};
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.sdp_api();
    /// assert!(!changes.has_changes());
    ///
    /// let mid = changes.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
    /// assert!(changes.has_changes());
    /// ```
    pub fn has_changes(&self) -> bool {
        !self.changes.0.is_empty()
    }

    /// Add audio or video media and get the `mid` that will be used.
    ///
    /// Each call will result in a new m-line in the offer identifed by the [`Mid`].
    ///
    /// The mid is not valid to use until the SDP offer-answer dance is complete and
    /// the mid been advertised via [`Event::MediaAdded`][crate::Event::MediaAdded].
    ///
    /// * `stream_id` is used to synchronize media. It is `a=msid-semantic: WMS <streamId>` line in SDP.
    /// * `track_id` is becomes both the track id in `a=msid <streamId> <trackId>` as well as the
    ///   CNAME in the RTP SDES.
    ///
    /// ```
    /// # use str0m::{Rtc, media::MediaKind, media::Direction};
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.sdp_api();
    ///
    /// let mid = changes.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
    /// ```
    pub fn add_media(
        &mut self,
        kind: MediaKind,
        dir: Direction,
        stream_id: Option<String>,
        track_id: Option<String>,
    ) -> Mid {
        let mid = self.rtc.new_mid();

        // https://www.rfc-editor.org/rfc/rfc8830
        // msid-id = 1*64token-char
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

        let stream_id = if let Some(stream_id) = stream_id {
            stream_id.chars().filter(is_token_char).take(64).collect()
        } else {
            Id::<20>::random().to_string()
        };

        let track_id = if let Some(track_id) = track_id {
            track_id.chars().filter(is_token_char).take(64).collect()
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

        // TODO: let user configure stream/track name.
        let msid = Msid {
            stream_id,
            track_id: track_id.clone(),
        };

        let add = AddMedia {
            mid,
            cname: track_id,
            msid,
            kind,
            dir,
            ssrcs,

            // Added later
            params: vec![],
            index: 0,
        };

        self.changes.0.push(Change::AddMedia(add));
        mid
    }

    /// Change the direction of an already existing media.
    ///
    /// All media have a direction. The media can be added by this side via
    /// [`SdpApi::add_media()`] or by the remote peer. Either way, the direction
    /// of the line can be changed at any time.
    ///
    /// It's possible to set the direction [`Direction::Inactive`] for media that
    /// will not be used by the session anymore.
    ///
    /// If the direction is set for media that doesn't exist, or if the direction is
    /// the same that's already set [`SdpApi::apply()`] not require a negotiation.
    pub fn set_direction(&mut self, mid: Mid, dir: Direction) {
        let Some(media) = self.rtc.session.media_by_mid_mut(mid) else {
            return;
        };

        if media.direction() == dir {
            return;
        }

        self.changes.0.push(Change::Direction(mid, dir));
    }

    /// Add a new data channel and get the `id` that will be used.
    ///
    /// The first ever data channel added to a WebRTC session results in a media
    /// of a special "application" type in the SDP. The m-line is for a SCTP association over
    /// DTLS, and all data channels are multiplexed over this single association.
    ///
    /// That means only the first ever `add_channel` will result in an [`SdpOffer`].
    /// Consecutive channels will be opened without needing a negotiation.
    ///
    /// The label is used to identify the data channel to the remote peer. This is mostly
    /// useful whe multiple channels are in use at the same time.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.sdp_api();
    ///
    /// let cid = changes.add_channel("my special channel".to_string());
    /// ```
    pub fn add_channel(&mut self, label: String) -> ChannelId {
        let has_media = self.rtc.session.app().is_some();

        if !has_media {
            let mid = self.rtc.new_mid();
            self.changes.0.push(Change::AddApp(mid));
        }

        let config = ChannelConfig {
            label,
            ..Default::default()
        };

        let id = self.rtc.chan.new_channel(&config);

        self.changes.0.push(Change::AddChannel((id, config)));

        id
    }
    /// Attempt to apply the changes made.
    ///
    /// If this returns [`SdpOffer`], the caller the changes are
    /// not happening straight away, and the caller is expected to do a negotiation with the remote
    /// peer and apply the answer using [`SdpPendingOffer`].
    ///
    /// In case this returns `None`, there either were no changes, or the changes could be applied
    /// without doing a negotiation. Specifically for additional [`SdpApi::add_channel()`]
    /// after the first, there is no negotiation needed.
    ///
    /// The [`SdpPendingOffer`] is valid until the next time we call this function, at which
    /// point using it will raise an error. Using [`SdpApi::accept_offer()`] will also invalidate
    /// the current [`SdpPendingOffer`].
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let mut rtc = Rtc::new();
    ///
    /// let changes = rtc.sdp_api();
    /// assert!(changes.apply().is_none());
    /// ```
    pub fn apply(self) -> Option<(SdpOffer, SdpPendingOffer)> {
        let change_id = self.rtc.next_change_id();

        let requires_negotiation = self.changes.0.iter().any(requires_negotiation);

        if requires_negotiation {
            let offer = create_offer(self.rtc, &self.changes);
            let pending = SdpPendingOffer {
                change_id,
                changes: self.changes,
            };
            Some((offer, pending))
        } else {
            apply_direct_changes(self.rtc, self.changes);
            None
        }
    }
}

/// Pending offer from a previous [`Rtc::sdp_api()`] call.
///
/// This allows us to accept a remote answer. No changes have been made to the session
/// before we call [`SdpApi::accept_answer()`], which means that rolling back a
/// change is as simple as dropping this instance.
///
/// ```no_run
/// # use str0m::Rtc;
/// # use str0m::media::{MediaKind, Direction};
/// # use str0m::change::SdpAnswer;
/// let mut rtc = Rtc::new();
///
/// let mut changes = rtc.sdp_api();
/// let mid = changes.add_media(MediaKind::Audio, Direction::SendOnly, None, None);
/// let (offer, pending) = changes.apply().unwrap();
///
/// // send offer to remote peer, receive answer back
/// let answer: SdpAnswer = todo!();
///
/// rtc.sdp_api().accept_answer(pending, answer).unwrap();
/// ```
pub struct SdpPendingOffer {
    change_id: usize,
    changes: Changes,
}

#[derive(Default)]
pub(crate) struct Changes(pub Vec<Change>);

#[derive(Debug)]
pub(crate) enum Change {
    AddMedia(AddMedia),
    AddApp(Mid),
    AddChannel((ChannelId, ChannelConfig)),
    Direction(Mid, Direction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddMedia {
    pub mid: Mid,
    pub cname: String,
    pub msid: Msid,
    pub kind: MediaKind,
    pub dir: Direction,
    pub ssrcs: Vec<(Ssrc, Option<Ssrc>)>,

    // These are filled in when creating a Media from AddMedia
    pub params: Vec<PayloadParams>,
    pub index: usize,
}

impl Deref for Changes {
    type Target = Vec<Change>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Changes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn requires_negotiation(c: &Change) -> bool {
    match c {
        Change::AddMedia(_) => true,
        Change::AddApp(_) => true,
        Change::AddChannel(_) => false,
        Change::Direction(_, _) => true,
    }
}

fn apply_direct_changes(rtc: &mut Rtc, mut changes: Changes) {
    // Split out new channels, since that is not handled by the Session.
    let new_channels = changes.take_new_channels();

    for (id, config) in new_channels {
        rtc.chan.confirm(id, config);
    }
}

fn create_offer(rtc: &mut Rtc, changes: &Changes) -> SdpOffer {
    if !rtc.dtls.is_inited() {
        // The side that makes the first offer is the controlling side.
        rtc.ice.set_controlling(true);
    }

    let params = AsSdpParams::new(rtc, Some(changes));
    let sdp = as_sdp(&rtc.session, params);

    sdp.into()
}

fn add_ice_details(rtc: &mut Rtc, sdp: &Sdp) -> Result<(), RtcError> {
    if let Some(creds) = sdp.ice_creds() {
        rtc.ice.set_remote_credentials(creds);
    } else {
        return Err(RtcError::RemoteSdp("missing a=ice-ufrag/pwd".into()));
    }

    for r in sdp.ice_candidates() {
        rtc.ice.add_remote_candidate(r.clone());
    }

    Ok(())
}

fn init_dtls(rtc: &mut Rtc, remote_sdp: &Sdp) -> Result<(), RtcError> {
    let setup = match remote_sdp.setup() {
        Some(v) => match v {
            // Remote being ActPass, we take Passive role.
            Setup::ActPass => Setup::Passive,
            _ => v.invert(),
        },

        None => {
            warn!("Missing a=setup line");
            Setup::Passive
        }
    };

    let active = setup == Setup::Active;
    rtc.init_dtls(active)?;

    Ok(())
}

fn as_sdp(session: &Session, params: AsSdpParams) -> Sdp {
    let (media_lines, mids, stream_ids) = {
        let mut v = as_media_lines(session);

        let mut new_lines = vec![];

        // When creating new m-lines from the pending changes, the m-line index starts from this.
        let new_index_start = v.len();

        // If there are additions in the pending changes, prepend them now.
        if let Some(pending) = params.pending {
            let exts = session.exts();
            new_lines = pending
                .as_new_medias(new_index_start, session.codec_config(), exts)
                .collect();
        }

        // Add potentially new m-lines to the existing ones.
        v.extend(new_lines.iter().map(|n| n as &dyn AsSdpMediaLine));

        // Turn into sdp::MediaLine (m-line).
        let mut lines = v
            .iter()
            .map(|m| {
                // Candidates should only be in the first BUNDLE mid
                let include_candidates = m.index() == 0;

                let attrs = params.media_attributes(include_candidates);

                m.as_media_line(attrs)
            })
            .collect::<Vec<_>>();

        if let Some(pending) = params.pending {
            pending.apply_to(&mut lines);
        }

        // Mids go into the session part of the SDP.
        let mids = v.iter().map(|m| m.mid()).collect();

        let mut stream_ids = vec![];
        for msid in v.iter().filter_map(|v| v.msid()) {
            if !stream_ids.contains(&msid.stream_id) {
                stream_ids.push(msid.stream_id.clone());
            }
        }

        (lines, mids, stream_ids)
    };

    let mut attrs = vec![
        SessionAttribute::Group {
            typ: "BUNDLE".into(),
            mids,
        },
        SessionAttribute::MsidSemantic {
            semantic: "WMS".to_string(),
            stream_ids,
        },
    ];

    if session.ice_lite {
        attrs.push(SessionAttribute::IceLite);
    }

    Sdp {
        session: sdp::Session {
            id: session.id(),
            bw: None,
            attrs,
        },
        media_lines,
    }
}

fn apply_offer(session: &mut Session, offer: SdpOffer) -> Result<(), RtcError> {
    offer.assert_consistency()?;

    update_session(session, &offer);

    let new_lines = sync_medias(session, &offer).map_err(RtcError::RemoteSdp)?;

    add_new_lines(session, &new_lines, true).map_err(RtcError::RemoteSdp)?;

    session.equalize_sources();

    Ok(())
}

fn apply_answer(
    session: &mut Session,
    pending: Changes,
    answer: SdpAnswer,
) -> Result<(), RtcError> {
    answer.assert_consistency()?;

    update_session(session, &answer);

    let new_lines = sync_medias(session, &answer).map_err(RtcError::RemoteSdp)?;

    // The new_lines from the answer must correspond to what we sent in the offer.
    if let Some(err) = pending.ensure_correct_answer(&new_lines) {
        return Err(RtcError::RemoteSdp(err));
    }

    add_new_lines(session, &new_lines, false).map_err(RtcError::RemoteSdp)?;

    // Add all pending changes (since we pre-allocated SSRC communicated in the Offer).
    add_pending_changes(session, pending);

    session.equalize_sources();

    Ok(())
}

fn add_pending_changes(session: &mut Session, pending: Changes) {
    // For pending AddMedia, we have outgoing SSRC communicated that needs to be added.
    for change in pending.0 {
        let add_media = match change {
            Change::AddMedia(v) => v,
            _ => continue,
        };

        for (ssrc, repairs) in &add_media.ssrcs {
            if repairs.is_none() {
                session.set_first_ssrc_local(*ssrc);
            }
        }

        let media = session
            .media_by_mid_mut(add_media.mid)
            .expect("Media to be added for pending mid");

        // the cname/msid has already been communicated in the offer, we need to kep
        // it the same once the m-line is created.
        media.set_cname(add_media.cname);
        media.set_msid(add_media.msid);

        for (ssrc, repairs) in add_media.ssrcs {
            let tx = media.get_or_create_source_tx(ssrc);
            if let Some(repairs) = repairs {
                if tx.set_repairs(repairs) {
                    media.set_equalize_sources();
                }
            }
        }
    }
}

/// Compares m-lines in Sdp with that already in the session.
///
/// * Existing m-lines can apply changes (such as direction change).
/// * New m-lines are returned to the caller.
fn sync_medias<'a>(session: &mut Session, sdp: &'a Sdp) -> Result<Vec<&'a MediaLine>, String> {
    let mut new_lines = Vec::with_capacity(sdp.media_lines.len());

    let config = session.codec_config().clone();
    let session_exts = *session.exts();

    for (idx, m) in sdp.media_lines.iter().enumerate() {
        // First, match existing m-lines.
        match m.typ {
            MediaType::Application => {
                if let Some((_, index)) = session.app() {
                    if idx != *index {
                        return index_err(m.mid());
                    }
                    continue;
                }
            }
            MediaType::Audio | MediaType::Video => {
                if let Some(media) = session.media_by_mid_mut(m.mid()) {
                    if idx != media.index() {
                        return index_err(m.mid());
                    }

                    update_media(media, m, &config, &session_exts);
                    continue;
                }
            }
            _ => {
                continue;
            }
        }

        // Second, discover new m-lines.
        new_lines.push(m);
    }

    fn index_err<T>(mid: Mid) -> Result<T, String> {
        Err(format!("Changed order for m-line with mid: {mid}"))
    }

    Ok(new_lines)
}

/// Adds new m-lines as found in an offer or answer.
fn add_new_lines(
    session: &mut Session,
    new_lines: &[&MediaLine],
    need_open_event: bool,
) -> Result<(), String> {
    for m in new_lines {
        let idx = session.line_count();

        if m.typ.is_media() {
            let mut exts = *session.exts();
            exts.keep_same(&session.exts);

            // Update the PTs to match that of the remote.
            session.codec_config.update_pts(m);

            let mut media = MediaInner::from_remote_media_line(m, idx, exts);
            media.need_open_event = need_open_event;
            update_media(&mut media, m, &session.codec_config, &session.exts);

            session.add_media(media);
        } else if m.typ.is_channel() {
            session.set_app(m.mid(), idx)?;
        } else {
            return Err(format!(
                "New m-line is neither media nor channel: {}",
                m.mid()
            ));
        }
    }

    Ok(())
}

/// Update session level properties like
/// Extensions from offer or answer.
fn update_session(session: &mut Session, sdp: &Sdp) {
    let old = session.exts;

    let extmaps = sdp.media_lines.iter().flat_map(|m| m.extmaps());

    for (id, ext) in extmaps {
        session.exts.apply(id, ext);
    }

    if old != session.exts {
        info!("Updated session extensions: {:?}", session.exts);
    }

    // Does any m-line contain a a=rtcp-fb:xx transport-cc?
    let has_transport_cc = sdp
        .media_lines
        .iter()
        .any(|m| m.rtp_params().iter().any(|p| p.fb_transport_cc));

    // Is the session level sequence number enabled?
    let has_twcc_header = session
        .exts
        .id_of(Extension::TransportSequenceNumber)
        .is_some();

    // Since twcc feedback is session wide and not per m-line or pt, we enable it if
    // there are _any_ m-line with a a=rtcp-fb transport-cc parameter and the sequence
    // number header is enabled.
    if has_transport_cc && has_twcc_header {
        session.enable_twcc_feedback();
    }
}

/// Returns all media/channels as `AsMediaLine` trait.
fn as_media_lines(session: &Session) -> Vec<&dyn AsSdpMediaLine> {
    let mut v = vec![];

    if let Some(app) = session.app() {
        v.push(app as &dyn AsSdpMediaLine);
    }
    v.extend(session.medias().iter().map(|m| m as &dyn AsSdpMediaLine));
    v.sort_by_key(|f| f.index());
    v
}

fn update_media(
    media: &mut MediaInner,
    m: &MediaLine,
    config: &CodecConfig,
    session_exts: &ExtensionMap,
) {
    // Nack enabled for any payload
    let nack_enabled = m.rtp_params().iter().any(|p| p.fb_nack);
    if nack_enabled {
        media.enable_nack();
    }

    // Direction changes
    //
    // All changes come from the other side, either via an incoming OFFER
    // or a ANSWER from our OFFER. Either way, the direction is inverted to
    // how we have it locally.
    let new_dir = m.direction().invert();
    media.set_direction(new_dir);

    // Narrowing of PT
    let params: Vec<Pt> = m
        .rtp_params()
        .into_iter()
        .filter(|p| config.matches(p))
        .map(|p| p.pt())
        .collect();
    media.retain_pts(&params);

    // Narrowing of Rtp header extension mappings.
    let mut exts = ExtensionMap::empty();
    for (id, ext) in m.extmaps() {
        exts.set(id, ext);
    }
    exts.keep_same(session_exts);
    media.set_exts(exts);

    // SSRC changes
    // This will always be for ReceiverSource since any incoming a=ssrc line will be
    // about the remote side's SSRC.
    let infos = m.ssrc_info();
    for info in infos {
        let rx = media.get_or_create_source_rx(info.ssrc);

        if let Some(repairs) = info.repair {
            if rx.set_repairs(repairs) {
                media.set_equalize_sources();
            }
        }
    }

    // Simulcast configuration
    if let Some(s) = m.simulcast() {
        if s.is_munged {
            warn!("Not supporting simulcast via munging SDP");
        } else if media.simulcast().is_none() {
            // Invert before setting, since it has a recv and send config.
            media.set_simulcast(s.invert());
        }
    }
}

trait AsSdpMediaLine {
    fn mid(&self) -> Mid;
    fn msid(&self) -> Option<&Msid>;
    fn index(&self) -> usize;
    fn as_media_line(&self, attrs: Vec<MediaAttribute>) -> MediaLine;
}

impl AsSdpMediaLine for (Mid, usize) {
    fn mid(&self) -> Mid {
        self.0
    }
    fn msid(&self) -> Option<&Msid> {
        None
    }
    fn index(&self) -> usize {
        self.1
    }
    fn as_media_line(&self, mut attrs: Vec<MediaAttribute>) -> MediaLine {
        attrs.push(MediaAttribute::Mid(self.0));
        attrs.push(MediaAttribute::SctpPort(5000));
        attrs.push(MediaAttribute::MaxMessageSize(262144));

        MediaLine {
            typ: sdp::MediaType::Application,
            proto: Proto::Sctp,
            pts: vec![],
            bw: None,
            attrs,
        }
    }
}

impl AsSdpMediaLine for MediaInner {
    fn mid(&self) -> Mid {
        MediaInner::mid(self)
    }
    fn msid(&self) -> Option<&Msid> {
        Some(MediaInner::msid(self))
    }
    fn index(&self) -> usize {
        MediaInner::index(self)
    }
    fn as_media_line(&self, mut attrs: Vec<MediaAttribute>) -> MediaLine {
        if self.app_tmp {
            let app = (self.mid(), self.index());
            return app.as_media_line(attrs);
        }

        attrs.push(MediaAttribute::Mid(self.mid()));

        let audio = self.kind() == MediaKind::Audio;
        for (id, ext) in self.exts().iter(audio) {
            attrs.push(MediaAttribute::ExtMap { id, ext });
        }

        attrs.push(self.direction().into());
        attrs.push(MediaAttribute::Msid(self.msid().clone()));
        attrs.push(MediaAttribute::RtcpMux);

        for p in self.payload_params() {
            p.as_media_attrs(&mut attrs);
        }

        // The advertised payload types.
        let pts = self
            .payload_params()
            .iter()
            .flat_map(|c| [Some(c.pt()), c.resend].into_iter())
            .flatten()
            .collect();

        if let Some(s) = self.simulcast() {
            fn to_rids<'a>(
                gs: &'a SimulcastGroups,
                direction: &'static str,
            ) -> impl Iterator<Item = MediaAttribute> + 'a {
                gs.iter().flat_map(|g| g.iter()).filter_map(move |o| {
                    if let SimulcastOption::Rid(id) = o {
                        Some(MediaAttribute::Rid {
                            id: id.clone(),
                            direction,
                            pt: vec![],
                            restriction: vec![],
                        })
                    } else {
                        None
                    }
                })
            }
            attrs.extend(to_rids(&s.recv, "recv"));
            attrs.extend(to_rids(&s.send, "send"));
            attrs.push(MediaAttribute::Simulcast(s.clone()));
        }

        // Outgoing SSRCs
        let msid = format!("{} {}", self.msid().stream_id, self.msid().track_id);
        for ssrc in self.source_tx_ssrcs() {
            attrs.push(MediaAttribute::Ssrc {
                ssrc,
                attr: "cname".to_string(),
                value: self.cname().to_string(),
            });
            attrs.push(MediaAttribute::Ssrc {
                ssrc,
                attr: "msid".to_string(),
                value: msid.clone(),
            });
        }

        let count = self.source_tx_ssrcs().count();
        #[allow(clippy::comparison_chain)]
        if count == 2 {
            attrs.push(MediaAttribute::SsrcGroup {
                semantics: "FID".to_string(),
                ssrcs: self.source_tx_ssrcs().collect(),
            });
        } else if count > 2 {
            // TODO: handle simulcast
        }

        MediaLine {
            typ: self.kind().into(),
            proto: Proto::Srtp,
            pts,
            bw: None,
            attrs,
        }
    }
}

impl From<MediaKind> for MediaType {
    fn from(value: MediaKind) -> Self {
        match value {
            MediaKind::Audio => MediaType::Audio,
            MediaKind::Video => MediaType::Video,
        }
    }
}

struct AsSdpParams<'a, 'b> {
    pub candidates: &'a [Candidate],
    pub creds: &'a IceCreds,
    pub fingerprint: &'a Fingerprint,
    pub setup: Setup,
    pub pending: Option<&'b Changes>,
}

impl<'a, 'b> AsSdpParams<'a, 'b> {
    pub fn new(rtc: &'a Rtc, pending: Option<&'b Changes>) -> Self {
        AsSdpParams {
            candidates: rtc.ice.local_candidates(),
            creds: rtc.ice.local_credentials(),
            fingerprint: rtc.dtls.local_fingerprint(),
            setup: match rtc.dtls.is_active() {
                Some(true) => Setup::Active,
                Some(false) => Setup::Passive,
                None => Setup::ActPass,
            },
            pending,
        }
    }

    fn media_attributes(&self, include_candidates: bool) -> Vec<MediaAttribute> {
        use MediaAttribute::*;

        let mut v = if include_candidates {
            self.candidates
                .iter()
                .map(|c| Candidate(c.clone()))
                .collect()
        } else {
            vec![]
        };

        v.push(IceUfrag(self.creds.ufrag.clone()));
        v.push(IcePwd(self.creds.pass.clone()));
        v.push(IceOptions("trickle".into()));
        v.push(Fingerprint(self.fingerprint.clone()));
        v.push(Setup(self.setup));

        v
    }
}

impl fmt::Debug for SdpPendingOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdpPendingOffer").finish()
    }
}

impl Changes {
    pub fn take_new_channels(&mut self) -> Vec<(ChannelId, ChannelConfig)> {
        let mut v = vec![];

        if self.0.is_empty() {
            return v;
        }

        for i in (0..self.0.len()).rev() {
            if matches!(&self.0[i], Change::AddChannel(_)) {
                if let Change::AddChannel(id) = self.0.remove(i) {
                    v.push(id);
                }
            }
        }

        v
    }

    /// Tests the given lines (from answer) corresponds to changes.
    fn ensure_correct_answer(&self, lines: &[&MediaLine]) -> Option<String> {
        if self.count_new_medias() != lines.len() {
            return Some(format!(
                "Differing m-line count in offer vs answer: {} != {}",
                self.count_new_medias(),
                lines.len()
            ));
        }

        'next: for l in lines {
            let mid = l.mid();

            for m in &self.0 {
                use Change::*;
                match m {
                    AddMedia(v) if v.mid == mid => {
                        if !l.typ.is_media() {
                            return Some(format!(
                                "Answer m-line for mid ({}) is not of media type: {:?}",
                                mid, l.typ
                            ));
                        }
                        continue 'next;
                    }
                    AddApp(v) if *v == mid => {
                        if !l.typ.is_channel() {
                            return Some(format!(
                                "Answer m-line for mid ({}) is not a data channel: {:?}",
                                mid, l.typ
                            ));
                        }
                        continue 'next;
                    }
                    _ => {}
                }
            }

            return Some(format!("Mid in answer is not in offer: {mid}"));
        }

        None
    }

    fn count_new_medias(&self) -> usize {
        self.0
            .iter()
            .filter(|c| matches!(c, Change::AddMedia(_) | Change::AddApp(_)))
            .count()
    }

    pub fn as_new_medias<'a, 'b: 'a>(
        &'a self,
        index_start: usize,
        config: &'b CodecConfig,
        exts: &'b ExtensionMap,
    ) -> impl Iterator<Item = MediaInner> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(move |(idx, c)| c.as_new_media(index_start + idx, config, exts))
    }

    pub(crate) fn apply_to(&self, lines: &mut [MediaLine]) {
        for change in &self.0 {
            if let Change::Direction(mid, dir) = change {
                if let Some(line) = lines.iter_mut().find(|l| l.mid() == *mid) {
                    if let Some(dir_pos) = line.attrs.iter().position(|a| a.is_direction()) {
                        line.attrs[dir_pos] = (*dir).into();
                    }
                }
            }
        }
    }
}

impl Change {
    fn as_new_media(
        &self,
        index: usize,
        config: &CodecConfig,
        exts: &ExtensionMap,
    ) -> Option<MediaInner> {
        use Change::*;
        match self {
            AddMedia(v) => {
                // TODO can we avoid all this cloning?
                let mut add = v.clone();
                add.params = config.all_for_kind(v.kind).copied().collect();
                add.index = index;

                Some(MediaInner::from_add_media(add, *exts))
            }
            AddApp(mid) => Some(MediaInner::from_app_tmp(*mid, index)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::format::Codec;
    use crate::sdp::RtpMap;

    use super::*;

    fn resolve_pt(m_line: &MediaLine, needle: Pt) -> RtpMap {
        m_line
            .attrs
            .iter()
            .find_map(|attr| match attr {
                MediaAttribute::RtpMap { pt, value } if *pt == needle => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("Expected to find RtpMap for {needle}"))
    }

    #[test]
    fn test_out_of_order_error() {
        let mut rtc1 = Rtc::new();
        let mut rtc2 = Rtc::new();

        let mut change1 = rtc1.sdp_api();
        change1.add_channel("ch1".into());
        let (offer1, pending1) = change1.apply().unwrap();

        let mut change2 = rtc2.sdp_api();
        change2.add_channel("ch2".into());
        let (offer2, _) = change2.apply().unwrap();

        // invalidates pending1
        let _ = rtc1.sdp_api().accept_offer(offer2).unwrap();
        let answer2 = rtc2.sdp_api().accept_offer(offer1).unwrap();

        let r = rtc1.sdp_api().accept_answer(pending1, answer2);

        assert!(matches!(r, Err(RtcError::ChangesOutOfOrder)));
    }

    #[test]
    fn test_rtp_payload_priority() {
        let mut rtc1 = Rtc::builder()
            .clear_codecs()
            .enable_h264(true)
            .enable_vp8(true)
            .enable_vp9(true)
            .build();
        let mut rtc2 = Rtc::builder()
            .clear_codecs()
            .enable_vp8(true)
            .enable_h264(true)
            .build();

        let mut change1 = rtc1.sdp_api();
        change1.add_media(MediaKind::Video, Direction::SendOnly, None, None);
        let (offer1, _) = change1.apply().unwrap();

        let answer = rtc2.sdp_api().accept_offer(offer1).unwrap();
        assert_eq!(
            answer.media_lines.len(),
            1,
            "There should be one mline only"
        );

        let first_mline = &answer.media_lines[0];
        let first_pt = resolve_pt(first_mline, first_mline.pts[0]);

        assert_eq!(
            first_pt.codec, Codec::H264,
            "The first PT returned should be the highest priority PT from the offer that is supported."
        );

        let vp9_unsupported = first_mline
            .pts
            .iter()
            .any(|pt| resolve_pt(first_mline, *pt).codec == Codec::Vp9);

        assert!(
            !vp9_unsupported,
            "VP9 was not offered, so it should not be present in the answer"
        );
    }
}
