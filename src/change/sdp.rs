//! Strategy that amends the [`Rtc`] via SDP OFFER/ANSWER negotiation.

use std::fmt;

use crate::change::{Change, Changes};
use crate::channel::ChannelId;
use crate::dtls::Fingerprint;
use crate::ice::{Candidate, IceCreds};
use crate::media::MediaInner;
use crate::media::{CodecConfig, MediaKind, PayloadParams, Source};
use crate::rtp::{Extension, Extensions, Mid, Pt};
use crate::sctp::DcepOpen;
use crate::sdp::{self, MediaAttribute, MediaLine, MediaType, Sdp};
use crate::sdp::{Proto, SessionAttribute, Setup};
use crate::sdp::{SimulcastGroups, SimulcastOption};
use crate::session::Session;
use crate::Rtc;
use crate::RtcError;

use super::{ChangeStrategy, ChangesWrapper};

pub use crate::sdp::{SdpAnswer, SdpOffer};

/// Sdp change strategy.
///
/// Provides the Offer/Answer dance.
pub struct SdpStrategy;

impl ChangeStrategy for SdpStrategy {
    type Apply = Option<(SdpOffer, SdpPendingOffer)>;

    fn apply(&self, change_id: usize, rtc: &mut Rtc, changes: ChangesWrapper) -> Self::Apply {
        let changes = changes.0;
        let requires_negotiation = changes.iter().any(requires_negotiation);

        if requires_negotiation {
            let offer = create_offer(rtc, &changes);
            let pending = SdpPendingOffer { change_id, changes };
            Some((offer, pending))
        } else {
            rtc.apply_direct_changes(changes);
            None
        }
    }
}

impl SdpStrategy {
    /// Accept an [`SdpOffer`] from the remote peer. If this call returns successfully, the
    /// changes will have been made to the session. The resulting [`SdpAnswer`] should be
    /// sent to the remote peer.
    ///
    /// <b>Note. Pending changes from a previous non-completed [`ChangeSet`][super::ChangeSet] will be
    /// considered rolled back when calling this function.</b>
    ///
    /// The incoming SDP is validated in various ways which can cause this call to fail.
    /// Example of such problems would be an SDP without any m-lines, missing `a=fingerprint`
    /// or if `a=group` doesn't match the number of m-lines.
    ///
    /// ```no_run
    /// # use str0m::Rtc;
    /// # use str0m::change::{SdpOffer, SdpStrategy};
    /// // obtain offer from remote peer.
    /// let json_offer: &[u8] = todo!();
    /// let offer: SdpOffer = serde_json::from_slice(json_offer).unwrap();
    ///
    /// let mut rtc = Rtc::new();
    /// let answer = SdpStrategy.accept_offer(&mut rtc, offer).unwrap();
    ///
    /// // send json_answer to remote peer.
    /// let json_answer = serde_json::to_vec(&answer).unwrap();
    /// ```
    pub fn accept_offer(&self, rtc: &mut Rtc, offer: SdpOffer) -> Result<SdpAnswer, RtcError> {
        // Invalidate any outstanding PendingOffer.
        rtc.next_change_id();

        if offer.media_lines.is_empty() {
            return Err(RtcError::RemoteSdp("No m-lines in offer".into()));
        }

        add_ice_details(rtc, &offer)?;

        if rtc.remote_fingerprint.is_none() {
            if let Some(f) = offer.fingerprint() {
                rtc.remote_fingerprint = Some(f);
            } else {
                rtc.disconnect();
                return Err(RtcError::RemoteSdp("missing a=fingerprint".into()));
            }
        }

        if !rtc.dtls.is_inited() {
            // The side that makes the first offer is the controlling side.
            rtc.ice.set_controlling(false);
        }

        // If we receive an offer, we are not allowed to answer with actpass.
        if rtc.setup == Setup::ActPass {
            let remote_setup = offer.setup().unwrap_or(Setup::Active);
            rtc.setup = if remote_setup == Setup::ActPass {
                Setup::Passive
            } else {
                remote_setup.invert()
            };
            debug!(
                "Change setup for answer: {} -> {}",
                Setup::ActPass,
                rtc.setup
            );
        }

        // Ensure setup=active/passive is corresponding remote and init dtls.
        init_dtls(rtc, &offer)?;

        // Modify session with offer
        apply_offer(&mut rtc.session, offer)?;

        // Handle potentially new m=application line.
        rtc.init_sctp();

        let params = AsSdpParams::new(rtc, None);
        let sdp = as_sdp(&rtc.session, params);

        Ok(sdp.into())
    }
}

/// Pending offer from a previous [`Rtc::create_change_set()`] call.
///
/// This allows us to either accept a remote answer, or rollback the changes.
///
/// ```no_run
/// # use str0m::Rtc;
/// # use str0m::media::{MediaKind, Direction};
/// # use str0m::change::{SdpStrategy, SdpAnswer};
/// let mut rtc = Rtc::new();
///
/// let mut changes = rtc.create_change_set(SdpStrategy);
/// let mid = changes.add_media(MediaKind::Audio, Direction::SendOnly, None);
/// let (offer, pending) = changes.apply().unwrap();
///
/// // send offer to remote peer, receive answer back
/// let answer: SdpAnswer = todo!();
///
/// pending.accept_answer(&mut rtc, answer).unwrap();
/// ```
pub struct SdpPendingOffer {
    change_id: usize,
    changes: Changes,
}

impl SdpPendingOffer {
    /// Accept an answer to a previously created [`SdpOffer`].
    ///
    /// This function returns an [`RtcError::ChangesOutOfOrder`] if we have created and applied another
    /// [`ChangeSet`][super::ChangeSet] before calling this. The same also happens if we use
    /// [`SdpStrategy::accept_offer()`] before using this pending instance.
    ///
    /// ```no_run
    /// # use str0m::Rtc;
    /// # use str0m::media::{MediaKind, Direction};
    /// # use str0m::change::{SdpStrategy, SdpAnswer};
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.create_change_set(SdpStrategy);
    /// let mid = changes.add_media(MediaKind::Audio, Direction::SendOnly, None);
    /// let (offer, pending) = changes.apply().unwrap();
    ///
    /// // send offer to remote peer, receive answer back
    /// let answer: SdpAnswer = todo!();
    ///
    /// pending.accept_answer(&mut rtc, answer).unwrap();
    /// ```
    pub fn accept_answer(mut self, rtc: &mut Rtc, answer: SdpAnswer) -> Result<(), RtcError> {
        if !rtc.is_correct_change_id(self.change_id) {
            return Err(RtcError::ChangesOutOfOrder);
        }

        add_ice_details(rtc, &answer)?;

        // Ensure setup=active/passive is corresponding remote and init dtls.
        init_dtls(rtc, &answer)?;

        if rtc.remote_fingerprint.is_none() {
            if let Some(f) = answer.fingerprint() {
                rtc.remote_fingerprint = Some(f);
            } else {
                rtc.disconnect();
                return Err(RtcError::RemoteSdp("missing a=fingerprint".into()));
            }
        }

        // Split out new channels, since that is not handled by the Session.
        let new_channels = self.changes.take_new_channels();

        // Modify session with answer
        apply_answer(&mut rtc.session, self.changes, answer)?;

        // Handle potentially new m=application line.
        rtc.init_sctp();

        for (id, dcep) in new_channels {
            rtc.sctp.open_stream(*id, dcep);
        }

        Ok(())
    }

    /// Abort these pending changes.
    pub fn rollback(self) {
        // TODO: some Rtc state to keep track of that we don't apply
        // rolled back pending.
    }
}

fn requires_negotiation(c: &Change) -> bool {
    match c {
        Change::AddMedia(_) => true,
        Change::AddApp(_) => true,
        Change::AddChannel(_, _) => false,
        Change::Direction(_, _) => true,
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
    if let Some(remote_setup) = remote_sdp.setup() {
        rtc.init_dtls(remote_setup)?;
    } else {
        warn!("Missing a=setup line");
    }

    Ok(())
}

fn as_sdp(session: &Session, params: AsSdpParams) -> Sdp {
    let (media_lines, mids) = {
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

        (lines, mids)
    };

    let mut attrs = vec![
        SessionAttribute::Group {
            typ: "BUNDLE".into(),
            mids,
        },
        // a=msid-semantic: WMS
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

    for x in extmaps {
        session.exts.apply_mapping(&x);
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
    session_exts: &Extensions,
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
        .map(PayloadParams::new)
        .filter(|p| config.matches(p))
        .map(|p| p.pt())
        .collect();
    media.retain_pts(&params);

    // Narrowing of Rtp header extension mappings.
    let mut exts = Extensions::new();
    for x in m.extmaps() {
        exts.set_mapping(x);
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
    fn index(&self) -> usize;
    fn as_media_line(&self, attrs: Vec<MediaAttribute>) -> MediaLine;
}

impl AsSdpMediaLine for (Mid, usize) {
    fn mid(&self) -> Mid {
        self.0
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
        for e in self.exts().as_extmap(audio) {
            attrs.push(MediaAttribute::ExtMap(e));
        }

        attrs.push(self.direction().into());
        attrs.push(MediaAttribute::Msid(self.msid().clone()));
        attrs.push(MediaAttribute::RtcpMux);

        for p in self.payload_params() {
            p.inner().as_media_attrs(&mut attrs);
        }

        // The advertised payload types.
        let pts = self
            .payload_params()
            .iter()
            .flat_map(|c| [Some(c.pt()), c.pt_rtx()].into_iter())
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
            setup: rtc.setup,
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
    pub fn take_new_channels(&mut self) -> Vec<(ChannelId, DcepOpen)> {
        let mut v = vec![];

        if self.0.is_empty() {
            return v;
        }

        for i in (0..self.0.len()).rev() {
            if matches!(&self.0[i], Change::AddChannel(_, _)) {
                if let Change::AddChannel(id, dcep) = self.0.remove(i) {
                    v.push((id, dcep));
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
        exts: &'b Extensions,
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
        exts: &Extensions,
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
    use super::*;

    #[test]
    fn test_out_of_order_error() {
        let mut rtc1 = Rtc::new();
        let mut rtc2 = Rtc::new();

        let mut change1 = rtc1.create_change_set(SdpStrategy);
        change1.add_channel("ch1".into());
        let (offer1, pending1) = change1.apply().unwrap();

        let mut change2 = rtc2.create_change_set(SdpStrategy);
        change2.add_channel("ch2".into());
        let (offer2, _) = change2.apply().unwrap();

        // invalidates pending1
        let _ = SdpStrategy.accept_offer(&mut rtc1, offer2).unwrap();
        let answer2 = SdpStrategy.accept_offer(&mut rtc2, offer1).unwrap();

        let r = pending1.accept_answer(&mut rtc1, answer2);

        assert!(matches!(r, Err(RtcError::ChangesOutOfOrder)));
    }
}
