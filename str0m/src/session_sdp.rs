use dtls::Fingerprint;
use ice::{Candidate, IceCreds};
use rtp::{Extensions, Mid};
use sdp::{Answer, MediaAttribute, MediaLine, MediaType};
use sdp::{Offer, Proto, Sdp, SessionAttribute, Setup};

use crate::change::{Change, Changes};
use crate::media::{App, CodecConfig, MediaKind};
use crate::session::{only_media_mut, MediaOrApp};
use crate::RtcError;

use super::{Media, Session};

pub struct AsSdpParams<'a> {
    pub candidates: &'a [Candidate],
    pub creds: &'a IceCreds,
    pub fingerprint: &'a Fingerprint,
    pub setup: Setup,
    pub pending: &'a Option<Changes>,
}

impl<'a> AsSdpParams<'a> {
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

impl Session {
    pub fn as_sdp(&self, params: AsSdpParams) -> Sdp {
        let (media_lines, mids) = {
            let mut v = self.as_media_lines().collect::<Vec<_>>();

            let mut new_lines = vec![];

            // When creating new m-lines from the pending changes, the m-line index starts from this.
            let new_index_start = v.len();

            // If there are additions in the pending changes, prepend them now.
            if let Some(pending) = params.pending {
                new_lines = pending
                    .as_new_m_lines(new_index_start, self.codec_config())
                    .collect();
            }

            // Add potentially new m-lines to the existing ones.
            v.extend(new_lines.iter().map(|n| n as &dyn AsMediaLine));

            // Session level extension map.
            let exts = self.exts();

            // Turn into sdp::MediaLine (m-line).
            let mut lines = v
                .iter()
                .map(|m| {
                    // Candidates should only be in the first BUNDLE mid
                    let include_candidates = m.index() == 0;

                    let attrs = params.media_attributes(include_candidates);

                    m.as_media_line(attrs, exts)
                })
                .collect::<Vec<_>>();

            if let Some(pending) = params.pending {
                pending.apply_to(&mut lines);
            }

            // Mids go into the session part of the SDP.
            let mids = v.iter().map(|m| m.mid()).collect();

            (lines, mids)
        };

        Sdp {
            session: sdp::Session {
                id: self.id(),
                bw: None,
                attrs: vec![
                    SessionAttribute::Group {
                        typ: "BUNDLE".into(),
                        mids,
                    },
                    // a=msid-semantic: WMS
                ],
            },
            media_lines,
        }
    }

    pub fn apply_offer(&mut self, offer: Offer) -> Result<(), RtcError> {
        offer.assert_consistency()?;

        self.update_session_extmaps(&offer)?;

        let new_lines = self.sync_m_lines(&offer).map_err(RtcError::RemoteSdp)?;

        self.add_new_lines(&new_lines)
            .map_err(RtcError::RemoteSdp)?;

        // For new lines appearing in an offer, we just add the corresponding amount of SSRC
        // that we find in the incoming line. This is probably always correct. If there is simulcast
        // configured, we (probably) have simulcast in both directions. If we have RTX, we have it
        // in both directions.
        for l in new_lines.iter().filter(|l| l.typ.is_media()) {
            let ssrcs: Vec<_> = l
                .ssrc_info()
                .iter()
                .map(|i| (self.new_ssrc(), i.repair.is_some()))
                .collect();

            let media = self
                .get_media(l.mid())
                .expect("Media to be added for new m-line");

            for (ssrc, is_rtx) in ssrcs {
                media.add_source_tx(ssrc, is_rtx);
            }
        }

        Ok(())
    }

    pub fn apply_answer(&mut self, pending: Changes, answer: Answer) -> Result<(), RtcError> {
        answer.assert_consistency()?;

        self.update_session_extmaps(&answer)?;

        let new_lines = self.sync_m_lines(&answer).map_err(RtcError::RemoteSdp)?;

        // The new_lines from the answer must correspond to what we sent in the offer.
        if let Some(err) = pending.ensure_correct_answer(&new_lines) {
            return Err(RtcError::RemoteSdp(err));
        }

        self.add_new_lines(&new_lines)
            .map_err(RtcError::RemoteSdp)?;

        // For pending AddMedia, we have outgoing SSRC communicated that needs to be added.
        for change in pending.0 {
            let add_media = match change {
                Change::AddMedia(v) => v,
                _ => continue,
            };

            let media = self
                .get_media(add_media.mid)
                .expect("Media to be added for pending mid");

            // the cname has already been communicated in the offer, we need to kep it the same
            // once the m-line is created.
            media.set_cname(add_media.cname);

            for (ssrc, is_rtx) in add_media.ssrcs {
                media.add_source_tx(ssrc, is_rtx);
            }
        }

        Ok(())
    }

    /// Compares m-lines in Sdp with that already in the session.
    ///
    /// * Existing m-lines can apply changes (such as direction change).
    /// * New m-lines are returned to the caller.
    fn sync_m_lines<'a>(&mut self, sdp: &'a Sdp) -> Result<Vec<&'a MediaLine>, String> {
        let mut new_lines = Vec::new();

        // SAFETY: CodecConfig is read only and not interfering with self.get_media.
        let config = unsafe {
            let ptr = &self.codec_config as *const CodecConfig;
            &*ptr
        };

        for (idx, m) in sdp.media_lines.iter().enumerate() {
            if let Some(media) = self.get_media(m.mid()) {
                if idx != media.index() {
                    return index_err(m.mid());
                }

                media.apply_changes(m, config);
            } else if let Some(app) = self.app() {
                if idx != app.index() {
                    return index_err(m.mid());
                }

                app.apply_changes(m);
            } else {
                new_lines.push(m);
            }
        }

        fn index_err<T>(mid: Mid) -> Result<T, String> {
            Err(format!("Changed order for m-line with mid: {}", mid))
        }

        Ok(new_lines)
    }

    /// Adds new m-lines as found in an offer or answer.
    fn add_new_lines(&mut self, new_lines: &[&MediaLine]) -> Result<(), String> {
        for m in new_lines {
            let idx = self.media.len();

            if m.typ.is_media() {
                let media = (*m, idx).into();
                self.media.push(MediaOrApp::Media(media));

                let media = only_media_mut(&mut self.media).last().unwrap();
                media.apply_changes(m, &self.codec_config);
            } else if m.typ.is_channel() {
                let app = (m.mid(), idx).into();
                self.media.push(MediaOrApp::App(app));

                let chan = self.app().unwrap();
                chan.apply_changes(m);
            } else {
                return Err(format!(
                    "New m-line is neither media nor channel: {}",
                    m.mid()
                ));
            }
        }

        Ok(())
    }

    /// Update session level Extensions.
    fn update_session_extmaps(&mut self, sdp: &Sdp) -> Result<(), RtcError> {
        let extmaps = sdp
            .media_lines
            .iter()
            .map(|m| m.extmaps())
            .flatten()
            // Only keep supported extensions
            .filter(|x| x.ext.is_supported());

        for x in extmaps {
            self.exts.apply_mapping(&x);
        }

        Ok(())
    }

    /// Returns all media/channels as `AsMediaLine` trait.
    pub fn as_media_lines(&self) -> impl Iterator<Item = &dyn AsMediaLine> {
        self.media.iter().map(|m| m as &dyn AsMediaLine)
    }
}

pub trait AsMediaLine {
    fn mid(&self) -> Mid;
    fn index(&self) -> usize;
    fn as_media_line(&self, attrs: Vec<MediaAttribute>, exts: &Extensions) -> MediaLine;
}

impl AsMediaLine for App {
    fn mid(&self) -> Mid {
        self.mid()
    }
    fn index(&self) -> usize {
        self.index()
    }
    fn as_media_line(&self, mut attrs: Vec<MediaAttribute>, _exts: &Extensions) -> MediaLine {
        attrs.push(MediaAttribute::Mid(self.mid()));
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

impl AsMediaLine for Media {
    fn mid(&self) -> Mid {
        self.mid()
    }
    fn index(&self) -> usize {
        self.index()
    }
    fn as_media_line(&self, mut attrs: Vec<MediaAttribute>, exts: &Extensions) -> MediaLine {
        attrs.push(MediaAttribute::Mid(self.mid()));

        let audio = self.kind() == MediaKind::Audio;
        for e in exts.into_extmap(audio) {
            attrs.push(MediaAttribute::ExtMap(e));
        }

        attrs.push(self.direction().into());
        attrs.push(MediaAttribute::Msid(self.msid().clone()));
        attrs.push(MediaAttribute::RtcpMux);

        for p in self.codecs() {
            p.inner().to_media_attrs(&mut attrs);
        }

        // The advertised payload types.
        let pts = self
            .codecs()
            .iter()
            .flat_map(|c| [Some(c.pt()), c.pt_rtx()].into_iter())
            .filter_map(|c| c)
            .collect();

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

impl AsMediaLine for MediaOrApp {
    fn mid(&self) -> Mid {
        use MediaOrApp::*;
        match self {
            Media(v) => v.mid(),
            App(v) => v.mid(),
        }
    }
    fn index(&self) -> usize {
        use MediaOrApp::*;
        match self {
            Media(v) => v.index(),
            App(v) => v.index(),
        }
    }
    fn as_media_line(&self, attrs: Vec<sdp::MediaAttribute>, exts: &Extensions) -> MediaLine {
        use MediaOrApp::*;
        match self {
            Media(v) => v.as_media_line(attrs, exts),
            App(v) => v.as_media_line(attrs, exts),
        }
    }
}

impl Into<MediaType> for MediaKind {
    fn into(self) -> MediaType {
        match self {
            MediaKind::Audio => MediaType::Audio,
            MediaKind::Video => MediaType::Video,
        }
    }
}
