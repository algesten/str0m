use dtls::Fingerprint;
use ice::{Candidate, IceCreds};
use rtp::{Extensions, MLineIdx, Mid};
use sdp::{MediaAttribute, MediaLine, MediaType, Proto, Sdp, SessionAttribute, Setup};

use crate::change::Changes;
use crate::media::MediaKind;

use super::{Channel, Media, Session};

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
    /// Merge media lines and data channels.
    pub fn as_media_lines(&self) -> impl Iterator<Item = &dyn AsMediaLine> {
        self.channels
            .iter()
            .map(|m| &*m as &dyn AsMediaLine)
            .chain(self.media.iter().map(|m| &*m as &dyn AsMediaLine))
    }

    pub fn as_sdp(&self, params: AsSdpParams) -> Sdp {
        let (media_lines, mids) = {
            let mut v = self.as_media_lines().collect::<Vec<_>>();

            // Sort on the order they been added to the SDP.
            v.sort_by_key(|m| *m.index());

            let mut new_lines = vec![];

            // If there are additions in the pending changes, prepend them now.
            if let Some(pending) = params.pending {
                new_lines = pending.as_new_m_lines(&self.codec_config).collect();
            }

            // Add potentially new m-lines to the existing ones.
            v.extend(new_lines.iter().map(|n| n as &dyn AsMediaLine));

            // Session level extension map.
            let exts = &self.exts;

            // Turn into sdp::MediaLine (m-line).
            let mut lines = v
                .iter()
                .map(|m| {
                    // Candidates should only be in the first BUNDLE mid
                    let include_candidates = {
                        let idx = m.index();
                        *idx == 0
                    };

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
                id: self.id,
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
}

pub trait AsMediaLine {
    fn mid(&self) -> Mid;
    fn index(&self) -> MLineIdx;
    fn as_media_line(&self, attrs: Vec<MediaAttribute>, exts: &Extensions) -> MediaLine;
}

impl AsMediaLine for Channel {
    fn mid(&self) -> Mid {
        self.mid()
    }
    fn index(&self) -> MLineIdx {
        self.m_line_idx()
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
    fn index(&self) -> MLineIdx {
        self.m_line_idx()
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
            pts: vec![],
            bw: None,
            attrs,
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
