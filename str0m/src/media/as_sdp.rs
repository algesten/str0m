use dtls::Fingerprint;
use ice::{Candidate, IceCreds};
use rtp::{MLineIdx, Mid};
use sdp::{MediaAttribute, MediaLine, MediaType, Proto, Sdp, SessionAttribute, Setup};

use crate::change::Changes;

use super::{Channel, Media, MediaKind, Session};

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
            // Merge media lines and data channels.
            let mut v = self
                .channels
                .iter()
                .map(|m| &*m as &dyn AsMediaLine)
                .chain(self.media.iter().map(|m| &*m as &dyn AsMediaLine))
                .collect::<Vec<_>>();

            // Sort on the order they been added to the SDP.
            v.sort_by_key(|m| *m.index());

            // Turn into sdp::MediaLine (m-line).
            let mut lines = v
                .iter()
                .map(|m| {
                    let idx = m.index();
                    // Candidates should only be in the first BUNDLE mid
                    let include_candidates = *idx == 0;
                    let attrs = params.media_attributes(include_candidates);
                    m.as_media_line(attrs)
                })
                .collect();

            // if we have pending changes, this is an offer and we need
            // to modify existing lines and add new lines.
            if let Some(pending) = params.pending {
                pending.apply_to_sdp(&mut lines);
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

trait AsMediaLine {
    fn mid(&self) -> Mid;
    fn index(&self) -> MLineIdx;
    fn as_media_line(&self, attrs: Vec<MediaAttribute>) -> MediaLine;
}

impl AsMediaLine for Channel {
    fn mid(&self) -> Mid {
        self.mid()
    }
    fn index(&self) -> MLineIdx {
        self.m_line_idx()
    }
    fn as_media_line(&self, mut attrs: Vec<MediaAttribute>) -> MediaLine {
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
    fn as_media_line(&self, mut attrs: Vec<MediaAttribute>) -> MediaLine {
        attrs.push(MediaAttribute::Mid(self.mid()));
        // extmaps here
        attrs.push(self.direction().into());
        // a=msid here
        attrs.push(MediaAttribute::RtcpMux);

        for p in self.codecs() {
            p.inner().to_media_attrs(&mut attrs);
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

impl Changes {
    fn apply_to_sdp(&self, lines: &mut Vec<MediaLine>) {
        todo!()
    }
}
