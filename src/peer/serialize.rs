use crate::sdp::{MediaAttribute, Sdp, Session, SessionAttribute};

use super::Peer;

// Keep in sync with below addition of dynamic attributes.
pub fn is_dynamic_media_attr(a: &MediaAttribute) -> bool {
    use MediaAttribute::*;
    matches!(
        a,
        IceUfrag(_)
            | IcePwd(_)
            | IceOptions(_)
            | Candidate(_)
            | EndOfCandidates
            | Fingerprint(_)
            | Setup(_)
    )
}

impl<T> Peer<T> {
    pub(crate) fn as_sdp(&self) -> Sdp {
        let creds = &self.ice_state.local_creds();

        let mut m_attrs = vec![
            MediaAttribute::IceUfrag(creds.username.clone()),
            MediaAttribute::IcePwd(creds.password.clone()),
        ];
        let mut s_attrs = vec![
            SessionAttribute::IceUfrag(creds.username.clone()),
            SessionAttribute::IcePwd(creds.password.clone()),
        ];

        if self.config.ice_lite {
            s_attrs.push(SessionAttribute::IceLite);
        }
        if !self.config.disable_trickle_ice {
            m_attrs.push(MediaAttribute::IceOptions("trickle".to_string()));
            s_attrs.push(SessionAttribute::IceOptions("trickle".to_string()));
        }

        for c in self.ice_state.local_candidates() {
            m_attrs.push(MediaAttribute::Candidate(c.clone()));
            s_attrs.push(SessionAttribute::Candidate(c.clone()));
        }

        if self.ice_state.local_end_of_candidates() {
            m_attrs.push(MediaAttribute::EndOfCandidates);
            s_attrs.push(SessionAttribute::EndOfCandidates);
        }

        let fp = self.dtls_state.local_fingerprint();
        m_attrs.push(MediaAttribute::Fingerprint(fp.clone()));
        m_attrs.push(MediaAttribute::Setup(self.setup));

        s_attrs.push(SessionAttribute::Fingerprint(fp.clone()));
        s_attrs.push(SessionAttribute::Setup(self.setup));

        s_attrs.push(SessionAttribute::Group {
            typ: "BUNDLE".into(),
            mids: self.media.iter().map(|m| m.mid()).collect(),
        });

        let new_lines = if let Some(pending) = &self.pending_changes {
            pending.new_media_lines().collect()
        } else {
            vec![]
        };

        let all_lines = self.media.iter().chain(new_lines.iter());

        let media_lines = all_lines
            .map(|m| m.media_line())
            .cloned()
            .map(|mut m| {
                // Splice in the m_attrs first in the attributes
                m.attrs = m_attrs
                    .clone()
                    .into_iter()
                    .chain(m.attrs.into_iter())
                    .collect();
                m
            })
            .collect();

        let sdp = Sdp {
            session: Session {
                id: self.session_id,
                bw: None,
                attrs: s_attrs,
            },
            media_lines,
        };

        if let Some(err) = sdp.check_consistent() {
            panic!("{}", err);
        }

        sdp
    }
}
