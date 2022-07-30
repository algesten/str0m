use crate::sdp::{MediaAttribute, Sdp, Session, SessionAttribute};

use super::Peer;

impl<T> Peer<T> {
    pub(crate) fn as_local_sdp(&self) -> Sdp {
        let secrets = vec![MediaAttribute::IceUfrag(
            self.stun_state.local_creds.username.clone(),
        )];

        let sdp = Sdp {
            session: Session {
                id: self.session_id,
                bw: None,
                attrs: vec![SessionAttribute::Group {
                    typ: "BUNDLE".into(),
                    mids: self
                        .media
                        .iter()
                        .filter(|m| m.include_in_local_sdp())
                        .map(|m| m.mid().to_string())
                        .collect(),
                }],
            },
            media_lines: self
                .media
                .iter()
                .filter(|m| m.include_in_local_sdp())
                .map(|m| m.media_line().clone())
                .collect(),
        };

        if let Some(err) = sdp.check_consistent() {
            panic!("{}", err);
        }

        sdp
    }

    pub(crate) fn as_remote_sdp(&self) -> Sdp {
        let sdp = Sdp {
            session: Session {
                id: self.session_id,
                bw: None,
                attrs: vec![SessionAttribute::Group {
                    typ: "BUNDLE".into(),
                    mids: self
                        .media
                        .iter()
                        .filter(|m| m.include_in_remote_sdp())
                        .map(|m| m.mid().to_string())
                        .collect(),
                }],
            },
            media_lines: self
                .media
                .iter()
                .filter(|m| m.include_in_remote_sdp())
                .map(|m| m.media_line().clone())
                .collect(),
        };

        if let Some(err) = sdp.check_consistent() {
            panic!("{}", err);
        }

        sdp
    }
}
