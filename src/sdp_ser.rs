use crate::format::select_formats;
use crate::media::Media;
use crate::media::MediaId;
use crate::media::MediaKind;
use crate::peer::IceCreds;
use crate::peer::LocalInfo;
use crate::peer::Peer;
use crate::sdp::*;
use crate::util::VecExt;
use crate::{Error, ErrorKind};

impl Peer {
    pub fn apply_remote_sdp(&mut self, sdp: &Sdp) -> Result<(), Error> {
        self.remote_id = sdp.session.id.clone();

        for m in &sdp.media {
            let mid = m.mid();

            let media = self.media.find_or_append(
                |m| m.media_id.0 == mid,
                || Media::new(MediaId(mid.to_string())),
            );

            media.apply_remote_sdp(m, sdp)?;
        }

        Ok(())
    }

    pub fn create_local_sdp(&self) -> Sdp {
        let mut attrs = vec![];

        if !self.media.is_empty() {
            attrs.push(SessionAttribute::Group {
                typ: "BUNDLE".to_string(), // BUNDLE, LS etc
                mids: self.media.iter().map(|m| m.media_id.0.clone()).collect(),
            });
            //            SessionAttribute::Unused("msid-semantic: WMS".to_string()),
        }

        let sdp = Sdp {
            session: Session {
                id: self.local_id.clone(),
                bw: None,
                attrs,
            },
            media: self
                // the order is defined in mid_order
                .media
                .iter()
                .map(|m| m.as_local_sdp(&self.local))
                .collect(),
        };

        // ensure what we created is correct
        for m in &sdp.media {
            if let Some(err) = m.check_consistent() {
                panic!("Bad create_sdp: {}", err);
            }
        }

        sdp
    }
}

impl Media {
    pub fn apply_remote_sdp(&mut self, m: &MediaDesc, sdp: &Sdp) -> Result<(), Error> {
        let mid = m.mid();

        self.direction = m.direction().flip();

        self.kind = MediaKind::from_type(&m.typ);

        self.restrictions = m.restrictions();
        self.simulcast = m.simulcast().map(|s| s.flip());

        // Construct all formats.
        let all_formats = m.formats(&self.restrictions);

        // Only keep the formats we intend to use.
        self.formats = select_formats(all_formats);

        let uname = m
            .attrs
            .username()
            .or_else(|| sdp.session.attrs.username())
            .ok_or_else(|| err!(ErrorKind::SdpApply, "SDP missing username for mid: {}", mid))?;

        let passw = m
            .attrs
            .password()
            .or_else(|| sdp.session.attrs.password())
            .ok_or_else(|| err!(ErrorKind::SdpApply, "SDP missing password for mid: {}", mid,))?;

        let ice_creds = IceCreds {
            username: uname.to_string(),
            password: passw.to_string(),
        };
        self.ice_creds = ice_creds;

        let fingr = m
            .attrs
            .fingerprint()
            .or_else(|| sdp.session.attrs.fingerprint())
            .ok_or_else(|| {
                err!(
                    ErrorKind::SdpApply,
                    "SDP missing fingerprint for mid: {}",
                    mid,
                )
            })?;

        self.fingerprint = fingr.clone();

        let extmaps = m
            .attrs
            .extmaps()
            .into_iter()
            .filter(|e| e.ext_type.is_supported())
            .collect();
        self.extmaps = extmaps;

        // Pre-create the ingress needed. This should not be needed if we use "modern"
        // unified plan where there is no a=ssrc sent. However, only with chrome
        // simulcast do we see a=rid lines as an alternative to match up format
        // with a specific SSRC.
        {
            // These SSRC need pre-instantiating.
            for ssrc_info in m.ssrc_info() {
                let ssrc = ssrc_info.ssrc;

                debug!("[pre] Associate SSRC {} with {:?}", ssrc, self.media_id);
                let ingress = self.ingress_create_ssrc(ssrc);

                if let Some(repaired_ssrc) = ssrc_info.repaired_ssrc {
                    debug!("[pre] SSRC {} repairs {}", ssrc, repaired_ssrc);
                    ingress.repaired_ssrc = Some(repaired_ssrc);
                }
            }
        }

        Ok(())
    }

    pub fn as_local_sdp(&self, local: &LocalInfo) -> MediaDesc {
        let map_no: Vec<_> = self.formats.iter().map(|f| f.map_no).collect();

        let attrs = self.as_local_sdp_attrs(local);

        MediaDesc {
            typ: self.kind.as_sdp_type(),
            proto: self.kind.as_sdp_proto(),
            map_no,
            bw: None,
            attrs,
        }
    }

    fn as_local_sdp_attrs(&self, local: &LocalInfo) -> Vec<MediaAttribute> {
        let mut ret = vec![MediaAttribute::Rtcp("9 IN IP4 0.0.0.0".to_string())];

        for cand in &local.candidates {
            ret.push(MediaAttribute::Candidate(cand.clone()));
        }

        ret.append(&mut vec![
            MediaAttribute::IceUfrag(local.ice_creds.username.clone()),
            MediaAttribute::IcePwd(local.ice_creds.password.clone()),
            // a=ice-options:trickle
            MediaAttribute::Fingerprint(local.fingerprint.clone()),
            MediaAttribute::Setup("passive".to_string()),
            MediaAttribute::Mid(self.media_id.0.clone()),
        ]);

        // a=extmap
        for e in &self.extmaps {
            ret.push(MediaAttribute::ExtMap(e.clone()));
        }

        match self.direction {
            crate::media::Direction::SendOnly => ret.push(MediaAttribute::SendOnly),
            crate::media::Direction::RecvOnly => ret.push(MediaAttribute::RecvOnly),
            crate::media::Direction::SendRecv => ret.push(MediaAttribute::SendRecv),
            crate::media::Direction::Inactive => ret.push(MediaAttribute::Inactive),
        }

        // do we need a=msid here?
        ret.push(MediaAttribute::RtcpMux);
        ret.push(MediaAttribute::RtcpRsize);

        for f in &self.formats {
            ret.push(f.as_rtpmap());
            f.append_rtcp_fp(&mut ret);
            if !f.fmtp.is_empty() {
                ret.push(MediaAttribute::Fmtp {
                    map_no: f.map_no,
                    values: f.fmtp.clone(),
                });
            }
        }

        for r in &self.restrictions {
            ret.push(r.to_media_attr());
        }

        if let Some(s) = &self.simulcast {
            ret.push(MediaAttribute::Simulcast(s.clone()));
        }

        // See if we can get away with not sending a=ssrc lines back.
        //
        // // a=ssrc-group:FID <ssrc> <ssrc>
        // let fid = self
        //     .formats
        //     .iter()
        //     .filter_map(|f| f.ssrc_info.as_ref())
        //     .map(|f| f.ssrc)
        //     .collect::<Vec<_>>();
        // if fid.len() >= 2 {
        //     ret.push(MediaAttribute::SsrcGroup {
        //         semantics: "FID".to_string(),
        //         ssrcs: fid,
        //     });
        // }
        // for SsrcInfo { ssrc, cname } in self.formats.iter().filter_map(|f| f.ssrc_info.as_ref()) {
        //     ret.push(MediaAttribute::Ssrc {
        //         ssrc: *ssrc,
        //         attr: "cname".to_string(),
        //         value: cname.to_string(),
        //     });
        // }

        ret
    }
}

impl MediaKind {
    fn from_type(typ: &MediaType) -> Self {
        match &typ.0[..] {
            "audio" => MediaKind::Audio,
            "video" => MediaKind::Video,
            "application" => MediaKind::Application,
            _ => {
                warn!("Unknown media type {}", typ);
                MediaKind::Application
            }
        }
    }

    fn as_sdp_type(&self) -> MediaType {
        MediaType(
            match self {
                MediaKind::Audio => "audio",
                MediaKind::Video => "video",
                MediaKind::Application => "application",
            }
            .to_string(),
        )
    }

    fn as_sdp_proto(&self) -> Proto {
        Proto(
            match self {
                MediaKind::Audio | MediaKind::Video => "UDP/TLS/RTP/SAVPF",
                MediaKind::Application => "DTLS/SCTP",
            }
            .to_string(),
        )
    }
}
