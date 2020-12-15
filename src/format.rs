use crate::sdp::{MediaAttribute, Simulcast, SsrcInfo, StreamId};
use std::cmp::Ordering;
use std::collections::HashMap;

/// One format from an m-section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Format {
    /// rtpmap number
    pub map_no: u8,
    /// Codec from `a=rtpmap:<no> codec/<clock-rate>` line
    pub codec: String,
    /// Clock rate from `a=rtpmap:<no> codec/<clock-rate>` line
    pub clock_rate: u32,
    /// Optional encoding parameters from `a=rtpmap:<no> codec/<clock-rate>/<enc-param>` line
    pub enc_param: Option<String>,
    /// Options from `a=rtcp_fb` lines.
    pub rtcp_fb: Vec<String>,
    /// Extra format parameters from the `a=fmtp` line.
    pub fmtp: Vec<(String, String)>,
    /// Restrictions that applies to this format from the `a=rid` lines.
    pub restrictions: Vec<StreamId>,
    /// For backwards compatibility, we need to provide a=ssrc cname lines.
    /// As of 2020-12-13, only Chrome is ok with an a=ssrc "free" world.
    pub ssrc_info: Option<SsrcInfo>,
}

impl Format {
    pub fn as_rtpmap(&self) -> MediaAttribute {
        MediaAttribute::RtpMap {
            map_no: self.map_no,
            codec: self.codec.clone(),
            clock_rate: self.clock_rate,
            enc_param: self.enc_param.clone(),
        }
    }

    pub fn append_rtcp_fp(&self, into: &mut Vec<MediaAttribute>) {
        for r in &self.rtcp_fb {
            into.push(MediaAttribute::RtcpFb {
                map_no: self.map_no,
                value: r.clone(),
            });
        }
    }

    pub fn is_repair(&self) -> bool {
        self.codec == "rtx"
    }

    pub fn fmtp_apt(&self) -> Option<u8> {
        for (k, v) in &self.fmtp {
            if k == "apt" {
                return v.parse().ok();
            }
        }

        None
    }

    pub fn needs_ssrc(&self) -> bool {
        match &self.codec[..] {
            "rtx" => false,
            "red" => {
                panic!("Investigate whether red needs a a=ssrc cname line");
            }
            _ => true,
        }
    }
}

/// Select the formats to keep from an SDP offer.
// TODO Let _simulcast affect this choice. We need to handle cases where
// a=rid points out different map_no.
pub fn select_formats(formats: Vec<Format>, _simulcast: &Option<Simulcast>) -> Vec<Format> {
    // map_no to order no in the incoming SDP.
    let mut remote_order: HashMap<u8, usize> = HashMap::new();
    for (idx, f) in formats.iter().enumerate() {
        remote_order.insert(f.map_no, idx);
    }

    // Our preferred order and codecs we support.
    // TODO investigate codecs:
    //   - red (redundant coding) has fmtp-apt
    //   - ulpfec (Uneven Level Protection Forward Error Correction) uses a=ssrc-group:FID
    const CODECS: &[&str] = &["h264", "opus"];
    const REPAIR: &[&str] = &[]; // &["rtx"];

    let mut wanted = vec![];
    let mut repair = vec![];
    let mut other = vec![];

    for mut f in formats {
        f.codec = f.codec.to_lowercase();
        if CODECS.contains(&&f.codec[..]) {
            wanted.push(f);
        } else if REPAIR.contains(&&f.codec[..]) {
            repair.push(f);
        } else {
            other.push(f);
        }
    }

    // Order the codecs in preferred order.
    wanted.sort_by(|a, b| {
        // primary sort
        let idx_a = CODECS.iter().position(|c| &a.codec == c).unwrap();
        let idx_b = CODECS.iter().position(|c| &b.codec == c).unwrap();

        // secondary sort
        let rem_a = remote_order.get(&a.map_no).unwrap();
        let rem_b = remote_order.get(&b.map_no).unwrap();

        let ord_a = idx_a * 1000 + rem_a;
        let ord_b = idx_b * 1000 + rem_b;

        assert!(ord_a != ord_b);

        if ord_a < ord_b {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    });

    // Pick first, which is the "winner"
    if let Some(head) = wanted.into_iter().next() {
        let map_no = head.map_no;
        let mut kept = vec![head];

        // Find related repair stream we are also keeping.
        for rep in repair {
            let is_related = rep.fmtp_apt() == Some(map_no);

            if is_related {
                kept.push(rep);
            }
        }

        debug!("Selected formats: {:?}", kept);

        kept
    } else {
        // We kept no codec :(
        debug!("No acceptable codec");
        vec![]
    }
}
