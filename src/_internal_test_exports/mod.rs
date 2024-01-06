//! Exported things with feature `_internal_test_exports`.

use crate::format::PayloadParams;
use crate::ice_::IceCreds;
use crate::media::Media;
use crate::media::Mid;
use crate::rtp::{ExtensionMap, RtpHeader};
use crate::Rtc;

pub mod fuzz;
mod rng;
use rng::Rng;

mod setup;

impl Rtc {
    /// UNSTABLE: not public API!
    pub fn _mids(&self) -> Vec<Mid> {
        self.session.medias.iter().map(Media::mid).collect()
    }

    /// UNSTABLE: not public API!
    pub fn _exts(&self) -> &ExtensionMap {
        &self.session.exts
    }

    /// UNSTABLE: not public API!
    pub fn _local_ice_creds(&self) -> IceCreds {
        self.ice.local_credentials().clone()
    }
}

impl RtpHeader {
    /// UNSTABLE: not public API!
    pub fn _parse(buf: &[u8], exts: &ExtensionMap) -> Option<RtpHeader> {
        Self::parse(buf, exts)
    }
}

impl PayloadParams {
    /// UNSTABLE: not public API!
    pub fn _is_locked(&self) -> bool {
        self.locked
    }
}
