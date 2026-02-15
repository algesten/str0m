//! Media formats and parameters

// These really don't belong anywhere, but I guess they're kind of related
// to codecs etc.
pub use crate::packet::{detect_av1_keyframe, detect_vp8_keyframe, detect_vp9_keyframe};
pub use crate::packet::{CodecExtra, H264CodecExtra, Vp8CodecExtra, Vp9CodecExtra};

mod codec;
mod codec_config;
mod format_params;
mod payload_params;

pub use codec::{Codec, CodecSpec};
pub use codec_config::CodecConfig;
pub use format_params::FormatParams;
pub use payload_params::PayloadParams;
