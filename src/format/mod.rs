//! Media formats and parameters

// These really don't belong anywhere, but I guess they're kind of related
// to codecs etc.
pub use crate::packet::detect_av1_keyframe;
pub use crate::packet::detect_h264_keyframe;
pub use crate::packet::detect_h265_keyframe;
pub use crate::packet::detect_vp8_keyframe;
pub use crate::packet::detect_vp9_keyframe;
pub use crate::packet::CodecExtra;
pub use crate::packet::H264CodecExtra;
pub use crate::packet::H265CodecExtra;
pub use crate::packet::Vp8CodecExtra;
pub use crate::packet::Vp9CodecExtra;
pub use crate::packet::Vp9PacketizerMode;

mod codec;
mod codec_config;
mod format_params;
mod payload_params;

pub use codec::{Codec, CodecSpec};
pub use codec_config::CodecConfig;
pub use format_params::FormatParams;
pub use payload_params::PayloadParams;
