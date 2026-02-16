//! Media formats and parameters

// These really don't belong anywhere, but I guess they're kind of related
// to codecs etc.
pub use crate::packet::{
    CodecExtra, H264CodecExtra, Vp8CodecExtra, Vp9CodecExtra, Vp9PacketizerMode,
};

mod codec;
mod codec_config;
mod format_params;
mod payload_params;

pub use codec::{Codec, CodecSpec};
pub use codec_config::CodecConfig;
pub use format_params::FormatParams;
pub use payload_params::PayloadParams;
