#![cfg(feature = "drv")]
//! Verifies the `drv` feature derives `drv::Input` on str0m's public
//! identity types so downstream `#[drv::memo]` queries can take them by
//! value. `Frequency` exercises the `NonZeroU32` path specifically.

use str0m::format::Codec;
use str0m::media::{Frequency, MediaKind, Mid};

#[derive(drv::Input)]
struct TrackFacts {
    pub mid: Mid,
    pub kind: MediaKind,
    pub codec: Codec,
    pub clock_rate: Frequency,
}

#[drv::memo(single)]
fn is_opus_audio(input: TrackFacts) -> bool {
    matches!(input.kind, MediaKind::Audio) && matches!(input.codec, Codec::Opus)
}

#[test]
fn identity_types_are_valid_memo_inputs() {
    let mid = Mid::from("0");
    let audio = TrackFacts {
        mid,
        kind: MediaKind::Audio,
        codec: Codec::Opus,
        clock_rate: Frequency::FORTY_EIGHT_KHZ,
    };
    assert!(is_opus_audio(audio));

    let video = TrackFacts {
        mid,
        kind: MediaKind::Video,
        codec: Codec::Vp8,
        clock_rate: Frequency::NINETY_KHZ,
    };
    assert!(!is_opus_audio(video));
}
