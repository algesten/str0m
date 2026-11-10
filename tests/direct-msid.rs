use std::time::Instant;

use str0m::Rtc;
use str0m::media::{MediaKind, Mid};

mod common;
use common::{init_crypto_default, init_log};

#[test]
pub fn direct_api_set_msid() {
    init_log();
    init_crypto_default();

    let mut rtc = Rtc::new(Instant::now());
    let mid: Mid = "aud".into();

    rtc.direct_api().declare_media(mid, MediaKind::Audio);
    assert!(rtc.direct_api().set_msid(mid, "my-stream", "my-track"));

    let media = rtc.media(mid).unwrap();
    assert_eq!(media.stream_id(), "my-stream");
    assert_eq!(media.track_id(), "my-track");
}

#[test]
pub fn direct_api_set_msid_sanitizes() {
    init_log();
    init_crypto_default();

    let mut rtc = Rtc::new(Instant::now());
    let mid: Mid = "vid".into();

    rtc.direct_api().declare_media(mid, MediaKind::Video);
    let long = "t".repeat(100);
    assert!(rtc.direct_api().set_msid(mid, "a b\u{7f}c", long));

    let media = rtc.media(mid).unwrap();
    assert_eq!(media.stream_id(), "abc");
    assert_eq!(media.track_id(), "t".repeat(64));
}

#[test]
pub fn direct_api_set_msid_preserves_valid_tilde() {
    init_crypto_default();
    let mut rtc = Rtc::new(Instant::now());
    let mid: Mid = "vid".into();
    rtc.direct_api().declare_media(mid, MediaKind::Video);
    assert!(rtc.direct_api().set_msid(mid, "stream~id", "track~id"));
    let media = rtc.media(mid).unwrap();
    assert_eq!(media.stream_id(), "stream~id");
    assert_eq!(media.track_id(), "track~id");
}

#[test]
pub fn direct_api_set_msid_unknown_mid() {
    init_log();
    init_crypto_default();

    let mut rtc = Rtc::new(Instant::now());

    assert!(!rtc.direct_api().set_msid("nope".into(), "s", "t"));
}

#[test]
pub fn direct_api_declare_media_keeps_random_msid() {
    init_log();
    init_crypto_default();

    let mut rtc = Rtc::new(Instant::now());
    let mid: Mid = "aud".into();

    rtc.direct_api().declare_media(mid, MediaKind::Audio);

    let media = rtc.media(mid).unwrap();
    assert!(!media.stream_id().is_empty());
    assert!(!media.track_id().is_empty());
}
