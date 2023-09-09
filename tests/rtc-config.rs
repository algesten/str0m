use std::time::Instant;
use str0m::{RtcError, RtcConfig, change::{IceCreds, DtlsCert}, format::CodecConfig, rtp::ExtensionMap};

mod common;
use common::init_log;
use tracing::info;

#[test]
pub fn reuse_certificate() -> Result<(), RtcError> {
    init_log();

    let start = Instant::now();
    let config = RtcConfig::default();
    info!("Duration of RtcConfig: {:?}", Instant::now().duration_since(start));
    config.build();

    let start = Instant::now();
    let dtls_cert = DtlsCert::new();
    info!("Duration of new cert: {:?}", Instant::now().duration_since(start));

    let start = Instant::now();
    let config = RtcConfig::new_with_dtls_cert(dtls_cert.clone());
    info!("Duration of rtcconfig with dtls cert: {:?}", Instant::now().duration_since(start));
    config.build();

    let start = Instant::now();
    let config = RtcConfig::new_with_dtls_cert_and_default(dtls_cert.clone());
    info!("Duration of rtcconfig with dtls cert and default: {:?}", Instant::now().duration_since(start));

    let start = Instant::now();
    config.build();
    info!("Duration of build: {:?}", Instant::now().duration_since(start));

    Ok(())
}