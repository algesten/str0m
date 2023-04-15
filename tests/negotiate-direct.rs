use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::{Candidate, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{init_log, progress, TestRtc};

#[test]
#[ignore = "infinite loop, client server never negotiate"]
pub fn negotiate_direct() -> Result<(), RtcError> {
    init_log();

    let client_config = RtcConfig::new().set_stats_interval(Duration::from_secs(60));
    let server_config = RtcConfig::new().set_stats_interval(Duration::from_secs(60));

    let client_ice_creds = client_config.local_ice_credentials();
    let server_ice_creds = server_config.local_ice_credentials();

    let client_fingerprint = client_config.dtls_cert().fingerprint();
    let server_fingerprint = server_config.dtls_cert().fingerprint();

    let mut client = TestRtc::new_with_rtc(info_span!("Client"), client_config.clone().build());
    let mut server = TestRtc::new_with_rtc(info_span!("Server"), server_config.clone().build());

    let client_candidate = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into())?;
    let server_candidate = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into())?;

    // setup client
    client.direct_api().set_ice_controlling(true);
    client.direct_api().set_ice_lite(false);
    client
        .direct_api()
        .set_remote_ice_credentials(server_ice_creds.clone());
    client
        .direct_api()
        .set_remote_fingerprint(server_fingerprint);
    client.add_local_candidate(client_candidate);
    client.add_remote_candidate(server_candidate.clone());
    client.direct_api().start_dtls(true)?;
    client.direct_api().start_sctp(true);

    // setup server
    server.direct_api().set_ice_controlling(false);
    server.direct_api().set_ice_lite(true);
    server
        .direct_api()
        .set_remote_ice_credentials(client_ice_creds.clone());
    server
        .direct_api()
        .set_remote_fingerprint(client_fingerprint);
    server.add_local_candidate(server_candidate);
    server.direct_api().start_dtls(false)?;
    server.direct_api().start_sctp(false);

    // negotiate
    loop {
        if client.is_connected() && server.is_connected() {
            break;
        }
        progress(&mut client, &mut server)?;
    }

    Ok(())
}
