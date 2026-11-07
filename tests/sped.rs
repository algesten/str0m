use std::net::Ipv4Addr;
use std::time::Duration;
use str0m::channel::ChannelConfig;
use str0m::crypto::dtls::DtlsVersion;
use str0m::{RtcError, SpedFallback};

mod common;
use common::{Peer, TestRtc, init_crypto_default, progress};

fn peers(
    enabled: bool,
    remote_enabled: bool,
    version: DtlsVersion,
) -> Result<(TestRtc, TestRtc), RtcError> {
    init_crypto_default();
    let mut left = TestRtc::new_with_config(Peer::Left, |c| {
        c.set_sped_enabled(enabled)
            .set_snap_enabled(true)
            .set_dtls_version(DtlsVersion::Auto)
    });
    let mut right = TestRtc::new_with_config(Peer::Right, |c| {
        c.set_sped_enabled(remote_enabled)
            .set_snap_enabled(true)
            .set_dtls_version(version)
            .set_ice_lite(true)
    });
    left.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    right.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());
    let mut change = left.sdp_api();
    change.add_channel_with_config(ChannelConfig {
        negotiated: Some(4),
        ..Default::default()
    });
    let (offer, pending) = change.apply().unwrap();
    let answer = right.sdp_api().accept_offer(offer)?;
    left.sdp_api().accept_answer(pending, answer)?;
    Ok((left, right))
}

fn connect(left: &mut TestRtc, right: &mut TestRtc) -> Result<(), RtcError> {
    while !left.is_connected() || !right.is_connected() {
        assert!(
            left.duration() < Duration::from_secs(10),
            "connection deadline"
        );
        progress(left, right)?;
    }
    Ok(())
}

#[test]
fn negotiated_sped_authenticates_dtls_12_and_13() -> Result<(), RtcError> {
    for version in [DtlsVersion::Dtls12, DtlsVersion::Dtls13, DtlsVersion::Auto] {
        let (mut left, mut right) = peers(true, true, version)?;
        connect(&mut left, &mut right)?;
        assert!(left.sped_stats().negotiated && right.sped_stats().negotiated);
        assert!(left.sped_stats().embedded_received + right.sped_stats().embedded_received > 0);
        assert!(left.direct_api().remote_dtls_fingerprint().is_some());
        assert!(right.direct_api().remote_dtls_fingerprint().is_some());
    }
    Ok(())
}

#[test]
fn ordinary_peer_falls_back_without_embedding() -> Result<(), RtcError> {
    for (local, remote) in [(true, false), (false, true), (false, false)] {
        let (mut left, mut right) = peers(local, remote, DtlsVersion::Dtls12)?;
        connect(&mut left, &mut right)?;
        assert!(!left.sped_stats().negotiated && !right.sped_stats().negotiated);
        assert_eq!(
            left.sped_stats().embedded_sent + right.sped_stats().embedded_sent,
            0
        );
        if local {
            assert_eq!(left.sped_stats().fallback, Some(SpedFallback::Unsupported));
        }
    }
    Ok(())
}

#[test]
fn cancellation_before_ice_selection_discards_unsendable_early_flights() -> Result<(), RtcError> {
    use str0m::Output;
    let (mut left, mut right) = peers(true, true, DtlsVersion::Dtls13)?;
    for peer in [&mut left, &mut right] {
        peer.close()?;
        assert!(!peer.is_alive());
        assert!(matches!(peer.poll_output()?, Output::Timeout(_)));
    }
    Ok(())
}

#[test]
fn ice_restart_preserves_authenticated_dtls_and_renegotiates_sped() -> Result<(), RtcError> {
    let (mut left, mut right) = peers(true, true, DtlsVersion::Dtls13)?;
    connect(&mut left, &mut right)?;
    let fingerprint = left.direct_api().remote_dtls_fingerprint().cloned();
    let mut changes = left.sdp_api();
    changes.ice_restart(true);
    let (offer, pending) = changes.apply().unwrap();
    let answer = right.sdp_api().accept_offer(offer)?;
    left.sdp_api().accept_answer(pending, answer)?;
    connect(&mut left, &mut right)?;
    assert_eq!(
        left.direct_api().remote_dtls_fingerprint(),
        fingerprint.as_ref()
    );
    assert!(left.sped_stats().negotiated && right.sped_stats().negotiated);
    Ok(())
}

fn embedded_request(local: &mut TestRtc, remote: &mut TestRtc, password: Option<&str>) -> Vec<u8> {
    use is::stun::{StunMessage, TransId};
    let local_creds = local.direct_api().local_ice_credentials();
    let remote_creds = remote.direct_api().local_ice_credentials();
    let username = format!("{}:{}", local_creds.ufrag, remote_creds.ufrag);
    let invalid_dtls = [22, 254, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255];
    let message = StunMessage::binding_request(&username, TransId::new(), false, 1, 100, false)
        .with_dtls(Some(&invalid_dtls), None);
    let provider = str0m::crypto::from_feature_flags();
    let hmac =
        |key: &[u8], payloads: &[&[u8]]| provider.sha1_hmac_provider.sha1_hmac(key, payloads);
    let mut bytes = vec![0; 1200];
    let len = message
        .to_bytes(
            Some(password.unwrap_or(&local_creds.pass).as_bytes()),
            &mut bytes,
            hmac,
        )
        .unwrap();
    bytes.truncate(len);
    bytes
}

#[test]
fn forged_checks_and_previous_ice_generation_cannot_inject_dtls() -> Result<(), RtcError> {
    use str0m::{
        Input,
        net::{Protocol, Receive},
    };
    let (mut left, mut right) = peers(true, true, DtlsVersion::Dtls13)?;
    let forged = embedded_request(&mut left, &mut right, Some("wrong-password"));
    let stale = embedded_request(&mut left, &mut right, None);
    let inject = |left: &mut TestRtc, bytes: &[u8]| -> Result<(), RtcError> {
        let input = Input::Receive(
            left.last,
            Receive {
                proto: Protocol::Udp,
                source: "2.2.2.2:2000".parse().unwrap(),
                destination: "1.1.1.1:1000".parse().unwrap(),
                contents: bytes.try_into().unwrap(),
            },
        );
        // Even a caller that forgot demultiplexing cannot bypass integrity.
        left.handle_input(input)
    };
    inject(&mut left, &forged)?;
    assert_eq!(left.sped_stats().embedded_received, 0);
    connect(&mut left, &mut right)?;
    let mut change = left.sdp_api();
    change.ice_restart(true);
    let (offer, pending) = change.apply().unwrap();
    let answer = right.sdp_api().accept_offer(offer)?;
    left.sdp_api().accept_answer(pending, answer)?;
    inject(&mut left, &stale)?;
    assert_eq!(left.sped_stats().embedded_received, 0);
    connect(&mut left, &mut right)?;
    Ok(())
}

#[test]
fn a_rejected_early_record_cannot_prevent_normal_authenticated_dtls() -> Result<(), RtcError> {
    use str0m::{
        Input,
        net::{Protocol, Receive},
    };
    let (mut left, mut right) = peers(true, true, DtlsVersion::Dtls13)?;
    let bytes = embedded_request(&mut left, &mut right, None);
    let now = left.last;
    left.handle_input(Input::Receive(
        now,
        Receive {
            proto: Protocol::Udp,
            source: "2.2.2.2:2000".parse().unwrap(),
            destination: "1.1.1.1:1000".parse().unwrap(),
            contents: bytes.as_slice().try_into().unwrap(),
        },
    ))?;
    assert_eq!(
        left.sped_stats().fallback,
        Some(SpedFallback::EarlyDtlsFailed)
    );
    connect(&mut left, &mut right)?;
    assert!(left.is_dtls_connected() && right.is_dtls_connected());
    Ok(())
}
