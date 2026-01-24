use str0m::media::{MediaKind, MediaTime};
use str0m::rtp::vla::{ResolutionAndFramerate, Serializer as VlaSerializer};
use str0m::rtp::vla::{SimulcastStreamAllocation, SpatialLayerAllocation};
use str0m::rtp::vla::{TemporalLayerAllocation, VideoLayersAllocation, URI as VLA_URI};
use str0m::rtp::{Extension, ExtensionValues, Ssrc};
use str0m::{Event, Rtc, RtcError};

mod common;
use common::{connect_l_r_with_rtc, init_crypto_default, init_log};

#[test]
pub fn vla_rtp_mode() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let vla_ext = Extension::with_serializer(VLA_URI, VlaSerializer);

    let rtc_l = Rtc::builder()
        .set_rtp_mode(true)
        .set_extension(14, vla_ext.clone())
        .build();
    let rtc_r = Rtc::builder()
        .set_rtp_mode(true)
        .set_extension(14, vla_ext)
        .build();

    let (mut l, mut r) = connect_l_r_with_rtc(rtc_l, rtc_r);

    let mid = "vid".into();
    let ssrc_tx: Ssrc = 1000.into();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Video);
        api.declare_stream_tx(ssrc_tx, None, mid, None);
        Ok(api.finish())
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Video);
        Ok(api.finish())
    })?;

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp8();
    let pt = params.pt();
    let mut ssrc_result = None;
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        ssrc_result = Some(api.stream_tx_by_mid(mid, None).unwrap().ssrc());
        Ok(api.finish())
    })?;
    let ssrc = ssrc_result.unwrap();

    let vla = VideoLayersAllocation {
        current_simulcast_stream_index: 0,
        simulcast_streams: vec![SimulcastStreamAllocation {
            spatial_layers: vec![SpatialLayerAllocation {
                temporal_layers: vec![TemporalLayerAllocation {
                    cumulative_kbps: 500,
                }],
                resolution_and_framerate: Some(ResolutionAndFramerate {
                    width: 640,
                    height: 480,
                    framerate: 30,
                }),
            }],
        }],
    };

    let mut exts = ExtensionValues::default();
    exts.mid = Some(mid);
    exts.user_values.set(vla.clone());

    let last = l.last;
    l.drive(&mut r, |tx| {
        tx.write_rtp(
            ssrc,
            pt,
            (1000_u64).into(),
            0,
            last,
            false,
            exts,
            false,
            vec![0xAA; 10],
        )
    })?;

    let mut vla_received = false;
    for _ in 0..100 {
        l.drive(&mut r, |tx| Ok(tx.finish()))?;

        for (_, event) in &r.events {
            if let Event::RtpPacket(packet) = event {
                if let Some(v) = packet
                    .header
                    .ext_vals
                    .user_values
                    .get::<VideoLayersAllocation>()
                {
                    assert_eq!(v, &vla);
                    assert_eq!(
                        v.simulcast_streams[0].spatial_layers[0].temporal_layers[0].cumulative_kbps,
                        500
                    );
                    assert_eq!(
                        v.simulcast_streams[0].spatial_layers[0]
                            .resolution_and_framerate
                            .as_ref()
                            .unwrap()
                            .width,
                        640
                    );
                    vla_received = true;
                } else {
                    println!(
                        "Packet received but no VLA. Exts: {:?}",
                        packet.header.ext_vals
                    );
                }
            }
        }
        if vla_received {
            break;
        }
        r.events.clear();
    }

    assert!(vla_received);

    Ok(())
}

#[test]
pub fn vla_frame_mode() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let vla_ext = Extension::with_serializer(VLA_URI, VlaSerializer);

    let rtc_l = Rtc::builder().set_extension(14, vla_ext.clone()).build();
    let rtc_r = Rtc::builder().set_extension(14, vla_ext).build();

    let (mut l, mut r) = connect_l_r_with_rtc(rtc_l, rtc_r);

    let mid = "vid".into();
    let ssrc_tx: Ssrc = 1000.into();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Video);
        api.declare_stream_tx(ssrc_tx, None, mid, None);
        Ok(api.finish())
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Video);
        Ok(api.finish())
    })?;

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let vla = VideoLayersAllocation {
        current_simulcast_stream_index: 0,
        simulcast_streams: vec![SimulcastStreamAllocation {
            spatial_layers: vec![SpatialLayerAllocation {
                temporal_layers: vec![TemporalLayerAllocation {
                    cumulative_kbps: 500,
                }],
                resolution_and_framerate: Some(ResolutionAndFramerate {
                    width: 640,
                    height: 480,
                    framerate: 30,
                }),
            }],
        }],
    };

    let pt = l.params_vp8().pt();
    let last = l.last;

    l.drive(&mut r, |tx| {
        let writer = tx.writer(mid).expect("writer");
        writer.user_extension_value(vla.clone()).write(
            pt,
            last,
            MediaTime::ZERO,
            vec![0xAA; 10],
        )
    })?;

    let mut vla_received = false;
    for _ in 0..100 {
        l.drive(&mut r, |tx| Ok(tx.finish()))?;

        for (_, event) in &r.events {
            if let Event::MediaData(data) = event {
                if let Some(v) = data.ext_vals.user_values.get::<VideoLayersAllocation>() {
                    assert_eq!(v, &vla);
                    assert_eq!(
                        v.simulcast_streams[0].spatial_layers[0].temporal_layers[0].cumulative_kbps,
                        500
                    );
                    assert_eq!(
                        v.simulcast_streams[0].spatial_layers[0]
                            .resolution_and_framerate
                            .as_ref()
                            .unwrap()
                            .width,
                        640
                    );
                    vla_received = true;
                } else {
                    println!("MediaData received but no VLA. Exts: {:?}", data.ext_vals);
                }
            }
        }
        if vla_received {
            break;
        }
        r.events.clear();
    }

    assert!(vla_received);

    Ok(())
}
