mod _common;

use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use _common::init_log;
use str0m::*;

pub enum TestData {
    Offer(Offer),
    Answer(Answer),
    Data(SocketAddr, SocketAddr, Vec<u8>),
}

fn connect_peer_active(
    tx: mpsc::Sender<TestData>,
    rx: mpsc::Receiver<TestData>,
) -> Result<Peer<state::Connected>, Error> {
    let peer_init = PeerConfig::with_session_id(1)
        .local_candidate(Candidate::host("1.1.1.1:1000".parse().unwrap()))
        .end_of_candidates()
        .build()?;

    let (offer, peer_offering) = peer_init.change_set().add_data_channel().apply();

    tx.send(TestData::Offer(offer)).unwrap();

    let data = rx.recv().unwrap();
    let answer = match data {
        TestData::Answer(v) => v,
        _ => panic!("Expected TestData::Answer"),
    };
    let mut peer_connecting = peer_offering.accept_answer(answer)?;

    let peer_connected = loop {
        while let Some(Output {
            source,
            target,
            data,
        }) = peer_connecting.io().network_output()
        {
            tx.send(TestData::Data(source, target, data.to_vec()))
                .unwrap();
        }

        match peer_connecting.try_connect() {
            ConnectionResult::Connecting(v) => peer_connecting = v,
            ConnectionResult::Connected(v) => break v,
        }

        if let Some(data) = rx.recv_timeout(Duration::from_millis(100)).ok() {
            let (source, target, data_in) = match data {
                TestData::Data(source, target, v) => (source, target, v),
                _ => panic!("Expected TestData::Data"),
            };
            let time = Instant::now();

            let input = NetworkInput::try_from(data_in.as_slice())?;

            peer_connecting
                .io()
                .network_input(time, source, target, input)?;
        } else {
            peer_connecting.io().tick(Instant::now())?;
        }
    };

    Ok(peer_connected)
}

fn connect_peer_passive(
    tx: mpsc::Sender<TestData>,
    rx: mpsc::Receiver<TestData>,
) -> Result<Peer<state::Connected>, Error> {
    let peer_init = PeerConfig::with_session_id(2)
        .local_candidate(Candidate::host("2.2.2.2:2000".parse().unwrap()))
        .end_of_candidates()
        .build()?;

    let data = rx.recv().unwrap();
    let offer = match data {
        TestData::Offer(v) => v,
        _ => panic!("Expected TestData::Offer"),
    };

    let (answer, mut peer_connecting) = peer_init.accept_offer(offer)?;
    tx.send(TestData::Answer(answer)).unwrap();

    let peer_connected = loop {
        while let Some(Output {
            source,
            target,
            data,
        }) = peer_connecting.io().network_output()
        {
            tx.send(TestData::Data(source, target, data.to_vec()))
                .unwrap();
        }

        match peer_connecting.try_connect() {
            ConnectionResult::Connecting(v) => peer_connecting = v,
            ConnectionResult::Connected(v) => break v,
        }

        if let Some(data) = rx.recv_timeout(Duration::from_millis(100)).ok() {
            let (source, target, data) = match data {
                TestData::Data(source, target, data) => (source, target, data),
                _ => panic!("Expected TestData::Data"),
            };
            let time = Instant::now();

            let input = NetworkInput::try_from(data.as_slice())?;

            peer_connecting
                .io()
                .network_input(time, source, target, input)?;
        } else {
            peer_connecting.io().tick(Instant::now())?;
        }
    };

    Ok(peer_connected)
}

#[test]
fn connect_audio() -> Result<(), Error> {
    init_log();

    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();

    let jh1 = thread::spawn(move || connect_peer_active(tx1, rx2));
    let jh2 = thread::spawn(move || connect_peer_passive(tx2, rx1));

    jh1.join().unwrap()?;
    jh2.join().unwrap()?;

    Ok(())
}
