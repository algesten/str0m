use crate::MediaTime;

use super::sdes::SdesType;
use super::*;

fn sr(ssrc: u32, ntp_time: MediaTime) -> RtcpFb {
    RtcpFb::SenderInfo(SenderInfo {
        ssrc: ssrc.into(),
        ntp_time,
        rtp_time: 4,
        sender_packet_count: 5,
        sender_octet_count: 6,
    })
}

fn rr(ssrc: u32) -> RtcpFb {
    RtcpFb::ReceiverReport(ReceiverReport {
        ssrc: ssrc.into(),
        fraction_lost: 3,
        packets_lost: 1234,
        max_seq: 4000,
        jitter: 5,
        last_sr_time: 12,
        last_sr_delay: 1,
    })
}

fn sdes(ssrc: u32) -> RtcpFb {
    RtcpFb::Sdes(Sdes {
        ssrc: ssrc.into(),
        values: vec![
            //
            (SdesType::NAME, "Martin".into()),
            (SdesType::TOOL, "str0m".into()),
            (SdesType::NOTE, "Writing things right here".into()),
        ],
    })
}

fn gb(ssrc: u32) -> RtcpFb {
    RtcpFb::Goodbye(ssrc.into())
}

#[test]
fn test_sr() {
    let mut buf = vec![0; 1200];

    let now = MediaTime::now();

    let mut fb = VecDeque::new();
    fb.push_back(sr(1, now));

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 28);

    let mut iter = RtcpFb::feedback(&buf);

    assert_eq!(iter.next(), Some(sr(1, now)));
}

#[test]
fn test_rr() {
    let mut buf = vec![0; 1200];

    let mut fb = VecDeque::new();
    fb.push_back(rr(2));

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 32);

    let mut iter = RtcpFb::feedback(&buf);

    assert_eq!(iter.next(), Some(rr(2)));
}

#[test]
fn test_sr_rr() {
    let mut buf = vec![0; 1200];

    let now = MediaTime::now();

    let mut fb = VecDeque::new();
    fb.push_back(rr(2));
    fb.push_back(sr(1, now));

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 52);

    let mut iter = RtcpFb::feedback(&buf);

    assert_eq!(iter.next(), Some(sr(1, now)));
    assert_eq!(iter.next(), Some(rr(2)));
}

#[test]
fn test_sr_rr_more_than_31() {
    let mut buf = vec![0; 1200];

    let now = MediaTime::now();

    let mut fb = VecDeque::new();
    for i in 0..33 {
        fb.push_back(rr(i + 2));
    }
    fb.push_back(sr(1, now));

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 828);

    let mut iter = RtcpFb::feedback(&buf);

    assert_eq!(iter.next(), Some(sr(1, now)));
    for i in 0..33 {
        fb.push_back(rr(i + 2));
    }
}

#[test]
fn test_gb() {
    let mut buf = vec![0; 1200];

    let mut fb = VecDeque::new();
    fb.push_back(gb(1));

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 8);

    let mut iter = RtcpFb::feedback(&buf);

    assert_eq!(iter.next(), Some(gb(1)));
}

#[test]
fn test_gb_2() {
    let mut buf = vec![0; 1200];

    let mut fb = VecDeque::new();
    fb.push_back(gb(2));
    fb.push_back(gb(1));

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 12);

    let mut iter = RtcpFb::feedback(&buf);

    assert_eq!(iter.next(), Some(gb(2)));
    assert_eq!(iter.next(), Some(gb(1)));
}

#[test]
fn test_gb_more_than_31() {
    let mut buf = vec![0; 1200];

    let mut fb = VecDeque::new();
    for i in 0..33 {
        fb.push_back(gb(1 + i));
    }

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 140);

    let mut iter = RtcpFb::feedback(&buf);

    for i in 0..33 {
        assert_eq!(iter.next(), Some(gb(i + 1)));
    }
}

#[test]
fn test_sdes() {
    let mut buf = vec![0; 1200];

    let mut fb = VecDeque::new();
    fb.push_back(sdes(1));

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 52);

    let mut iter = RtcpFb::feedback(&buf);

    assert_eq!(iter.next(), Some(sdes(1)));
}

#[test]
fn test_sdes_2() {
    let mut buf = vec![0; 1200];

    let mut fb = VecDeque::new();
    fb.push_back(sdes(2));
    fb.push_back(sdes(1));

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 100);

    let mut iter = RtcpFb::feedback(&buf);

    assert_eq!(iter.next(), Some(sdes(2)));
    assert_eq!(iter.next(), Some(sdes(1)));
}

#[test]
fn test_sdes_32() {
    let mut fb = VecDeque::new();
    for i in 0..32 {
        fb.push_back(sdes(i + 3));
    }

    // first packet
    let mut buf = vec![0; 1200];

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 1156);

    let mut iter = RtcpFb::feedback(&buf);

    for i in 0..24 {
        assert_eq!(iter.next(), Some(sdes(i + 3)));
    }

    // second packet
    let mut buf = vec![0; 1200];

    let n = RtcpFb::build_feedback(&mut fb, &mut buf);
    buf.truncate(n);
    assert_eq!(n, 388);

    let mut iter = RtcpFb::feedback(&buf);

    for i in 24..32 {
        assert_eq!(iter.next(), Some(sdes(i + 3)));
    }
}
