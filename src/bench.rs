pub use super::rtp_::bench::srtp;

pub fn benchmark_cache_sent_packet() {
    use crate::media::MediaTime;
    use crate::rtp::{RtpHeader, SeqNo};
    use crate::streams::rtx_cache::RtxCache;
    use crate::RtpPacket;
    use rand::random;
    use std::time::{Duration, Instant};

    let mut cache = RtxCache::new(1024, Duration::from_secs(3));

    let mut start = Instant::now();

    for i in 0..3000 {
        let n = i * 10;
        cache.cache_sent_packet(packet(n, start), start + Duration::from_millis(0));
        cache.cache_sent_packet(packet(n + 1, start), start + Duration::from_millis(100));
        cache.cache_sent_packet(packet(n + 2, start), start + Duration::from_millis(200));
        cache.cache_sent_packet(packet(n + 3, start), start + Duration::from_millis(300));
        cache.cache_sent_packet(packet(n + 4, start), start + Duration::from_millis(400));
        cache.cache_sent_packet(packet(n + 5, start), start + Duration::from_millis(500));
        cache.cache_sent_packet(packet(n + 6, start), start + Duration::from_millis(600));
        cache.cache_sent_packet(packet(n + 7, start), start + Duration::from_millis(700));
        cache.cache_sent_packet(packet(n + 8, start), start + Duration::from_millis(800));
        cache.cache_sent_packet(packet(n + 9, start), start + Duration::from_millis(900));

        start += Duration::from_secs(1);
    }

    fn packet(n: usize, timestamp: Instant) -> RtpPacket {
        let seq_no: SeqNo = (n as u64).into();
        let r: f32 = random();
        let payload = vec![0; (2000.0 * r) as usize];
        RtpPacket {
            seq_no,
            time: MediaTime::new(n as i64 * 63, 90_000),
            header: RtpHeader {
                sequence_number: *seq_no as u16,
                ..Default::default()
            },
            payload,
            timestamp,
            nackable: true,
        }
    }
}
