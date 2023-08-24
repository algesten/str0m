use std::mem;
use std::time::{Duration, Instant};

use crate::rtp_::SeqNo;

use super::AckedPacket;

const BURST_TIME_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Default)]
pub struct ArrivalGroup {
    first: Option<(SeqNo, Instant, Instant)>,
    last_seq_no: Option<SeqNo>,
    last_local_send_time: Option<Instant>,
    last_remote_recv_time: Option<Instant>,
    size: usize,
}

impl ArrivalGroup {
    /// Maybe add a packet to the group.
    ///
    /// Returns [`true`] if a new group needs to be created and [`false`] otherwise.
    fn add_packet(&mut self, packet: AckedPacket) -> bool {
        match self.belongs_to_group(&packet) {
            Belongs::NewGroup => return true,
            Belongs::Skipped => return false,
            Belongs::Yes => {}
        }

        if self.first.is_none() {
            self.first = Some((
                packet.seq_no,
                packet.local_send_time,
                packet.remote_recv_time,
            ));
        }

        self.last_remote_recv_time = self
            .last_remote_recv_time
            .max(Some(packet.remote_recv_time));
        self.last_local_send_time = self.last_local_send_time.max(Some(packet.local_send_time));
        self.size += 1;
        self.last_seq_no = self.last_seq_no.max(Some(packet.seq_no));

        false
    }

    fn belongs_to_group(&self, packet: &AckedPacket) -> Belongs {
        let Some((_, first_local_send_time, first_remote_recv_time)) = self.first else {
            // Start of the group
            return Belongs::Yes;
        };

        let Some(send_diff) = packet
            .local_send_time
            .checked_duration_since(first_local_send_time)
        else {
            // Out of order
            return Belongs::Skipped;
        };

        if send_diff < BURST_TIME_INTERVAL {
            // Sent within the same burst interval
            return Belongs::Yes;
        }

        let inter_arrival_time = packet
            .remote_recv_time
            .checked_duration_since(self.remote_recv_time());

        let Some(inter_arrival_time) = inter_arrival_time else {
            info!("TWCC: Out of order arrival");
            return Belongs::Skipped;
        };

        let inter_group_delay_delta = inter_arrival_time.as_secs_f64()
            - (packet.local_send_time - self.local_send_time()).as_secs_f64();

        if inter_group_delay_delta < 0.0
            && inter_arrival_time < BURST_TIME_INTERVAL
            && packet.remote_recv_time - first_remote_recv_time < Duration::from_millis(100)
        {
            Belongs::Yes
        } else {
            Belongs::NewGroup
        }
    }

    /// Calculate the inter group delay delta between self and a subsequent group.
    pub(super) fn inter_group_delay_delta(&self, other: &Self) -> Option<f64> {
        let first_seq_no = self.first.map(|(s, _, _)| s)?;
        let last_seq_no = self.last_seq_no?;

        let arrival_delta = self.arrival_delta(other)?.as_secs_f64() * 1000.0;
        let departure_delta = self.departure_delta(other)?.as_secs_f64() * 1000.0;

        assert!(arrival_delta >= 0.0);

        let result = arrival_delta - departure_delta;
        trace!("Delay delta for group({first_seq_no}..={last_seq_no}. {result:?} = {arrival_delta:?} - {departure_delta:?}");

        Some(result)
    }

    pub(super) fn departure_delta(&self, other: &Self) -> Option<Duration> {
        other
            .local_send_time()
            .checked_duration_since(self.local_send_time())
    }

    fn arrival_delta(&self, other: &Self) -> Option<Duration> {
        other
            .remote_recv_time()
            .checked_duration_since(self.remote_recv_time())
    }

    /// The local send time i.e. departure time, for the group.
    ///
    /// Panics if the group doesn't have at least one packet.
    fn local_send_time(&self) -> Instant {
        self.last_local_send_time
            .expect("local_send_time to only be called on non-empty groups")
    }

    /// The remote receive time i.e. arrival time, for the group.
    ///
    /// Panics if the group doesn't have at least one packet.
    fn remote_recv_time(&self) -> Instant {
        self.last_remote_recv_time
            .expect("remote_recv_time to only be called on non-empty groups")
    }
}

/// Whether a given packet is belongs to a group or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Belongs {
    /// The packet is belongs to the group.
    Yes,
    /// The packet is does not belong to the group, a new group should be created.
    NewGroup,
    /// The packet was skipped and a decision wasn't made.
    Skipped,
}

impl Belongs {
    fn new_group(&self) -> bool {
        matches!(self, Self::NewGroup)
    }
}

#[derive(Debug, Default)]
pub struct ArrivalGroupAccumulator {
    previous_group: Option<ArrivalGroup>,
    current_group: ArrivalGroup,
}

impl ArrivalGroupAccumulator {
    /// Accumulate a packet.
    ///
    /// If adding this packet produced a new delay delta it is returned.
    pub(super) fn accumulate_packet(
        &mut self,
        packet: AckedPacket,
    ) -> Option<InterGroupDelayDelta> {
        let need_new_group = self.current_group.add_packet(packet);

        if !need_new_group {
            return None;
        }

        // Variation between previous group and current.
        let delay_delta = self.inter_group_delay_delta();
        let send_delta = self.send_delta();
        let last_remote_recv_time = self.current_group.remote_recv_time();

        let current_group = mem::take(&mut self.current_group);
        self.previous_group = Some(current_group);

        self.current_group.add_packet(packet);

        Some(InterGroupDelayDelta {
            send_delta: send_delta?,
            delay_delta: delay_delta?,
            last_remote_recv_time,
        })
    }

    fn inter_group_delay_delta(&self) -> Option<f64> {
        self.previous_group
            .as_ref()
            .and_then(|prev| prev.inter_group_delay_delta(&self.current_group))
    }

    fn send_delta(&self) -> Option<Duration> {
        self.previous_group
            .as_ref()
            .and_then(|prev| prev.departure_delta(&self.current_group))
    }
}

/// The calculate delay delta between two groups of packets.
#[derive(Debug, Clone, Copy)]
pub(super) struct InterGroupDelayDelta {
    /// The delta between the send times of the two groups i.e. delta between the last packet sent
    /// in each group.
    pub(super) send_delta: Duration,
    /// The delay delta between the two groups.
    pub(super) delay_delta: f64,
    /// The reported receive time for the last packet in the first arrival group.
    pub(super) last_remote_recv_time: Instant,
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::rtp_::DataSize;

    use super::{AckedPacket, ArrivalGroup, Belongs};

    #[test]
    fn test_arrival_group_all_packets_belong_to_empty_group() {
        let now = Instant::now();
        let group = ArrivalGroup::default();

        assert_eq!(
            group.belongs_to_group(&AckedPacket {
                seq_no: 1.into(),
                size: DataSize::ZERO,
                local_send_time: now,
                remote_recv_time: now + duration_us(10),
            }),
            Belongs::Yes,
            "Any packet should belong to an empty arrival group"
        );
    }

    #[test]
    fn test_arrival_group_all_packets_sent_within_burst_interval_belong() {
        let now = Instant::now();
        #[allow(clippy::vec_init_then_push)]
        let packets = {
            let mut packets = vec![];

            packets.push(AckedPacket {
                seq_no: 0.into(),
                size: DataSize::ZERO,
                local_send_time: now,
                remote_recv_time: now + duration_us(150),
            });

            packets.push(AckedPacket {
                seq_no: 1.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(50),
                remote_recv_time: now + duration_us(225),
            });

            packets.push(AckedPacket {
                seq_no: 2.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(1005),
                remote_recv_time: now + duration_us(1140),
            });

            packets.push(AckedPacket {
                seq_no: 3.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(4995),
                remote_recv_time: now + duration_us(5001),
            });

            // Should not belong
            packets.push(AckedPacket {
                seq_no: 4.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(5700),
                remote_recv_time: now + duration_us(6000),
            });

            packets
        };

        let mut group = ArrivalGroup::default();

        for p in packets {
            let need_new_group = group.belongs_to_group(&p).new_group();
            if !need_new_group {
                group.add_packet(p);
            }
        }

        assert_eq!(group.size, 4, "Expected group to contain 4 packets");
    }

    #[test]
    fn test_arrival_group_out_order_arrival_ignored() {
        let now = Instant::now();
        #[allow(clippy::vec_init_then_push)]
        let packets = {
            let mut packets = vec![];

            packets.push(AckedPacket {
                seq_no: 0.into(),
                size: DataSize::ZERO,
                local_send_time: now,
                remote_recv_time: now + duration_us(150),
            });

            packets.push(AckedPacket {
                seq_no: 1.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(50),
                remote_recv_time: now + duration_us(225),
            });

            packets.push(AckedPacket {
                seq_no: 2.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(1005),
                remote_recv_time: now + duration_us(1140),
            });

            packets.push(AckedPacket {
                seq_no: 3.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(4995),
                remote_recv_time: now + duration_us(5001),
            });

            // Should be skipped
            packets.push(AckedPacket {
                seq_no: 4.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(5001),
                remote_recv_time: now + duration_us(5000),
            });

            // Should not belong
            packets.push(AckedPacket {
                seq_no: 5.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(5700),
                remote_recv_time: now + duration_us(6000),
            });

            packets
        };

        let mut group = ArrivalGroup::default();

        for p in packets {
            let need_new_group = group.belongs_to_group(&p).new_group();
            if !need_new_group {
                group.add_packet(p);
            }
        }

        assert_eq!(group.size, 4, "Expected group to contain 4 packets");
    }

    #[test]
    fn test_arrival_group_arrival_membership() {
        let now = Instant::now();
        #[allow(clippy::vec_init_then_push)]
        let packets = {
            let mut packets = vec![];

            packets.push(AckedPacket {
                seq_no: 0.into(),
                size: DataSize::ZERO,
                local_send_time: now,
                remote_recv_time: now + duration_us(150),
            });

            packets.push(AckedPacket {
                seq_no: 1.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(50),
                remote_recv_time: now + duration_us(225),
            });

            packets.push(AckedPacket {
                seq_no: 2.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(5152),
                // Just less than 5ms inter arrival delta
                remote_recv_time: now + duration_us(5224),
            });

            // Should not belong
            packets.push(AckedPacket {
                seq_no: 3.into(),
                size: DataSize::ZERO,
                local_send_time: now + duration_us(5700),
                remote_recv_time: now + duration_us(6000),
            });

            packets
        };

        let mut group = ArrivalGroup::default();

        for p in packets {
            let need_new_group = group.belongs_to_group(&p).new_group();
            if !need_new_group {
                group.add_packet(p);
            }
        }

        assert_eq!(group.size, 3, "Expected group to contain 4 packets");
    }

    fn duration_us(us: u64) -> Duration {
        Duration::from_micros(us)
    }
}
