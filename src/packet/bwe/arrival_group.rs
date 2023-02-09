use std::mem;
use std::time::{Duration, Instant};

use crate::rtp::SeqNo;

use super::AckedPacket;

const BURST_TIME_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Default)]
pub struct ArrivalGroup {
    first_seq_no: Option<SeqNo>,
    last_seq_no: Option<SeqNo>,
    first_local_send_time: Option<Instant>,
    local_send_time: Option<Instant>,
    remote_recv_time: Option<Instant>,
    size: usize,
}

impl ArrivalGroup {
    /// Maybe add a packet to the group.
    ///
    /// ## Return
    ///
    /// * [`Belongs::Belongs`] if the packet belongs to the group and was added.
    /// * [`Belongs::NewGroup`] if the packet is the start of a new group and thus wasn't added.
    ///                         The caller should create a new group and add this packet to the
    ///                         group.
    /// * [`Belongs::Skipped`] if the packet was skipped i.e. because it was out of order.
    fn add_packet(&mut self, packet: AckedPacket) -> Belongs {
        let belongs = self.belongs_to_group(&packet);

        if belongs == Belongs::NewGroup || belongs == Belongs::Skipped {
            return belongs;
        }

        self.remote_recv_time = Some(packet.remote_recv_time);

        if self.first_local_send_time.is_none() {
            self.first_local_send_time = Some(packet.local_send_time);
            self.first_seq_no = Some(packet.seq_no);
        }

        self.local_send_time = self.local_send_time.max(Some(packet.local_send_time));
        self.size += 1;
        self.last_seq_no = Some(packet.seq_no);

        Belongs::Belongs
    }

    fn belongs_to_group(&self, packet: &AckedPacket) -> Belongs {
        let Some(first_local_send_time) = self.first_local_send_time else {
            // Start of the group
            return Belongs::Belongs;
        };

        let Some(send_diff) = packet
            .local_send_time
            .checked_duration_since(first_local_send_time) else {
                warn!("Out of order send");
                // Out of order
                return Belongs::Skipped;
        };

        if send_diff < BURST_TIME_INTERVAL {
            // Sent within the same burst interval
            return Belongs::Belongs;
        }

        let inter_arrival_time = packet
            .remote_recv_time
            .checked_duration_since(self.remote_recv_time());

        let Some(inter_arrival_time) = inter_arrival_time else {
            warn!("Out of order arrival");
            return Belongs::Skipped;
        };

        let inter_group_delay_variation = inter_arrival_time.as_secs_f64()
            - (packet.local_send_time - self.local_send_time()).as_secs_f64();

        return (inter_group_delay_variation < 0.0 && inter_arrival_time < BURST_TIME_INTERVAL)
            .into();
    }

    /// Calculate the inter group delay variation between self and a subsequent group.
    pub(super) fn inter_group_delay_variation(&self, other: &Self) -> f64 {
        let arrival_variation = self.arrival_variation(&other);
        let departure_variation = self.departure_variation(&other);

        assert!(arrival_variation >= 0.0);

        let result = arrival_variation - departure_variation;
        let first_seq_no = self.first_seq_no.unwrap();
        let last_seq_no = self.last_seq_no.unwrap();
        trace!("Delay variation for group({first_seq_no}..={last_seq_no}. {result} = {arrival_variation} - {departure_variation}");

        result
    }

    pub(super) fn departure_variation(&self, other: &Self) -> f64 {
        other
            .local_send_time()
            .checked_duration_since(self.local_send_time())
            .unwrap_or_else(|| {
                panic!(
                    "other.departure_time() = {:?} to be later than self.departure_time() = {:?}",
                    other.local_send_time(),
                    self.local_send_time()
                )
            })
            .as_millis() as f64
    }

    fn arrival_variation(&self, other: &Self) -> f64 {
        other
            .remote_recv_time()
            .checked_duration_since(self.remote_recv_time())
            .unwrap_or_else(|| {
                panic!(
                    "other.arrival_time() = {:?} to be later than self.arrival_time() = {:?}, other {:?}, self: {:?}",
                    other.remote_recv_time(),
                    self.remote_recv_time(),
                    other,
                    self,
                )
            }) .as_millis() as f64
    }

    /// The local send time i.e. departure time, for the group.
    ///
    /// Panics if the group doesn't have at least one packet.
    fn local_send_time(&self) -> Instant {
        self.local_send_time
            .expect("local_send_time to only be called on non-empty groups")
    }

    /// The remote receive time i.e. arrival time, for the group.
    ///
    /// Panics if the group doesn't have at least one packet.
    fn remote_recv_time(&self) -> Instant {
        self.remote_recv_time
            .expect("remote_recv_time to only be called on non-empty groups")
    }
}

/// Whether a given packet is belongs to a group or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Belongs {
    /// The packet is belongs to the group.
    Belongs,
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

impl From<bool> for Belongs {
    fn from(value: bool) -> Self {
        if value {
            Belongs::Belongs
        } else {
            Belongs::NewGroup
        }
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
    /// If adding this packet produced a new delay variation it is returned.
    pub(super) fn accumulate_packet(
        &mut self,
        packet: AckedPacket,
    ) -> Option<InterGroupDelayVariation> {
        let add_outcome = self.current_group.add_packet(packet);

        if !add_outcome.new_group() {
            return None;
        }

        // Variation between previous group and current.
        let delay_variation = self.inter_group_delay_variation();
        let send_delta = self.send_delta();

        let current_group = mem::replace(&mut self.current_group, ArrivalGroup::default());
        self.previous_group = Some(current_group);

        self.current_group.add_packet(packet);

        delay_variation.map(|delay| InterGroupDelayVariation {
            send_delta: send_delta.unwrap(),
            delay,
            last_remote_recv_time: packet.remote_recv_time,
        })
    }

    fn inter_group_delay_variation(&self) -> Option<f64> {
        self.previous_group
            .as_ref()
            .map(|prev| prev.inter_group_delay_variation(&self.current_group))
    }

    fn send_delta(&self) -> Option<f64> {
        self.previous_group
            .as_ref()
            .map(|prev| prev.departure_variation(&self.current_group))
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct InterGroupDelayVariation {
    pub(super) send_delta: f64,
    /// The delay variation.
    pub(super) delay: f64,
    /// The reported receive time for the last packet in the arrival group.
    pub(super) last_remote_recv_time: Instant,
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use super::{AckedPacket, ArrivalGroup, Belongs};

    #[test]
    fn test_arrival_group_all_packets_belong_to_empty_group() {
        let now = Instant::now();
        let group = ArrivalGroup::default();

        assert_eq!(
            group.belongs_to_group(&AckedPacket {
                seq_no: 1.into(),
                local_send_time: now,
                remote_recv_time: now + duration_us(10),
            }),
            Belongs::Belongs,
            "Any packet should belong to an empty arrival group"
        );
    }

    #[test]
    fn test_arrival_group_all_packets_sent_within_burst_interval_belong() {
        let now = Instant::now();
        let packets = {
            let mut packets = vec![];

            packets.push(AckedPacket {
                seq_no: 1.into(),
                local_send_time: now,
                remote_recv_time: now + duration_us(150),
            });

            packets.push(AckedPacket {
                seq_no: 1.into(),
                local_send_time: now + duration_us(50),
                remote_recv_time: now + duration_us(225),
            });

            packets.push(AckedPacket {
                seq_no: 2.into(),
                local_send_time: now + duration_us(1005),
                remote_recv_time: now + duration_us(1140),
            });

            packets.push(AckedPacket {
                seq_no: 3.into(),
                local_send_time: now + duration_us(4995),
                remote_recv_time: now + duration_us(5001),
            });

            // Should not belong
            packets.push(AckedPacket {
                seq_no: 4.into(),
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

    fn duration_us(us: u64) -> Duration {
        Duration::from_micros(us)
    }
}
