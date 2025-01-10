pub use self::ffi::*;

#[cxx::bridge(namespace = "webrtc")]
pub mod ffi {
    #[derive(Debug, Eq, Hash, PartialEq)]
    #[repr(i32)]
    pub enum BandwidthUsage {
        kBwNormal,
        kBwUnderusing,
        kBwOverusing,
        kLast,
    }

    unsafe extern "C++" {
        include!("bridge.h");

        pub type InterArrivalDelta;

        pub fn new_inter_arrival_delta() -> UniquePtr<InterArrivalDelta>;

        // This function returns true if a delta was computed, or false if the current
        // group is still incomplete or if only one group has been completed.
        //
        // `send_time` is the send time.
        // `arrival_time` is the time at which the packet arrived.
        // `packet_size` is the size of the packet.
        // `timestamp_delta` (output) is the computed send time delta.
        // `arrival_time_delta` (output) is the computed arrival-time delta.
        // `packet_size_delta` (output) is the computed size delta.
        //
        // bool ComputeDeltas(
        //      Timestamp send_time,            // packet_feedback.sent_packet.send_time,
        //      Timestamp arrival_time,         // packet_feedback.receive_time,
        //      Timestamp system_time,          // at_time
        //      size_t packet_size,             // packet_size.bytes(),
        //      TimeDelta* send_time_delta,     // &send_delta,
        //      TimeDelta* arrival_time_delta,  // &recv_delta,
        //      int* packet_size_delta          // &size_delta
        // );
        pub fn ComputeDeltas(
            iad: Pin<&mut InterArrivalDelta>,
            send_time_us: u64,
            arrival_time_us: u64,
            system_time_us: u64,
            packet_size_bytes: u64,
            send_time_delta_us: &mut i64,
            arrival_time_delta_us: &mut i64,
            packet_size_delta: &mut u64,
        ) -> bool;

    }
}

unsafe impl Send for InterArrivalDelta {}
