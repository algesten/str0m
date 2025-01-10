#include "bridge.h"

namespace webrtc {

std::unique_ptr<webrtc::InterArrivalDelta> new_inter_arrival_delta() {
    return std::make_unique<webrtc::InterArrivalDelta>(webrtc::TimeDelta::Millis(5));
}

bool ComputeDeltas(
    webrtc::InterArrivalDelta& self,
    uint64_t send_time_us,
    uint64_t arrival_time_us,
    uint64_t system_time_us,
    uint64_t packet_size,
    int64_t& send_time_delta_us,
    int64_t& arrival_time_delta_us,
    uint64_t& packet_size_delta
) {
    TimeDelta send_delta = TimeDelta::Zero();
    TimeDelta recv_delta = TimeDelta::Zero();
    int size_delta = 0;

    auto computed_deltas = self.ComputeDeltas(
        webrtc::Timestamp::Micros(send_time_us),
        webrtc::Timestamp::Micros(arrival_time_us),
        webrtc::Timestamp::Micros(system_time_us),
        packet_size,
        &send_delta,
        &recv_delta,
        &size_delta
    );

    send_time_delta_us = send_delta.us();
    arrival_time_delta_us = recv_delta.us();
    packet_size_delta = size_delta;

    return computed_deltas;
};

}  // namespace bridge
