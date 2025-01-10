#ifndef BRIDGE_H_
#define BRIDGE_H_

#include <cassert>
#include <chrono>
#include <iostream>
#include <memory>

#include "time_delta.h"
#include "inter_arrival_delta.h"

namespace webrtc {

    std::unique_ptr<webrtc::InterArrivalDelta> new_inter_arrival_delta();

    bool ComputeDeltas(
        webrtc::InterArrivalDelta& self,
        uint64_t send_time_us,
        uint64_t arrival_time_us,
        uint64_t system_time_us,
        uint64_t packet_size,
        int64_t& send_time_delta_us,
        int64_t& arrival_time_delta_us,
        uint64_t& packet_size_delta);

}  // namespace bridge

#endif  // BRIDGE_H_
