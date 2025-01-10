/*
 *  Copyright (c) 2018 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#ifndef API_UNITS_TIMESTAMP_H_
#define API_UNITS_TIMESTAMP_H_

#include <cstdint>
#include <string>
#include <type_traits>

#include "time_delta.h"
#include "unit_base.h"  // IWYU pragma: export

namespace webrtc {
// Timestamp represents the time that has passed since some unspecified epoch.
// The epoch is assumed to be before any represented timestamps, this means that
// negative values are not valid. The most notable feature is that the
// difference of two Timestamps results in a TimeDelta.
class Timestamp final : public rtc_units_impl::UnitBase<Timestamp> {
 public:
  template <typename T>
  static constexpr Timestamp Seconds(T value) {
    static_assert(std::is_arithmetic<T>::value, "");
    return FromFraction(1'000'000, value);
  }
  template <typename T>
  static constexpr Timestamp Millis(T value) {
    static_assert(std::is_arithmetic<T>::value, "");
    return FromFraction(1'000, value);
  }
  template <typename T>
  static constexpr Timestamp Micros(T value) {
    static_assert(std::is_arithmetic<T>::value, "");
    return FromValue(value);
  }

  Timestamp() = delete;

  template <typename Sink>
  friend void AbslStringify(Sink& sink, Timestamp value);

  template <typename T = int64_t>
  constexpr T seconds() const {
    return ToFraction<1000000, T>();
  }
  template <typename T = int64_t>
  constexpr T ms() const {
    return ToFraction<1000, T>();
  }
  template <typename T = int64_t>
  constexpr T us() const {
    return ToValue<T>();
  }

  constexpr int64_t seconds_or(int64_t fallback_value) const {
    return ToFractionOr<1000000>(fallback_value);
  }
  constexpr int64_t ms_or(int64_t fallback_value) const {
    return ToFractionOr<1000>(fallback_value);
  }
  constexpr int64_t us_or(int64_t fallback_value) const {
    return ToValueOr(fallback_value);
  }

  constexpr Timestamp operator+(const TimeDelta delta) const {
    if (IsPlusInfinity() || delta.IsPlusInfinity()) {
      return PlusInfinity();
    } else if (IsMinusInfinity() || delta.IsMinusInfinity()) {
      return MinusInfinity();
    }
    return Timestamp::Micros(us() + delta.us());
  }
  constexpr Timestamp operator-(const TimeDelta delta) const {
    if (IsPlusInfinity() || delta.IsMinusInfinity()) {
      return PlusInfinity();
    } else if (IsMinusInfinity() || delta.IsPlusInfinity()) {
      return MinusInfinity();
    }
    return Timestamp::Micros(us() - delta.us());
  }
  constexpr TimeDelta operator-(const Timestamp other) const {
    if (IsPlusInfinity() || other.IsMinusInfinity()) {
      return TimeDelta::PlusInfinity();
    } else if (IsMinusInfinity() || other.IsPlusInfinity()) {
      return TimeDelta::MinusInfinity();
    }
    return TimeDelta::Micros(us() - other.us());
  }
  constexpr Timestamp& operator-=(const TimeDelta delta) {
    *this = *this - delta;
    return *this;
  }
  constexpr Timestamp& operator+=(const TimeDelta delta) {
    *this = *this + delta;
    return *this;
  }

 private:
  friend class rtc_units_impl::UnitBase<Timestamp>;
  using UnitBase::UnitBase;
  static constexpr bool one_sided = true;
};

std::string ToString(Timestamp value);

template <typename Sink>
void AbslStringify(Sink& sink, Timestamp value) {
  sink.Append(ToString(value));
}

}  // namespace webrtc

#endif  // API_UNITS_TIMESTAMP_H_
