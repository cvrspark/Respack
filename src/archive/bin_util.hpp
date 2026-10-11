#pragma once

#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

namespace respack::util {

template <typename T> inline void append_struct(std::vector<uint8_t>& vec, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable");
    const auto* ptr = reinterpret_cast<const uint8_t*>(&value);
    vec.insert(vec.end(), ptr, ptr + sizeof(T));
}

template <typename T> inline bool read_struct(const std::vector<uint8_t>& vec, size_t offset, T& out) {
    static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable");
    if (offset + sizeof(T) > vec.size())
        return false;
    std::memcpy(&out, vec.data() + offset, sizeof(T));
    return true;
}

} // namespace respack::util