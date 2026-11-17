#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <span>

#include "res.hpp"

namespace respack {

std::vector<uint8_t> gen_key();
std::string key_to_string(std::span<const uint8_t> key);
std::array<uint8_t, 32> key_from_string(const std::string& key_str);

res pack(const std::string& dir, const std::string& output_pkg, bool use_poly1305 = true);
res pack(const std::string& dir, const std::string& output_pkg, std::span<const uint8_t> key, bool use_poly1305 = true);

res unpack(const std::string& pkg, const std::string& output_dir, bool expect_poly1305 = true);
res unpack(const std::string& pkg, const std::string& output_dir, std::span<const uint8_t> key, bool expect_poly1305 = true);

} // namespace respack

#define RESPACK_VERSION "2.1"