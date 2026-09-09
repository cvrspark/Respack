#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "res.hxx"

namespace respack {

std::vector<uint8_t> gen_key();
std::string key_to_string(const std::vector<uint8_t>& key);
std::vector<uint8_t> key_from_string(const std::string& key_str);

res pack(const std::string& dir, const std::string& output_pkg);
res pack(const std::string& dir, const std::string& output_pkg, const std::vector<uint8_t>& key);

res unpack(const std::string& pkg, const std::string& output_dir);
res unpack(const std::string& pkg, const std::string& output_dir, const std::vector<uint8_t>& key);

} // namespace respack
