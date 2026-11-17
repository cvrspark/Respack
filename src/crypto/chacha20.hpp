#pragma once

#include "../res.hpp"
#include <cstdint>
#include <span>
#include <vector>

namespace respack::crypto {

void generate_nonce(uint8_t nonce[12]);

void chacha20_crypt(std::vector<uint8_t>& data, std::span<const uint8_t> key, const uint8_t nonce[12], uint32_t initial_counter = 1);

uint32_t calculate_crc32(const std::vector<uint8_t>& data);

bool is_valid_key(std::span<const uint8_t> key);

res encrypt_payload(std::vector<uint8_t>& payload, std::span<const uint8_t> key, bool use_poly1305 = true);
res decrypt_payload(std::vector<uint8_t>& payload, std::span<const uint8_t> key, bool expect_poly1305 = true);

} // namespace respack::crypto