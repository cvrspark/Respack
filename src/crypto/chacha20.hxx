#pragma once

#include "../res.hxx"
#include <cstdint>
#include <vector>

namespace respack::crypto {

void generate_nonce(uint8_t nonce[12]);

void chacha20_crypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const uint8_t nonce[12], uint32_t initial_counter = 1);

uint32_t calculate_crc32(const std::vector<uint8_t>& data);

bool is_valid_key(const std::vector<uint8_t>& key);

res encrypt_payload(std::vector<uint8_t>& payload, const std::vector<uint8_t>& key);
res decrypt_payload(std::vector<uint8_t>& payload, const std::vector<uint8_t>& key);

} // namespace respack::crypto