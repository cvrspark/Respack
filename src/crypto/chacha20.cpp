#include "chacha20.hpp"
#include <algorithm>
#include <cstring>
#include <random>
#include <span>
#include <stdexcept>

namespace respack::crypto {

namespace {

inline constexpr uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

inline uint32_t load32_le(const uint8_t* src) {
    return static_cast<uint32_t>(src[0]) |
          (static_cast<uint32_t>(src[1]) << 8) |
          (static_cast<uint32_t>(src[2]) << 16) |
          (static_cast<uint32_t>(src[3]) << 24);
}

inline void store32_le(uint8_t* dst, uint32_t val) {
    dst[0] = static_cast<uint8_t>(val);
    dst[1] = static_cast<uint8_t>(val >> 8);
    dst[2] = static_cast<uint8_t>(val >> 16);
    dst[3] = static_cast<uint8_t>(val >> 24);
}

void chacha20_block(uint32_t out[16], const uint32_t key[8], const uint32_t nonce[3], uint32_t counter) {
    static const uint8_t constants[16] = {
        'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
    };
    uint32_t state[16];

    state[0] = load32_le(constants);
    state[1] = load32_le(constants + 4);
    state[2] = load32_le(constants + 8);
    state[3] = load32_le(constants + 12);

    for (int i = 0; i < 8; ++i) state[4 + i] = key[i];

    state[12] = counter;
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    std::memcpy(out, state, sizeof(state));

    for (int i = 0; i < 10; ++i) {
        quarter_round(out[0], out[4], out[8], out[12]);
        quarter_round(out[1], out[5], out[9], out[13]);
        quarter_round(out[2], out[6], out[10], out[14]);
        quarter_round(out[3], out[7], out[11], out[15]);

        quarter_round(out[0], out[5], out[10], out[15]);
        quarter_round(out[1], out[6], out[11], out[12]);
        quarter_round(out[2], out[7], out[8], out[13]);
        quarter_round(out[3], out[4], out[9], out[14]);
    }

    for (int i = 0; i < 16; ++i) out[i] += state[i];
}

void poly1305_mac(uint8_t tag[16], const uint8_t* msg, size_t msg_len, const uint8_t key[32]) {
    uint32_t t0 = load32_le(key + 0);
    uint32_t t1 = load32_le(key + 4);
    uint32_t t2 = load32_le(key + 8);
    uint32_t t3 = load32_le(key + 12);

    t0 &= 0x0fffffff;
    t1 &= 0x0ffffffc;
    t2 &= 0x0ffffffc;
    t3 &= 0x0ffffffc;

    unsigned long r0 = t0 & 0x3ffffff;
    unsigned long r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    unsigned long r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    unsigned long r3 = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    unsigned long r4 = (t3 >> 8) & 0x3ffffff;

    uint32_t s0 = load32_le(key + 16);
    uint32_t s1 = load32_le(key + 20);
    uint32_t s2 = load32_le(key + 24);

    unsigned long h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    
    auto process_block = [&](const uint8_t* m, uint64_t padbit) {
        unsigned long d0 = load32_le(m + 0);
        unsigned long d1 = load32_le(m + 4);
        unsigned long d2 = load32_le(m + 8);
        unsigned long d3 = load32_le(m + 12);

        h0 += d0 & 0x3ffffff;
        h1 += ((d0 >> 26) | (d1 << 6)) & 0x3ffffff;
        h2 += ((d1 >> 20) | (d2 << 12)) & 0x3ffffff;
        h3 += ((d2 >> 14) | (d3 << 18)) & 0x3ffffff;
        h4 += (d3 >> 8) | (padbit << 24);

        unsigned long long bp0 = static_cast<unsigned long long>(h0) * r0 + static_cast<unsigned long long>(h1) * (5 * r4) + static_cast<unsigned long long>(h2) * (5 * r3) + static_cast<unsigned long long>(h3) * (5 * r2) + static_cast<unsigned long long>(h4) * (5 * r1);
        unsigned long long bp1 = static_cast<unsigned long long>(h0) * r1 + static_cast<unsigned long long>(h1) * r0 + static_cast<unsigned long long>(h2) * (5 * r4) + static_cast<unsigned long long>(h3) * (5 * r3) + static_cast<unsigned long long>(h4) * (5 * r2);
        unsigned long long bp2 = static_cast<unsigned long long>(h0) * r2 + static_cast<unsigned long long>(h1) * r1 + static_cast<unsigned long long>(h2) * r0 + static_cast<unsigned long long>(h3) * (5 * r4) + static_cast<unsigned long long>(h4) * (5 * r3);
        unsigned long long bp3 = static_cast<unsigned long long>(h0) * r3 + static_cast<unsigned long long>(h1) * r2 + static_cast<unsigned long long>(h2) * r1 + static_cast<unsigned long long>(h3) * r0 + static_cast<unsigned long long>(h4) * (5 * r4);
        unsigned long long bp4 = static_cast<unsigned long long>(h0) * r4 + static_cast<unsigned long long>(h1) * r3 + static_cast<unsigned long long>(h2) * r2 + static_cast<unsigned long long>(h3) * r1 + static_cast<unsigned long long>(h4) * r0;

        unsigned long c;
        h0 = bp0 & 0x3ffffff; c = bp0 >> 26; bp1 += c;
        h1 = bp1 & 0x3ffffff; c = bp1 >> 26; bp2 += c;
        h2 = bp2 & 0x3ffffff; c = bp2 >> 26; bp3 += c;
        h3 = bp3 & 0x3ffffff; c = bp3 >> 26; bp4 += c;
        h4 = bp4 & 0x3ffffff; c = bp4 >> 26; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    };

    size_t offset = 0;
    uint8_t block[16];
    while (msg_len >= 16) {
        process_block(msg + offset, 1);
        offset += 16;
        msg_len -= 16;
    }

    if (msg_len > 0) {
        std::memset(block, 0, sizeof(block));
        std::memcpy(block, msg + offset, msg_len);
        block[msg_len] = 1;
        process_block(block, 0);
    }

    unsigned long c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    unsigned long g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    unsigned long g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    unsigned long g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    unsigned long g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    unsigned long g4 = h4 + c - (1 << 26);

    unsigned long mask = (g4 >> 31) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    unsigned long long f0 = ((h0) | (h1 << 26)) + s0;
    unsigned long long f1 = ((h1 >> 6) | (h2 << 20)) + s1;
    unsigned long long f2 = ((h2 >> 12) | (h3 << 14)) + s2;

    store32_le(tag + 0, static_cast<uint32_t>(f0));
    store32_le(tag + 4, static_cast<uint32_t>(f0 >> 32));
    store32_le(tag + 8, static_cast<uint32_t>(f1));
    store32_le(tag + 12, static_cast<uint32_t>(f2));
}

} // namespace

void generate_nonce(uint8_t nonce[12]) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

    for (int i = 0; i < 3; ++i) {
        store32_le(nonce + i * 4, dist(gen));
    }
}

void chacha20_crypt(std::vector<uint8_t>& data, std::span<const uint8_t> key, const uint8_t nonce[12], uint32_t initial_counter) {
    if (key.size() != 32) return;

    uint32_t key32[8];
    for (int i = 0; i < 8; ++i) {
        key32[i] = load32_le(key.data() + i * 4);
    }

    uint32_t nonce32[3];
    for (int i = 0; i < 3; ++i) {
        nonce32[i] = load32_le(nonce + i * 4);
    }

    uint32_t block[16];
    uint8_t keystream[64];
    uint64_t counter = initial_counter;

    for (size_t i = 0; i < data.size(); i += 64) {
        if (counter > 0xFFFFFFFF) {
            throw std::overflow_error("ChaCha20 counter overflow.");
        }

        chacha20_block(block, key32, nonce32, static_cast<uint32_t>(counter++));

        for (int b = 0; b < 16; ++b) {
            store32_le(keystream + b * 4, block[b]);
        }

        size_t bytes_to_xor = std::min<size_t>(64, data.size() - i);
        for (size_t j = 0; j < bytes_to_xor; ++j) {
            data[i + j] ^= keystream[j];
        }
    }
}

uint32_t calculate_crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; ++i) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

bool is_valid_key(std::span<const uint8_t> key) { return key.size() == 32; }

res encrypt_payload(std::vector<uint8_t>& payload, std::span<const uint8_t> key, bool use_poly1305) {
    if (!is_valid_key(key)) {
        return {status::invalid_argument, "Key must be exactly 32 bytes (256 bits)."};
    }

    uint8_t nonce[12];
    try {
        generate_nonce(nonce);
    } catch (const std::exception& e) {
        return {status::io_error, e.what()};
    }

    uint32_t key32[8];
    for (int i = 0; i < 8; ++i) key32[i] = load32_le(key.data() + i * 4);
    uint32_t nonce32[3];
    for (int i = 0; i < 3; ++i) nonce32[i] = load32_le(nonce + i * 4);

    uint8_t poly_key[32]{};
    if (use_poly1305) {
        uint32_t poly_block[16];
        chacha20_block(poly_block, key32, nonce32, 0);
        for (int i = 0; i < 8; ++i) store32_le(poly_key + i * 4, poly_block[i]);
    }

    uint32_t initial_counter = use_poly1305 ? 1 : 0;
    try {
        chacha20_crypt(payload, key, nonce, initial_counter);
    } catch (const std::exception& e) {
        return {status::invalid_argument, e.what()};
    }

    if (use_poly1305) {
        uint8_t tag[16];
        poly1305_mac(tag, payload.data(), payload.size(), poly_key);
        payload.insert(payload.begin(), tag, tag + 16);
        payload.insert(payload.begin(), nonce, nonce + 12);
    } else {
        payload.insert(payload.begin(), nonce, nonce + 12);
    }

    return {status::ok, ""};
}

res decrypt_payload(std::vector<uint8_t>& payload, std::span<const uint8_t> key, bool expect_poly1305) {
    if (!is_valid_key(key)) {
        return {status::invalid_argument, "Key must be exactly 32 bytes (256 bits)."};
    }

    size_t min_header_size = expect_poly1305 ? 28 : 12;
    if (payload.size() < min_header_size) {
        return {status::invalid_argument, "Payload too short: missing header data."};
    }

    uint8_t nonce[12];
    std::memcpy(nonce, payload.data(), 12);

    std::vector<uint8_t> ciphertext;
    uint32_t initial_counter = 0;

    uint32_t key32[8];
    for (int i = 0; i < 8; ++i) key32[i] = load32_le(key.data() + i * 4);
    uint32_t nonce32[3];
    for (int i = 0; i < 3; ++i) nonce32[i] = load32_le(nonce + i * 4);

    if (expect_poly1305) {
        uint8_t expected_tag[16];
        std::memcpy(expected_tag, payload.data() + 12, 16);

        ciphertext.assign(payload.begin() + 28, payload.end());

        uint32_t poly_block[16];
        chacha20_block(poly_block, key32, nonce32, 0);
        uint8_t poly_key[32];
        for (int i = 0; i < 8; ++i) store32_le(poly_key + i * 4, poly_block[i]);

        uint8_t computed_tag[16];
        poly1305_mac(computed_tag, ciphertext.data(), ciphertext.size(), poly_key);

        uint8_t diff = 0;
        for (int i = 0; i < 16; ++i) {
            diff |= expected_tag[i] ^ computed_tag[i];
        }
        if (diff != 0) {
            return {status::invalid_argument, "Authentication failed: payload tampered or incorrect key."};
        }

        initial_counter = 1;
    } else {
        ciphertext.assign(payload.begin() + 12, payload.end());
        initial_counter = 0;
    }

    try {
        chacha20_crypt(ciphertext, key, nonce, initial_counter);
    } catch (const std::exception& e) {
        return {status::invalid_argument, e.what()};
    }

    payload = std::move(ciphertext);
    return {status::ok, ""};
}

} // namespace respack::crypto