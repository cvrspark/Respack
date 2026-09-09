#include "chacha20.hxx"
#include <algorithm>
#include <cstring>
#include <random>
#include <stdexcept>

namespace respack::crypto {

namespace {

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA20_QUARTERROUND(a, b, c, d)                                                                                                  \
    a += b;                                                                                                                                \
    d ^= a;                                                                                                                                \
    d = ROTL32(d, 16);                                                                                                                     \
    c += d;                                                                                                                                \
    b ^= c;                                                                                                                                \
    b = ROTL32(b, 12);                                                                                                                     \
    a += b;                                                                                                                                \
    d ^= a;                                                                                                                                \
    d = ROTL32(d, 8);                                                                                                                      \
    c += d;                                                                                                                                \
    b ^= c;                                                                                                                                \
    b = ROTL32(b, 7);

inline uint32_t load32_le(const uint8_t* src) {
    return static_cast<uint32_t>(src[0]) | (static_cast<uint32_t>(src[1]) << 8) | (static_cast<uint32_t>(src[2]) << 16) |
           (static_cast<uint32_t>(src[3]) << 24);
}

inline void store32_le(uint8_t* dst, uint32_t val) {
    dst[0] = static_cast<uint8_t>(val);
    dst[1] = static_cast<uint8_t>(val >> 8);
    dst[2] = static_cast<uint8_t>(val >> 16);
    dst[3] = static_cast<uint8_t>(val >> 24);
}

void chacha20_block(uint32_t out[16], const uint32_t key[8], const uint32_t nonce[3], uint32_t counter) {
    static const char constants[] = "expand 32-byte k";
    uint32_t state[16];

    state[0] = load32_le(reinterpret_cast<const uint8_t*>(constants));
    state[1] = load32_le(reinterpret_cast<const uint8_t*>(constants + 4));
    state[2] = load32_le(reinterpret_cast<const uint8_t*>(constants + 8));
    state[3] = load32_le(reinterpret_cast<const uint8_t*>(constants + 12));

    for (int i = 0; i < 8; ++i)
        state[4 + i] = key[i];
    state[12] = counter;
    for (int i = 0; i < 3; ++i)
        state[13 + i] = nonce[i];

    std::memcpy(out, state, sizeof(state));

    for (int i = 0; i < 10; ++i) {
        CHACHA20_QUARTERROUND(out[0], out[4], out[8], out[12]);
        CHACHA20_QUARTERROUND(out[1], out[5], out[9], out[13]);
        CHACHA20_QUARTERROUND(out[2], out[6], out[10], out[14]);
        CHACHA20_QUARTERROUND(out[3], out[7], out[11], out[15]);

        CHACHA20_QUARTERROUND(out[0], out[5], out[10], out[15]);
        CHACHA20_QUARTERROUND(out[1], out[6], out[11], out[12]);
        CHACHA20_QUARTERROUND(out[2], out[7], out[8], out[13]);
        CHACHA20_QUARTERROUND(out[3], out[4], out[9], out[14]);
    }

    for (int i = 0; i < 16; ++i) {
        out[i] += state[i];
    }
}

} // namespace

void generate_nonce(uint8_t nonce[12]) {
    std::random_device rd;
    for (int i = 0; i < 12; ++i) {
        nonce[i] = static_cast<uint8_t>(rd());
    }
}

void chacha20_crypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const uint8_t nonce[12], uint32_t initial_counter) {
    if (key.size() != 32)
        return;

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
            throw std::overflow_error("ChaCha20 counter overflow: maximum payload size exceeded.");
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

bool is_valid_key(const std::vector<uint8_t>& key) { return key.size() == 32; }

res encrypt_payload(std::vector<uint8_t>& payload, const std::vector<uint8_t>& key) {
    if (!is_valid_key(key)) {
        return {status::invalid_argument, "Key must be exactly 32 bytes (256 bits)."};
    }

    uint8_t nonce[12];
    try {
        generate_nonce(nonce);
    } catch (const std::exception& e) {
        return {status::io_error, e.what()};
    }

    try {
        chacha20_crypt(payload, key, nonce);
    } catch (const std::exception& e) {
        return {status::invalid_argument, e.what()};
    }

    payload.insert(payload.begin(), nonce, nonce + 12);
    return {status::ok, ""};
}

res decrypt_payload(std::vector<uint8_t>& payload, const std::vector<uint8_t>& key) {
    if (!is_valid_key(key)) {
        return {status::invalid_argument, "Key must be exactly 32 bytes (256 bits)."};
    }
    if (payload.size() < 12) {
        return {status::invalid_argument, "Payload missing 12-byte nonce header."};
    }

    uint8_t nonce[12];
    std::memcpy(nonce, payload.data(), 12);

    std::vector<uint8_t> ciphertext(payload.begin() + 12, payload.end());
    try {
        chacha20_crypt(ciphertext, key, nonce);
    } catch (const std::exception& e) {
        return {status::invalid_argument, e.what()};
    }

    payload = std::move(ciphertext);
    return {status::ok, ""};
}

} // namespace respack::crypto