#include "../main.hxx"
#include <random>
#include <stdexcept>

namespace respack {

namespace {
constexpr char BASE64URL_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789-_";

uint8_t base64url_char_to_val(char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '-')
        return 62;
    if (c == '_')
        return 63;
    throw std::invalid_argument("Invalid character in base64url string.");
}
} // namespace

std::vector<uint8_t> gen_key() {
    constexpr size_t KEY_SIZE = 32;
    std::vector<uint8_t> key(KEY_SIZE);

    std::random_device rd;
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        key[i] = static_cast<uint8_t>(rd() & 0xFF);
    }

    return key;
}

std::string key_to_string(const std::vector<uint8_t>& key) {
    std::string result;
    result.reserve(((key.size() + 2) / 3) * 4);

    size_t i = 0;
    size_t len = key.size();

    while (len >= 3) {
        uint32_t val = (static_cast<uint32_t>(key[i]) << 16) |
                       (static_cast<uint32_t>(key[i + 1]) << 8) |
                       static_cast<uint32_t>(key[i + 2]);

        result.push_back(BASE64URL_CHARS[(val >> 18) & 0x3F]);
        result.push_back(BASE64URL_CHARS[(val >> 12) & 0x3F]);
        result.push_back(BASE64URL_CHARS[(val >> 6) & 0x3F]);
        result.push_back(BASE64URL_CHARS[val & 0x3F]);
        i += 3;
        len -= 3;
    }

    if (len == 2) {
        uint32_t val = (static_cast<uint32_t>(key[i]) << 16) |
                       (static_cast<uint32_t>(key[i + 1]) << 8);

        result.push_back(BASE64URL_CHARS[(val >> 18) & 0x3F]);
        result.push_back(BASE64URL_CHARS[(val >> 12) & 0x3F]);
        result.push_back(BASE64URL_CHARS[(val >> 6) & 0x3F]);
    } else if (len == 1) {
        uint32_t val = static_cast<uint32_t>(key[i]) << 16;

        result.push_back(BASE64URL_CHARS[(val >> 18) & 0x3F]);
        result.push_back(BASE64URL_CHARS[(val >> 12) & 0x3F]);
    }

    return result;
}

std::vector<uint8_t> key_from_string(const std::string& key_str) {
    std::vector<uint8_t> key;
    size_t len = key_str.size();

    if (len == 0)
        return key;

    key.reserve((len * 3) / 4);

    size_t i = 0;
    while (len >= 4) {
        uint32_t val = (static_cast<uint32_t>(base64url_char_to_val(key_str[i])) << 18) |
                       (static_cast<uint32_t>(base64url_char_to_val(key_str[i + 1])) << 12) |
                       (static_cast<uint32_t>(base64url_char_to_val(key_str[i + 2])) << 6) |
                       static_cast<uint32_t>(base64url_char_to_val(key_str[i + 3]));

        key.push_back((val >> 16) & 0xFF);
        key.push_back((val >> 8) & 0xFF);
        key.push_back(val & 0xFF);

        i += 4;
        len -= 4;
    }

    if (len == 3) {
        uint8_t c0 = base64url_char_to_val(key_str[i]);
        uint8_t c1 = base64url_char_to_val(key_str[i + 1]);
        uint8_t c2 = base64url_char_to_val(key_str[i + 2]);

        if (c2 & 0x03) {
            throw std::invalid_argument("Invalid base64url padding bits in key.");
        }

        uint32_t val = (static_cast<uint32_t>(c0) << 18) |
                       (static_cast<uint32_t>(c1) << 12) |
                       (static_cast<uint32_t>(c2) << 6);

        key.push_back((val >> 16) & 0xFF);
        key.push_back((val >> 8) & 0xFF);
    } else if (len == 2) {
        uint8_t c0 = base64url_char_to_val(key_str[i]);
        uint8_t c1 = base64url_char_to_val(key_str[i + 1]);

        if (c1 & 0x0F) {
            throw std::invalid_argument("Invalid base64url padding bits in key.");
        }

        uint32_t val = (static_cast<uint32_t>(c0) << 18) |
                       (static_cast<uint32_t>(c1) << 12);

        key.push_back((val >> 16) & 0xFF);
    } else if (len == 1) {
        throw std::invalid_argument("Invalid base64url string length.");
    }

    return key;
}

} // namespace respack