/*
                                                            oooo
lib                                                         `888
oooo d8b  .ooooo.   .oooo.o oo.ooooo.   .oooo.    .ooooo.   888  oooo
`888""8P d88' `88b d88(  "8  888' `88b `P  )88b  d88' `"Y8  888 .8P'
 888     888ooo888 `"Y88b.   888   888  .oP"888  888        888888.
 888     888    .o o.  )88b  888   888 d8(  888  888   .o8  888 `88b.
d888b    `Y8bod8P' 8""888P'  888bod8P' `Y888""8o `Y8bod8P' o888o o888o
                             888
                            o888o

**MIT License**

Copyright (c) 2026 respack contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace spk::respack {

enum class status { ok = 0, io_error, crypto_error, invalid_argument, corrupted_data };

struct res {
    status code;
    std::string message;
    explicit operator bool() const { return code == status::ok; }
};

namespace util {

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

} // namespace util

namespace archive {

constexpr uint32_t SIGNATURE_LOCAL_FILE_HEADER = 0x04034b50;
constexpr uint32_t SIGNATURE_CENTRAL_DIRECTORY_HEADER = 0x02014b50;
constexpr uint32_t SIGNATURE_END_OF_CENTRAL_DIRECTORY = 0x06054b50;

#pragma pack(push, 1)
struct LocalFileHeader {
    uint32_t signature = SIGNATURE_LOCAL_FILE_HEADER;
    uint16_t version_needed = 10;
    uint16_t flags = 0;
    uint16_t compression_method = 0;
    uint16_t last_mod_time = 0;
    uint16_t last_mod_date = 0;
    uint32_t crc32 = 0;
    uint32_t compressed_size = 0;
    uint32_t uncompressed_size = 0;
    uint16_t file_name_length = 0;
    uint16_t extra_field_length = 0;
};

struct CentralDirectoryHeader {
    uint32_t signature = SIGNATURE_CENTRAL_DIRECTORY_HEADER;
    uint16_t version_made_by = 20;
    uint16_t version_needed = 10;
    uint16_t flags = 0;
    uint16_t compression_method = 0;
    uint16_t last_mod_time = 0;
    uint16_t last_mod_date = 0;
    uint32_t crc32 = 0;
    uint32_t compressed_size = 0;
    uint32_t uncompressed_size = 0;
    uint16_t file_name_length = 0;
    uint16_t extra_field_length = 0;
    uint16_t file_comment_length = 0;
    uint16_t disk_number_start = 0;
    uint16_t internal_file_attrib = 0;
    uint32_t external_file_attrib = 0;
    uint32_t relative_offset_local_header = 0;
};

struct EndOfCentralDirectoryRecord {
    uint32_t signature = SIGNATURE_END_OF_CENTRAL_DIRECTORY;
    uint16_t disk_number = 0;
    uint16_t start_disk = 0;
    uint16_t entries_on_disk = 0;
    uint16_t total_entries = 0;
    uint32_t size_of_cd = 0;
    uint32_t offset_of_cd = 0;
    uint16_t comment_length = 0;
};
#pragma pack(pop)

struct ZipEntryMeta {
    std::string rel_path;
    uint32_t crc32;
    uint32_t size;
    uint32_t local_header_offset;
};

} // namespace archive

namespace crypto {

namespace detail {

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA20_QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16);    \
    c += d; b ^= c; b = ROTL32(b, 12);    \
    a += b; d ^= a; d = ROTL32(d, 8);     \
    c += d; b ^= c; b = ROTL32(b, 7);

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

inline void chacha20_block(uint32_t out[16], const uint32_t key[8], const uint32_t nonce[3], uint32_t counter) {
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
        CHACHA20_QUARTERROUND(out[0], out[4], out[8], out[12]);
        CHACHA20_QUARTERROUND(out[1], out[5], out[9], out[13]);
        CHACHA20_QUARTERROUND(out[2], out[6], out[10], out[14]);
        CHACHA20_QUARTERROUND(out[3], out[7], out[11], out[15]);

        CHACHA20_QUARTERROUND(out[0], out[5], out[10], out[15]);
        CHACHA20_QUARTERROUND(out[1], out[6], out[11], out[12]);
        CHACHA20_QUARTERROUND(out[2], out[7], out[8], out[13]);
        CHACHA20_QUARTERROUND(out[3], out[4], out[9], out[14]);
    }

    for (int i = 0; i < 16; ++i) out[i] += state[i];
}

#undef ROTL32
#undef CHACHA20_QUARTERROUND

} // namespace detail

inline void generate_nonce(uint8_t nonce[12]) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

    for (int i = 0; i < 3; ++i) {
        detail::store32_le(nonce + i * 4, dist(gen));
    }
}

inline void chacha20_crypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const uint8_t nonce[12], uint32_t initial_counter = 1) {
    if (key.size() != 32)
        return;

    uint32_t key32[8];
    for (int i = 0; i < 8; ++i) {
        key32[i] = detail::load32_le(key.data() + i * 4);
    }

    uint32_t nonce32[3];
    for (int i = 0; i < 3; ++i) {
        nonce32[i] = detail::load32_le(nonce + i * 4);
    }

    uint32_t block[16];
    uint8_t keystream[64];
    uint64_t counter = initial_counter;

    for (size_t i = 0; i < data.size(); i += 64) {
        if (counter > 0xFFFFFFFF) {
            throw std::overflow_error("ChaCha20 counter overflow: maximum payload size exceeded.");
        }

        detail::chacha20_block(block, key32, nonce32, static_cast<uint32_t>(counter++));

        for (int b = 0; b < 16; ++b) {
            detail::store32_le(keystream + b * 4, block[b]);
        }

        size_t bytes_to_xor = std::min<size_t>(64, data.size() - i);
        for (size_t j = 0; j < bytes_to_xor; ++j) {
            data[i + j] ^= keystream[j];
        }
    }
}

inline uint32_t calculate_crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; ++i) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

inline bool is_valid_key(const std::vector<uint8_t>& key) { return key.size() == 32; }

inline res encrypt_payload(std::vector<uint8_t>& payload, const std::vector<uint8_t>& key) {
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

inline res decrypt_payload(std::vector<uint8_t>& payload, const std::vector<uint8_t>& key) {
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

} // namespace crypto

namespace detail {

constexpr char BASE64URL_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789-_";

inline uint8_t base64url_char_to_val(char c) {
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

} // namespace detail

inline std::string key_to_string(const std::vector<uint8_t>& key) {
    std::string result;
    result.reserve(((key.size() + 2) / 3) * 4);

    size_t i = 0;
    size_t len = key.size();

    while (len >= 3) {
        uint32_t val = (static_cast<uint32_t>(key[i]) << 16) |
                       (static_cast<uint32_t>(key[i + 1]) << 8) |
                       static_cast<uint32_t>(key[i + 2]);

        result.push_back(detail::BASE64URL_CHARS[(val >> 18) & 0x3F]);
        result.push_back(detail::BASE64URL_CHARS[(val >> 12) & 0x3F]);
        result.push_back(detail::BASE64URL_CHARS[(val >> 6) & 0x3F]);
        result.push_back(detail::BASE64URL_CHARS[val & 0x3F]);
        i += 3;
        len -= 3;
    }

    if (len == 2) {
        uint32_t val = (static_cast<uint32_t>(key[i]) << 16) |
                       (static_cast<uint32_t>(key[i + 1]) << 8);

        result.push_back(detail::BASE64URL_CHARS[(val >> 18) & 0x3F]);
        result.push_back(detail::BASE64URL_CHARS[(val >> 12) & 0x3F]);
        result.push_back(detail::BASE64URL_CHARS[(val >> 6) & 0x3F]);
    } else if (len == 1) {
        uint32_t val = static_cast<uint32_t>(key[i]) << 16;

        result.push_back(detail::BASE64URL_CHARS[(val >> 18) & 0x3F]);
        result.push_back(detail::BASE64URL_CHARS[(val >> 12) & 0x3F]);
    }

    return result;
}

inline std::vector<uint8_t> key_from_string(const std::string& key_str) {
    std::vector<uint8_t> key;
    size_t len = key_str.size();

    if (len == 0)
        return key;

    key.reserve((len * 3) / 4);

    size_t i = 0;
    while (len >= 4) {
        uint32_t val = (static_cast<uint32_t>(detail::base64url_char_to_val(key_str[i])) << 18) |
                       (static_cast<uint32_t>(detail::base64url_char_to_val(key_str[i + 1])) << 12) |
                       (static_cast<uint32_t>(detail::base64url_char_to_val(key_str[i + 2])) << 6) |
                       static_cast<uint32_t>(detail::base64url_char_to_val(key_str[i + 3]));

        key.push_back((val >> 16) & 0xFF);
        key.push_back((val >> 8) & 0xFF);
        key.push_back(val & 0xFF);

        i += 4;
        len -= 4;
    }

    if (len == 3) {
        uint8_t c0 = detail::base64url_char_to_val(key_str[i]);
        uint8_t c1 = detail::base64url_char_to_val(key_str[i + 1]);
        uint8_t c2 = detail::base64url_char_to_val(key_str[i + 2]);

        if (c2 & 0x03) {
            throw std::invalid_argument("Invalid base64url padding bits in key.");
        }

        uint32_t val = (static_cast<uint32_t>(c0) << 18) |
                       (static_cast<uint32_t>(c1) << 12) |
                       (static_cast<uint32_t>(c2) << 6);

        key.push_back((val >> 16) & 0xFF);
        key.push_back((val >> 8) & 0xFF);
    } else if (len == 2) {
        uint8_t c0 = detail::base64url_char_to_val(key_str[i]);
        uint8_t c1 = detail::base64url_char_to_val(key_str[i + 1]);

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

namespace detail {

inline res pack_internal(const std::string& dir, const std::string& output_pkg, const std::vector<uint8_t>* key) {
    namespace fs = std::filesystem;
    using namespace spk::respack::archive;

    fs::path src_dir(dir);

    std::error_code ec;
    if (!fs::exists(src_dir, ec) || !fs::is_directory(src_dir, ec)) {
        return {status::invalid_argument, "Source directory does not exist or is not a directory."};
    }

    fs::path out_path(output_pkg);
    if (out_path.extension().empty()) {
        out_path += ".rvlt";
    }

    std::vector<uint8_t> zip_stream;
    std::vector<ZipEntryMeta> entries;

    auto dir_iter = fs::recursive_directory_iterator(src_dir, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
        return {status::io_error, "Failed to iterate source directory: " + ec.message()};
    }

    for (const auto& entry : dir_iter) {
        if (entry.is_regular_file(ec)) {
            std::string rel_path = fs::relative(entry.path(), src_dir, ec).generic_string();
            if (ec) {
                return {status::io_error, "Failed to resolve relative path."};
            }

            if (rel_path.size() > std::numeric_limits<uint16_t>::max()) {
                return {status::invalid_argument, "Relative path length exceeds 16-bit ZIP limit: " + rel_path};
            }

            std::ifstream in(entry.path(), std::ios::binary | std::ios::ate);
            if (!in.is_open()) {
                return {status::io_error, "Failed to open input file: " + rel_path};
            }

            const auto file_size_s = in.tellg();
            if (file_size_s < 0 || file_size_s > static_cast<std::streamoff>(std::numeric_limits<uint32_t>::max())) {
                return {status::invalid_argument, "File size exceeds standard 32-bit ZIP limits: " + rel_path};
            }
            const uint32_t file_size = static_cast<uint32_t>(file_size_s);
            in.seekg(0, std::ios::beg);

            std::vector<uint8_t> content(file_size);
            if (file_size > 0 && !in.read(reinterpret_cast<char*>(content.data()), file_size)) {
                return {status::io_error, "Failed to read file content: " + rel_path};
            }

            const uint64_t projected_offset = static_cast<uint64_t>(zip_stream.size());
            if (projected_offset > std::numeric_limits<uint32_t>::max()) {
                return {status::invalid_argument, "Archive size exceeds standard 32-bit ZIP limits."};
            }

            ZipEntryMeta meta{
                rel_path,
                crypto::calculate_crc32(content),
                file_size,
                static_cast<uint32_t>(projected_offset)
            };

            LocalFileHeader lfh{};
            lfh.crc32 = meta.crc32;
            lfh.compressed_size = meta.size;
            lfh.uncompressed_size = meta.size;
            lfh.file_name_length = static_cast<uint16_t>(rel_path.size());

            util::append_struct(zip_stream, lfh);
            zip_stream.insert(zip_stream.end(), rel_path.begin(), rel_path.end());
            zip_stream.insert(zip_stream.end(), content.begin(), content.end());

            entries.push_back(meta);
        }
    }

    if (entries.size() > std::numeric_limits<uint16_t>::max()) {
        return {status::invalid_argument, "Too many files for standard 16-bit ZIP entry limits."};
    }

    if (zip_stream.size() > std::numeric_limits<uint32_t>::max()) {
        return {status::invalid_argument, "Central directory offset exceeds standard 32-bit ZIP limits."};
    }

    const uint32_t cd_offset = static_cast<uint32_t>(zip_stream.size());

    for (const auto& meta : entries) {
        CentralDirectoryHeader cdh{};
        cdh.crc32 = meta.crc32;
        cdh.compressed_size = meta.size;
        cdh.uncompressed_size = meta.size;
        cdh.file_name_length = static_cast<uint16_t>(meta.rel_path.size());
        cdh.relative_offset_local_header = meta.local_header_offset;

        util::append_struct(zip_stream, cdh);
        zip_stream.insert(zip_stream.end(), meta.rel_path.begin(), meta.rel_path.end());
    }

    EndOfCentralDirectoryRecord eocd{};
    eocd.entries_on_disk = static_cast<uint16_t>(entries.size());
    eocd.total_entries = static_cast<uint16_t>(entries.size());
    eocd.size_of_cd = static_cast<uint32_t>(zip_stream.size()) - cd_offset;
    eocd.offset_of_cd = cd_offset;

    util::append_struct(zip_stream, eocd);

    if (key && !key->empty()) {
        auto crypt_res = crypto::encrypt_payload(zip_stream, *key);
        if (crypt_res.code != status::ok)
            return crypt_res;
    }

    std::ofstream out(out_path, std::ios::binary);
    if (!out.is_open())
        return {status::io_error, "Failed to create output file."};

    out.write(reinterpret_cast<const char*>(zip_stream.data()), static_cast<std::streamsize>(zip_stream.size()));
    if (!out.good()) {
        return {status::io_error, "Failed to write package content to disk."};
    }

    return {status::ok, "Package created successfully."};
}

inline res unpack_internal(const std::string& pkg_path, const std::string& output_dir, const std::vector<uint8_t>* key) {
    namespace fs = std::filesystem;
    using namespace spk::respack::archive;

    std::ifstream in(pkg_path, std::ios::binary | std::ios::ate);
    if (!in.is_open())
        return {status::io_error, "Failed to open package file."};

    const auto file_size = in.tellg();
    if (file_size <= 0)
        return {status::invalid_argument, "Package file is empty or unreadable."};

    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(file_size));
    if (!in.read(reinterpret_cast<char*>(buffer.data()), file_size)) {
        return {status::io_error, "Failed to read package file into memory."};
    }

    if (key && !key->empty()) {
        auto crypt_res = crypto::decrypt_payload(buffer, *key);
        if (crypt_res.code != status::ok)
            return crypt_res;
    }

    size_t cursor = 0;
    std::error_code ec;
    fs::path target_dir = fs::absolute(output_dir, ec);
    if (ec) {
        return {status::invalid_argument, "Invalid target directory path."};
    }

    fs::create_directories(target_dir, ec);

    LocalFileHeader lfh{};
    while (util::read_struct(buffer, cursor, lfh)) {
        if (lfh.signature != SIGNATURE_LOCAL_FILE_HEADER)
            break;

        cursor += sizeof(LocalFileHeader);

        const size_t rem_buf = buffer.size() - cursor;
        const size_t header_payload_len = static_cast<size_t>(lfh.file_name_length) + lfh.extra_field_length;

        if (header_payload_len > rem_buf || lfh.compressed_size > (rem_buf - header_payload_len)) {
            return {status::corrupted_data, "Corrupted archive stream or unexpected EOF."};
        }

        std::string filename(reinterpret_cast<const char*>(buffer.data() + cursor), lfh.file_name_length);
        cursor += lfh.file_name_length + lfh.extra_field_length;

        fs::path file_out_path = fs::weakly_canonical(target_dir / filename, ec);

        auto [root_end, dummy] = std::mismatch(target_dir.begin(), target_dir.end(), file_out_path.begin());
        if (root_end != target_dir.end()) {
            return {status::invalid_argument, "Path traversal attempt detected in filename: " + filename};
        }

        fs::create_directories(file_out_path.parent_path(), ec);

        std::vector<uint8_t> file_data(buffer.begin() + cursor, buffer.begin() + cursor + lfh.compressed_size);
        cursor += lfh.compressed_size;

        if (crypto::calculate_crc32(file_data) != lfh.crc32) {
            return {status::corrupted_data, "CRC32 mismatch on file: " + filename};
        }

        std::ofstream out(file_out_path, std::ios::binary);
        if (!out.is_open())
            return {status::io_error, "Failed to create output file: " + filename};

        out.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
        if (!out.good()) {
            return {status::io_error, "Failed to write extracted file content: " + filename};
        }
    }

    return {status::ok, "Unpacked successfully."};
}

} // namespace detail

inline res pack(const std::string& dir, const std::string& output_pkg) { 
    return detail::pack_internal(dir, output_pkg, nullptr); 
}

inline res pack(const std::string& dir, const std::string& output_pkg, const std::vector<uint8_t>& key) {
    if (key.empty())
        return {status::invalid_argument, "Key cannot be empty."};
    return detail::pack_internal(dir, output_pkg, &key);
}

inline res unpack(const std::string& pkg_path, const std::string& output_dir) { 
    return detail::unpack_internal(pkg_path, output_dir, nullptr); 
}

inline res unpack(const std::string& pkg_path, const std::string& output_dir, const std::vector<uint8_t>& key) {
    if (key.empty())
        return {status::invalid_argument, "Key cannot be empty."};
    return detail::unpack_internal(pkg_path, output_dir, &key);
}

} // namespace spk::respack