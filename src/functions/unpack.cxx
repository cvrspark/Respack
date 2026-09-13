#include "../archive/bin_util.hxx"
#include "../archive/zip_spec.hxx"
#include "../crypto/chacha20.hxx"
#include "../main.hxx"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace respack::archive;

namespace respack {

namespace {

res unpack_internal(const std::string& pkg_path, const std::string& output_dir, const std::vector<uint8_t>* key) {
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

} // namespace

res unpack(const std::string& pkg_path, const std::string& output_dir) { 
    return unpack_internal(pkg_path, output_dir, nullptr); 
}

res unpack(const std::string& pkg_path, const std::string& output_dir, const std::vector<uint8_t>& key) {
    if (key.empty())
        return {status::invalid_argument, "Key cannot be empty."};
    return unpack_internal(pkg_path, output_dir, &key);
}

} // namespace respack