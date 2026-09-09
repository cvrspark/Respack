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
    std::ifstream in(pkg_path, std::ios::binary);
    if (!in.is_open())
        return {status::io_error, "Failed to open package file."};

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (buffer.empty())
        return {status::invalid_argument, "Package file is empty."};

    if (key && !key->empty()) {
        auto crypt_res = crypto::decrypt_payload(buffer, *key);
        if (crypt_res.code != status::ok)
            return crypt_res;
    }

    size_t cursor = 0;
    fs::path target_dir(output_dir);
    fs::create_directories(target_dir);

    LocalFileHeader lfh;
    while (util::read_struct(buffer, cursor, lfh)) {
        if (lfh.signature != SIGNATURE_LOCAL_FILE_HEADER)
            break;

        cursor += sizeof(LocalFileHeader);

        if (cursor + lfh.file_name_length + lfh.extra_field_length + lfh.compressed_size > buffer.size()) {
            return {status::invalid_argument, "Corrupted archive stream."};
        }

        std::string filename(reinterpret_cast<const char*>(buffer.data() + cursor), lfh.file_name_length);
        cursor += lfh.file_name_length + lfh.extra_field_length;

        fs::path file_out_path = target_dir / filename;
        fs::create_directories(file_out_path.parent_path());

        std::vector<uint8_t> file_data(buffer.begin() + cursor, buffer.begin() + cursor + lfh.compressed_size);
        cursor += lfh.compressed_size;

        if (crypto::calculate_crc32(file_data) != lfh.crc32) {
            return {status::corrupted_data, "CRC32 mismatch on file: " + filename};
        }

        std::ofstream out(file_out_path, std::ios::binary);
        if (!out.is_open())
            return {status::io_error, "Failed to write extracted file: " + filename};

        out.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
    }

    return {status::ok, "Unpacked successfully."};
}

} // namespace

res unpack(const std::string& pkg_path, const std::string& output_dir) { return unpack_internal(pkg_path, output_dir, nullptr); }

res unpack(const std::string& pkg_path, const std::string& output_dir, const std::vector<uint8_t>& key) {
    if (key.empty())
        return {status::invalid_argument, "Key cannot be empty."};
    return unpack_internal(pkg_path, output_dir, &key);
}

} // namespace respack