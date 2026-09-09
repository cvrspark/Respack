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

res pack_internal(const std::string& dir, const std::string& output_pkg, const std::vector<uint8_t>* key) {
    fs::path src_dir(dir);
    if (!fs::exists(src_dir) || !fs::is_directory(src_dir)) {
        return {status::invalid_argument, "Source directory does not exist."};
    }

    std::vector<uint8_t> zip_stream;
    std::vector<ZipEntryMeta> entries;

    for (const auto& entry : fs::recursive_directory_iterator(src_dir)) {
        if (fs::is_regular_file(entry.status())) {
            std::string rel_path = fs::relative(entry.path(), src_dir).generic_string();

            std::ifstream in(entry.path(), std::ios::binary);
            if (!in)
                continue;

            std::vector<uint8_t> content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

            ZipEntryMeta meta{
                rel_path, crypto::calculate_crc32(content), static_cast<uint32_t>(content.size()), static_cast<uint32_t>(zip_stream.size())
            };

            LocalFileHeader lfh;
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

    uint32_t cd_offset = static_cast<uint32_t>(zip_stream.size());

    for (const auto& meta : entries) {
        CentralDirectoryHeader cdh;
        cdh.crc32 = meta.crc32;
        cdh.compressed_size = meta.size;
        cdh.uncompressed_size = meta.size;
        cdh.file_name_length = static_cast<uint16_t>(meta.rel_path.size());
        cdh.relative_offset_local_header = meta.local_header_offset;

        util::append_struct(zip_stream, cdh);
        zip_stream.insert(zip_stream.end(), meta.rel_path.begin(), meta.rel_path.end());
    }

    EndOfCentralDirectoryRecord eocd;
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

    std::ofstream out(output_pkg, std::ios::binary);
    if (!out.is_open())
        return {status::io_error, "Failed to create output file."};

    out.write(reinterpret_cast<const char*>(zip_stream.data()), zip_stream.size());
    return {status::ok, "Package created successfully."};
}

} // namespace

res pack(const std::string& dir, const std::string& output_pkg) { return pack_internal(dir, output_pkg, nullptr); }

res pack(const std::string& dir, const std::string& output_pkg, const std::vector<uint8_t>& key) {
    if (key.empty())
        return {status::invalid_argument, "Key cannot be empty."};
    return pack_internal(dir, output_pkg, &key);
}

} // namespace respack