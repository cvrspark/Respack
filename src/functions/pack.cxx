#include "../archive/bin_util.hxx"
#include "../archive/zip_spec.hxx"
#include "../crypto/chacha20.hxx"
#include "../main.hxx"
#include <filesystem>
#include <fstream>
#include <limits>

namespace fs = std::filesystem;
using namespace respack::archive;

namespace respack {

namespace {

res pack_internal(const std::string& dir, const std::string& output_pkg, const std::vector<uint8_t>* key) {
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

} // namespace

res pack(const std::string& dir, const std::string& output_pkg) { 
    return pack_internal(dir, output_pkg, nullptr); 
}

res pack(const std::string& dir, const std::string& output_pkg, const std::vector<uint8_t>& key) {
    if (key.empty())
        return {status::invalid_argument, "Key cannot be empty."};
    return pack_internal(dir, output_pkg, &key);
}

} // namespace respack