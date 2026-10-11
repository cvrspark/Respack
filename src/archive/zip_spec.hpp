#pragma once

#include <cstdint>
#include <string>

namespace respack::archive {

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

} // namespace respack::archive