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

#ifndef SPK_RESPACK_H
#define SPK_RESPACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#include <direct.h>
#include <windows.h>
#define SPK_PATH_SEP '\\'
#define SPK_MKDIR(path) _mkdir(path)
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define SPK_PATH_SEP '/'
#define SPK_MKDIR(path) mkdir(path, 0755)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum spk_status {
    SPK_STATUS_OK = 0,
    SPK_STATUS_IO_ERROR,
    SPK_STATUS_CRYPTO_ERROR,
    SPK_STATUS_INVALID_ARGUMENT,
    SPK_STATUS_CORRUPTED_DATA
} spk_status;

typedef struct spk_res {
    spk_status code;
    char message[256];
} spk_res;

static inline spk_res spk_make_res(spk_status code, const char* msg) {
    spk_res r;
    r.code = code;
    if (msg) {
        strncpy(r.message, msg, sizeof(r.message) - 1);
        r.message[sizeof(r.message) - 1] = '\0';
    } else {
        r.message[0] = '\0';
    }
    return r;
}

typedef struct spk_buffer {
    uint8_t* data;
    size_t size;
    size_t capacity;
} spk_buffer;

static inline void spk_buf_init(spk_buffer* buf) {
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

static inline void spk_buf_free(spk_buffer* buf) {
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->size = 0;
    buf->capacity = 0;
}

static inline bool spk_buf_reserve(spk_buffer* buf, size_t needed) {
    if (buf->size + needed > buf->capacity) {
        size_t new_cap = buf->capacity == 0 ? 256 : buf->capacity * 2;
        while (new_cap < buf->size + needed) {
            new_cap *= 2;
        }
        uint8_t* new_data = (uint8_t*)realloc(buf->data, new_cap);
        if (!new_data)
            return false;
        buf->data = new_data;
        buf->capacity = new_cap;
    }
    return true;
}

static inline bool spk_buf_append(spk_buffer* buf, const void* src, size_t len) {
    if (!spk_buf_reserve(buf, len))
        return false;
    memcpy(buf->data + buf->size, src, len);
    buf->size += len;
    return true;
}

static inline bool spk_buf_prepend(spk_buffer* buf, const void* src, size_t len) {
    if (!spk_buf_reserve(buf, len))
        return false;
    memmove(buf->data + len, buf->data, buf->size);
    memcpy(buf->data, src, len);
    buf->size += len;
    return true;
}

#define SPK_SIGNATURE_LOCAL_FILE_HEADER 0x04034b50
#define SPK_SIGNATURE_CENTRAL_DIRECTORY_HEADER 0x02014b50
#define SPK_SIGNATURE_END_OF_CENTRAL_DIRECTORY 0x06054b50

#pragma pack(push, 1)
typedef struct spk_LocalFileHeader {
    uint32_t signature;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression_method;
    uint16_t last_mod_time;
    uint16_t last_mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_field_length;
} spk_LocalFileHeader;

typedef struct spk_CentralDirectoryHeader {
    uint32_t signature;
    uint16_t version_made_by;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression_method;
    uint16_t last_mod_time;
    uint16_t last_mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_field_length;
    uint16_t file_comment_length;
    uint16_t disk_number_start;
    uint16_t internal_file_attrib;
    uint32_t external_file_attrib;
    uint32_t relative_offset_local_header;
} spk_CentralDirectoryHeader;

typedef struct spk_EndOfCentralDirectoryRecord {
    uint32_t signature;
    uint16_t disk_number;
    uint16_t start_disk;
    uint16_t entries_on_disk;
    uint16_t total_entries;
    uint32_t size_of_cd;
    uint32_t offset_of_cd;
    uint16_t comment_length;
} spk_EndOfCentralDirectoryRecord;
#pragma pack(pop)

typedef struct spk_ZipEntryMeta {
    char* rel_path;
    uint32_t crc32;
    uint32_t size;
    uint32_t local_header_offset;
} spk_ZipEntryMeta;

typedef struct spk_FileEntry {
    char* name;
    uint8_t* data;
    size_t size;
} spk_FileEntry;

typedef struct spk_ReadResult {
    spk_status code;
    char message[256];
    spk_FileEntry* files;
    size_t count;
} spk_ReadResult;

#define SPK_ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define SPK_CHACHA20_QUARTERROUND(a, b, c, d)                                                                                                        \
    a += b;                                                                                                                                          \
    d ^= a;                                                                                                                                          \
    d = SPK_ROTL32(d, 16);                                                                                                                           \
    c += d;                                                                                                                                          \
    b ^= c;                                                                                                                                          \
    b = SPK_ROTL32(b, 12);                                                                                                                           \
    a += b;                                                                                                                                          \
    d ^= a;                                                                                                                                          \
    d = SPK_ROTL32(d, 8);                                                                                                                            \
    c += d;                                                                                                                                          \
    b ^= c;                                                                                                                                          \
    b = SPK_ROTL32(b, 7);

static inline uint32_t spk_load32_le(const uint8_t* src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static inline void spk_store32_le(uint8_t* dst, uint32_t val) {
    dst[0] = (uint8_t)(val);
    dst[1] = (uint8_t)(val >> 8);
    dst[2] = (uint8_t)(val >> 16);
    dst[3] = (uint8_t)(val >> 24);
}

static inline void spk_chacha20_block(uint32_t out[16], const uint32_t key[8], const uint32_t nonce[3], uint32_t counter) {
    static const char constants[] = "expand 32-byte k";
    uint32_t state[16];

    state[0] = spk_load32_le((const uint8_t*)(constants));
    state[1] = spk_load32_le((const uint8_t*)(constants + 4));
    state[2] = spk_load32_le((const uint8_t*)(constants + 8));
    state[3] = spk_load32_le((const uint8_t*)(constants + 12));

    for (int i = 0; i < 8; ++i)
        state[4 + i] = key[i];
    state[12] = counter;
    for (int i = 0; i < 3; ++i)
        state[13 + i] = nonce[i];

    memcpy(out, state, sizeof(state));

    for (int i = 0; i < 10; ++i) {
        SPK_CHACHA20_QUARTERROUND(out[0], out[4], out[8], out[12]);
        SPK_CHACHA20_QUARTERROUND(out[1], out[5], out[9], out[13]);
        SPK_CHACHA20_QUARTERROUND(out[2], out[6], out[10], out[14]);
        SPK_CHACHA20_QUARTERROUND(out[3], out[7], out[11], out[15]);

        SPK_CHACHA20_QUARTERROUND(out[0], out[5], out[10], out[15]);
        SPK_CHACHA20_QUARTERROUND(out[1], out[6], out[11], out[12]);
        SPK_CHACHA20_QUARTERROUND(out[2], out[7], out[8], out[13]);
        SPK_CHACHA20_QUARTERROUND(out[3], out[4], out[9], out[14]);
    }

    for (int i = 0; i < 16; ++i) {
        out[i] += state[i];
    }
}

static inline void spk_generate_nonce(uint8_t nonce[12]) {
    for (int i = 0; i < 12; ++i) {
        nonce[i] = (uint8_t)(rand() & 0xFF);
    }
}

static inline spk_res spk_chacha20_crypt(spk_buffer* payload, const uint8_t* key, size_t key_len, const uint8_t nonce[12], uint32_t initial_counter) {
    if (key_len != 32) {
        return spk_make_res(SPK_STATUS_INVALID_ARGUMENT, "Key length must be 32 bytes.");
    }

    uint32_t key32[8];
    for (int i = 0; i < 8; ++i)
        key32[i] = spk_load32_le(key + i * 4);

    uint32_t nonce32[3];
    for (int i = 0; i < 3; ++i)
        nonce32[i] = spk_load32_le(nonce + i * 4);

    uint32_t block[16];
    uint8_t keystream[64];
    uint64_t counter = initial_counter;

    for (size_t i = 0; i < payload->size; i += 64) {
        if (counter > 0xFFFFFFFF) {
            return spk_make_res(SPK_STATUS_CRYPTO_ERROR, "ChaCha20 counter overflow.");
        }

        spk_chacha20_block(block, key32, nonce32, (uint32_t)(counter++));

        for (int b = 0; b < 16; ++b) {
            spk_store32_le(keystream + b * 4, block[b]);
        }

        size_t bytes_to_xor = (payload->size - i < 64) ? (payload->size - i) : 64;
        for (size_t j = 0; j < bytes_to_xor; ++j) {
            payload->data[i + j] ^= keystream[j];
        }
    }

    return spk_make_res(SPK_STATUS_OK, "");
}

static inline uint32_t spk_calculate_crc32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t k = 0; k < size; ++k) {
        crc ^= data[k];
        for (int i = 0; i < 8; ++i) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

static inline spk_res spk_encrypt_payload(spk_buffer* payload, const uint8_t* key, size_t key_len) {
    if (key_len != 32) {
        return spk_make_res(SPK_STATUS_INVALID_ARGUMENT, "Key must be exactly 32 bytes (256 bits).");
    }

    uint8_t nonce[12];
    spk_generate_nonce(nonce);

    spk_res res = spk_chacha20_crypt(payload, key, key_len, nonce, 1);
    if (res.code != SPK_STATUS_OK)
        return res;

    if (!spk_buf_prepend(payload, nonce, 12)) {
        return spk_make_res(SPK_STATUS_IO_ERROR, "Failed to allocate memory for nonce header.");
    }

    return spk_make_res(SPK_STATUS_OK, "");
}

static inline spk_res spk_decrypt_payload(spk_buffer* payload, const uint8_t* key, size_t key_len) {
    if (key_len != 32) {
        return spk_make_res(SPK_STATUS_INVALID_ARGUMENT, "Key must be exactly 32 bytes (256 bits).");
    }
    if (payload->size < 12) {
        return spk_make_res(SPK_STATUS_INVALID_ARGUMENT, "Payload missing 12-byte nonce header.");
    }

    uint8_t nonce[12];
    memcpy(nonce, payload->data, 12);

    memmove(payload->data, payload->data + 12, payload->size - 12);
    payload->size -= 12;

    return spk_chacha20_crypt(payload, key, key_len, nonce, 1);
}

static inline void spk_normalize_path(char* path) {
    for (size_t i = 0; path[i] != '\0'; ++i) {
        if (path[i] == '\\')
            path[i] = '/';
    }
}

static inline void spk_mkdir_p(const char* dir) {
    char tmp[1024];
    char* p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            SPK_MKDIR(tmp);
            *p = '/';
        }
    }
    SPK_MKDIR(tmp);
}

typedef struct spk_file_list {
    char** paths;
    size_t count;
    size_t capacity;
} spk_file_list;

static inline void spk_file_list_init(spk_file_list* list) {
    list->paths = NULL;
    list->count = 0;
    list->capacity = 0;
}

static inline void spk_file_list_add(spk_file_list* list, const char* path) {
    if (list->count >= list->capacity) {
        list->capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        list->paths = (char**)realloc(list->paths, list->capacity * sizeof(char*));
    }
    list->paths[list->count] = (char*)malloc(strlen(path) + 1);
    strcpy(list->paths[list->count], path);
    list->count++;
}

static inline void spk_file_list_free(spk_file_list* list) {
    for (size_t i = 0; i < list->count; ++i) {
        free(list->paths[i]);
    }
    free(list->paths);
    list->paths = NULL;
    list->count = 0;
}

#if defined(_WIN32) || defined(_WIN64)
static inline void spk_collect_files_recursive(const char* base_dir, const char* sub_dir, spk_file_list* list) {
    char search_path[1024];
    if (sub_dir && strlen(sub_dir) > 0) {
        snprintf(search_path, sizeof(search_path), "%s\\%s\\*", base_dir, sub_dir);
    } else {
        snprintf(search_path, sizeof(search_path), "%s\\*", base_dir);
    }

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char rel_path[1024];
        if (sub_dir && strlen(sub_dir) > 0) {
            snprintf(rel_path, sizeof(rel_path), "%s\\%s", sub_dir, fd.cFileName);
        } else {
            snprintf(rel_path, sizeof(rel_path), "%s", fd.cFileName);
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            spk_collect_files_recursive(base_dir, rel_path, list);
        } else {
            spk_file_list_add(list, rel_path);
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}
#else
static inline void spk_collect_files_recursive(const char* base_dir, const char* sub_dir, spk_file_list* list) {
    char full_path[1024];
    if (sub_dir && strlen(sub_dir) > 0) {
        snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, sub_dir);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", base_dir);
    }

    DIR* dir = opendir(full_path);
    if (!dir)
        return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char rel_path[1024];
        if (sub_dir && strlen(sub_dir) > 0) {
            snprintf(rel_path, sizeof(rel_path), "%s/%s", sub_dir, entry->d_name);
        } else {
            snprintf(rel_path, sizeof(rel_path), "%s", entry->d_name);
        }

        char check_path[1024];
        snprintf(check_path, sizeof(check_path), "%s/%s", base_dir, rel_path);

        struct stat st;
        if (stat(check_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                spk_collect_files_recursive(base_dir, rel_path, list);
            } else if (S_ISREG(st.st_mode)) {
                spk_file_list_add(list, rel_path);
            }
        }
    }
    closedir(dir);
}
#endif

static inline spk_res spk_pack_internal(const char* dir, const char* output_pkg, const uint8_t* key, size_t key_len) {
    spk_file_list files;
    spk_file_list_init(&files);
    spk_collect_files_recursive(dir, "", &files);

    if (files.count == 0) {
        spk_file_list_free(&files);
        return spk_make_res(SPK_STATUS_INVALID_ARGUMENT, "Source directory does not exist or is empty.");
    }

    char out_path[1024];
    snprintf(out_path, sizeof(out_path), "%s", output_pkg);
    if (!strstr(out_path, ".")) {
        strcat(out_path, ".rvlt");
    }

    spk_buffer zip_stream;
    spk_buf_init(&zip_stream);

    spk_ZipEntryMeta* entries = (spk_ZipEntryMeta*)malloc(files.count * sizeof(spk_ZipEntryMeta));

    for (size_t i = 0; i < files.count; ++i) {
        char full_src_path[1024];
        snprintf(full_src_path, sizeof(full_src_path), "%s/%s", dir, files.paths[i]);

        FILE* in = fopen(full_src_path, "rb");
        if (!in)
            continue;

        fseek(in, 0, SEEK_END);
        long fsize = ftell(in);
        fseek(in, 0, SEEK_SET);

        uint8_t* content = (uint8_t*)malloc(fsize);
        if (fread(content, 1, fsize, in) != (size_t)fsize) {
            fclose(in);
            free(content);
            continue;
        }
        fclose(in);

        char rel_path_norm[1024];
        snprintf(rel_path_norm, sizeof(rel_path_norm), "%s", files.paths[i]);
        spk_normalize_path(rel_path_norm);

        entries[i].rel_path = (char*)malloc(strlen(rel_path_norm) + 1);
        strcpy(entries[i].rel_path, rel_path_norm);
        entries[i].crc32 = spk_calculate_crc32(content, fsize);
        entries[i].size = (uint32_t)fsize;
        entries[i].local_header_offset = (uint32_t)zip_stream.size;

        spk_LocalFileHeader lfh;
        memset(&lfh, 0, sizeof(lfh));
        lfh.signature = SPK_SIGNATURE_LOCAL_FILE_HEADER;
        lfh.version_needed = 10;
        lfh.crc32 = entries[i].crc32;
        lfh.compressed_size = entries[i].size;
        lfh.uncompressed_size = entries[i].size;
        lfh.file_name_length = (uint16_t)strlen(rel_path_norm);

        spk_buf_append(&zip_stream, &lfh, sizeof(lfh));
        spk_buf_append(&zip_stream, rel_path_norm, lfh.file_name_length);
        spk_buf_append(&zip_stream, content, fsize);

        free(content);
    }

    uint32_t cd_offset = (uint32_t)zip_stream.size;

    for (size_t i = 0; i < files.count; ++i) {
        spk_CentralDirectoryHeader cdh;
        memset(&cdh, 0, sizeof(cdh));
        cdh.signature = SPK_SIGNATURE_CENTRAL_DIRECTORY_HEADER;
        cdh.version_made_by = 20;
        cdh.version_needed = 10;
        cdh.crc32 = entries[i].crc32;
        cdh.compressed_size = entries[i].size;
        cdh.uncompressed_size = entries[i].size;
        cdh.file_name_length = (uint16_t)strlen(entries[i].rel_path);
        cdh.relative_offset_local_header = entries[i].local_header_offset;

        spk_buf_append(&zip_stream, &cdh, sizeof(cdh));
        spk_buf_append(&zip_stream, entries[i].rel_path, cdh.file_name_length);

        free(entries[i].rel_path);
    }
    free(entries);
    spk_file_list_free(&files);

    spk_EndOfCentralDirectoryRecord eocd;
    memset(&eocd, 0, sizeof(eocd));
    eocd.signature = SPK_SIGNATURE_END_OF_CENTRAL_DIRECTORY;
    eocd.entries_on_disk = (uint16_t)zip_stream.size;
    eocd.total_entries = (uint16_t)files.count;
    eocd.size_of_cd = (uint32_t)zip_stream.size - cd_offset;
    eocd.offset_of_cd = cd_offset;

    spk_buf_append(&zip_stream, &eocd, sizeof(eocd));

    if (key && key_len > 0) {
        spk_res crypt_res = spk_encrypt_payload(&zip_stream, key, key_len);
        if (crypt_res.code != SPK_STATUS_OK) {
            spk_buf_free(&zip_stream);
            return crypt_res;
        }
    }

    FILE* out = fopen(out_path, "wb");
    if (!out) {
        spk_buf_free(&zip_stream);
        return spk_make_res(SPK_STATUS_IO_ERROR, "Failed to create output file.");
    }

    fwrite(zip_stream.data, 1, zip_stream.size, out);
    fclose(out);

    spk_buf_free(&zip_stream);
    return spk_make_res(SPK_STATUS_OK, "Package created successfully.");
}

static inline spk_res spk_unpack_internal(const char* pkg_path, const char* output_dir, const uint8_t* key, size_t key_len) {
    FILE* in = fopen(pkg_path, "rb");
    if (!in) {
        return spk_make_res(SPK_STATUS_IO_ERROR, "Failed to open package file.");
    }

    fseek(in, 0, SEEK_END);
    long fsize = ftell(in);
    fseek(in, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(in);
        return spk_make_res(SPK_STATUS_INVALID_ARGUMENT, "Package file is empty.");
    }

    spk_buffer buffer;
    spk_buf_init(&buffer);
    spk_buf_reserve(&buffer, fsize);
    buffer.size = fread(buffer.data, 1, fsize, in);
    fclose(in);

    if (key && key_len > 0) {
        spk_res crypt_res = spk_decrypt_payload(&buffer, key, key_len);
        if (crypt_res.code != SPK_STATUS_OK) {
            spk_buf_free(&buffer);
            return crypt_res;
        }
    }

    size_t cursor = 0;
    spk_mkdir_p(output_dir);

    while (cursor + sizeof(spk_LocalFileHeader) <= buffer.size) {
        spk_LocalFileHeader lfh;
        memcpy(&lfh, buffer.data + cursor, sizeof(spk_LocalFileHeader));

        if (lfh.signature != SPK_SIGNATURE_LOCAL_FILE_HEADER)
            break;

        cursor += sizeof(spk_LocalFileHeader);

        if (cursor + lfh.file_name_length + lfh.extra_field_length + lfh.compressed_size > buffer.size) {
            spk_buf_free(&buffer);
            return spk_make_res(SPK_STATUS_INVALID_ARGUMENT, "Corrupted archive stream.");
        }

        char filename[1024];
        memcpy(filename, buffer.data + cursor, lfh.file_name_length);
        filename[lfh.file_name_length] = '\0';
        cursor += lfh.file_name_length + lfh.extra_field_length;

        char file_out_path[2048];
        snprintf(file_out_path, sizeof(file_out_path), "%s/%s", output_dir, filename);

        /* Create directory hierarchy */
        char* last_slash = strrchr(file_out_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            spk_mkdir_p(file_out_path);
            *last_slash = '/';
        }

        const uint8_t* file_data = buffer.data + cursor;
        cursor += lfh.compressed_size;

        if (spk_calculate_crc32(file_data, lfh.compressed_size) != lfh.crc32) {
            spk_buf_free(&buffer);
            char err[256];
            snprintf(err, sizeof(err), "CRC32 mismatch on file: %s", filename);
            return spk_make_res(SPK_STATUS_CORRUPTED_DATA, err);
        }

        FILE* out = fopen(file_out_path, "wb");
        if (!out) {
            spk_buf_free(&buffer);
            char err[256];
            snprintf(err, sizeof(err), "Failed to write extracted file: %s", filename);
            return spk_make_res(SPK_STATUS_IO_ERROR, err);
        }

        fwrite(file_data, 1, lfh.compressed_size, out);
        fclose(out);
    }

    spk_buf_free(&buffer);
    return spk_make_res(SPK_STATUS_OK, "Unpacked successfully.");
}

static inline void spk_free_read_result(spk_ReadResult* res) {
    if (!res || !res->files)
        return;
    for (size_t i = 0; i < res->count; ++i) {
        free(res->files[i].name);
        free(res->files[i].data);
    }
    free(res->files);
    res->files = NULL;
    res->count = 0;
}

static inline spk_ReadResult spk_read_pack_internal(const char* pkg_path, const uint8_t* key, size_t key_len) {
    spk_ReadResult res;
    memset(&res, 0, sizeof(res));

    FILE* in = fopen(pkg_path, "rb");
    if (!in) {
        res.code = SPK_STATUS_IO_ERROR;
        snprintf(res.message, sizeof(res.message), "Failed to open package file.");
        return res;
    }

    fseek(in, 0, SEEK_END);
    long fsize = ftell(in);
    fseek(in, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(in);
        res.code = SPK_STATUS_INVALID_ARGUMENT;
        snprintf(res.message, sizeof(res.message), "Package file is empty.");
        return res;
    }

    spk_buffer buffer;
    spk_buf_init(&buffer);
    spk_buf_reserve(&buffer, (size_t)fsize);
    buffer.size = fread(buffer.data, 1, (size_t)fsize, in);
    fclose(in);

    if (key && key_len > 0) {
        spk_res crypt_res = spk_decrypt_payload(&buffer, key, key_len);
        if (crypt_res.code != SPK_STATUS_OK) {
            spk_buf_free(&buffer);
            res.code = crypt_res.code;
            snprintf(res.message, sizeof(res.message), "%s", crypt_res.message);
            return res;
        }
    }

    size_t cursor = 0;
    size_t capacity = 16;
    res.files = (spk_FileEntry*)malloc(capacity * sizeof(spk_FileEntry));

    while (cursor + sizeof(spk_LocalFileHeader) <= buffer.size) {
        spk_LocalFileHeader lfh;
        memcpy(&lfh, buffer.data + cursor, sizeof(spk_LocalFileHeader));
        if (lfh.signature != SPK_SIGNATURE_LOCAL_FILE_HEADER)
            break;

        cursor += sizeof(spk_LocalFileHeader);
        if (cursor + lfh.file_name_length + lfh.extra_field_length + lfh.compressed_size > buffer.size) {
            spk_buf_free(&buffer);
            spk_free_read_result(&res);
            res.code = SPK_STATUS_INVALID_ARGUMENT;
            snprintf(res.message, sizeof(res.message), "Corrupted archive stream.");
            return res;
        }

        if (res.count >= capacity) {
            capacity *= 2;
            res.files = (spk_FileEntry*)realloc(res.files, capacity * sizeof(spk_FileEntry));
        }

        spk_FileEntry* entry = &res.files[res.count];
        entry->name = (char*)malloc(lfh.file_name_length + 1);
        memcpy(entry->name, buffer.data + cursor, lfh.file_name_length);
        entry->name[lfh.file_name_length] = '\0';

        cursor += lfh.file_name_length + lfh.extra_field_length;

        const uint8_t* file_data = buffer.data + cursor;
        cursor += lfh.compressed_size;

        if (spk_calculate_crc32(file_data, lfh.compressed_size) != lfh.crc32) {
            spk_buf_free(&buffer);
            spk_free_read_result(&res);
            res.code = SPK_STATUS_CORRUPTED_DATA;
            snprintf(res.message, sizeof(res.message), "CRC32 mismatch on file: %s", entry->name);
            return res;
        }

        entry->size = lfh.compressed_size;
        entry->data = (uint8_t*)malloc(entry->size);
        memcpy(entry->data, file_data, entry->size);

        res.count++;
    }

    spk_buf_free(&buffer);
    res.code = SPK_STATUS_OK;
    snprintf(res.message, sizeof(res.message), "Read successfully.");
    return res;
}

static inline spk_res spk_pack(const char* dir, const char* output_pkg) { return spk_pack_internal(dir, output_pkg, NULL, 0); }

static inline spk_res spk_pack_encrypted(const char* dir, const char* output_pkg, const uint8_t* key, size_t key_len) {
    if (!key || key_len == 0) {
        return spk_make_res(SPK_STATUS_INVALID_ARGUMENT, "Key cannot be empty.");
    }
    return spk_pack_internal(dir, output_pkg, key, key_len);
}

static inline spk_res spk_unpack(const char* pkg_path, const char* output_dir) { return spk_unpack_internal(pkg_path, output_dir, NULL, 0); }

static inline spk_res spk_unpack_encrypted(const char* pkg_path, const char* output_dir, const uint8_t* key, size_t key_len) {
    if (!key || key_len == 0) {
        return spk_make_res(SPK_STATUS_INVALID_ARGUMENT, "Key cannot be empty.");
    }
    return spk_unpack_internal(pkg_path, output_dir, key, key_len);
}

static inline spk_ReadResult spk_read_pack(const char* pkg_path) { return spk_read_pack_internal(pkg_path, NULL, 0); }

static inline spk_ReadResult spk_read_pack_encrypted(const char* pkg_path, const uint8_t* key, size_t key_len) {
    if (!key || key_len == 0) {
        spk_ReadResult res;
        memset(&res, 0, sizeof(res));
        res.code = SPK_STATUS_INVALID_ARGUMENT;
        snprintf(res.message, sizeof(res.message), "Key cannot be empty.");
        return res;
    }
    return spk_read_pack_internal(pkg_path, key, key_len);
}

#ifdef __cplusplus
}
#endif

#endif /* SPK_RESPACK_H */