#pragma once
#include <string>

namespace respack {

enum class status { ok = 0, io_error, crypto_error, invalid_argument, corrupted_data };

struct res {
    status code;
    std::string message;
    explicit operator bool() const { return code == status::ok; }
};
} // namespace respack
