# librespack

Bundles folders into `.rvlt` archives with optional ChaCha20 encryption and CRC32 checks.

## Files

- `librespack_c.h` – C99 header.
- `librespack.hxx` – C++17 header.

---

## Usage

### C (`librespack_c.h`)

```c
#include "librespack_c.h"
#include <stdio.h>

int main(void) {
    uint8_t key[32] = "01234567890123456789012345678901";

    // Pack
    spk_res p_res = spk_pack_encrypted("./assets", "assets.rvlt", key, 32);
    if (p_res.code != SPK_STATUS_OK) return 1;

    // Read to memory
    spk_ReadResult r_res = spk_read_pack_encrypted("assets.rvlt", key, 32);
    if (r_res.code != SPK_STATUS_OK) return 1;

    for (size_t i = 0; i < r_res.count; ++i) {
        printf("%s (%zu bytes)\n", r_res.files[i].name, r_res.files[i].size);
    }

    spk_free_read_result(&r_res);
    return 0;
}

```

### C++ (`librespack.hxx`)

```cpp
#include "librespack.hxx"
#include <iostream>
#include <vector>

int main() {
    std::vector<uint8_t> key(32, '0');

    // Pack
    auto pack_res = spk::respack::pack("./assets", "assets.rvlt", key);
    if (!pack_res) return 1;

    // Read to memory
    auto read_res = spk::respack::read_pack("assets.rvlt", key);
    if (!read_res) return 1;

    for (const auto& file : read_res.files) {
        std::cout << file.name << " (" << file.data.size() << " bytes)\n";
    }

    return 0;
}

```

---

## License

MIT
