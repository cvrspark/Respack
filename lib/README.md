```text
                                                            oooo
LIB                                                         `888
oooo d8b  .ooooo.   .oooo.o oo.ooooo.   .oooo.    .ooooo.   888  oooo
`888""8P d88' `88b d88(  "8  888' `88b `P  )88b  d88' `"Y8  888 .8P'
 888     888ooo888 `"Y88b.   888   888  .oP"888  888        888888.
 888     888    .o o.  )88b  888   888 d8(  888  888   .o8  888 `88b.
d888b    `Y8bod8P' 8""888P'  888bod8P' `Y888""8o `Y8bod8P' o888o o888o
                             888
                            o888o
```
---

## Main functions
```cpp
// key converters
spk::respack::key_from_string(const std::string& key_str); // std::vector<uint8_t>
spk::respack::key_to_string(const std::vector<uint8_t>& key); // std::string

// packing
spk::respack::pack(const std::string& dir, const std::string& output_pkg); // spk::res (code, message)
spk::respack::pack(const std::string& dir, const std::string& output_pkg, const std::vector<uint8_t>& key); // spk::res (code, message)

// unpacking
spk::respack::unpack(const std::string& pkg_path, const std::string& output_dir); // spk::res (code, message)
spk::respack::unpack(const std::string& pkg_path, const std::string& output_dir, const std::vector<uint8_t>& key); // spk::res (code, message)
// Note: output_dir specifies the directory created to hold unpacked files.

// reading from memory (without writing to disk)
spk::respack::read_pack(const std::string& pkg_path); // spk::read_res (code, message, map[filename : filecontent])
spk::respack::read_pack(const std::string& pkg_path, const std::vector<uint8_t>& key); // spk::read_res (code, message, map[filename : filecontent])
```

---

## Usage Example

### Packing

```cpp
#include <iostream>
#include <string>
#include "librespack.hxx"

int main() {
    std::string key_str = "dmPJQedEs4LtX7z55TPzMQk28vrBUrOEkXOrM_8xrrw";
    auto key = spk::respack::key_from_string(key_str);
    auto pack_res = spk::respack::pack("./assets", "assets", key); 
    // first arg is the target dir to pack, second is the package name, third is the key (optional)

    if (!pack_res) {
        util::exit(pack_res.code, pack_res.message);
    }
    std::cout << "Successfully packed resource folder.\n";
    return 0;
}

```

### Unpacking

```cpp
#include <iostream>
#include <string>
#include "librespack.hxx"

int main() {
    std::string key_str = "dmPJQedEs4LtX7z55TPzMQk28vrBUrOEkXOrM_8xrrw"; // random key
    auto key = spk::respack::key_from_string(key_str);
    auto pack_res = spk::respack::unpack("./testfolder.rvlt", "testfolder", key);
    // first arg is the target pack, second is the final directory name, third is the key (optional)
    
    if (!pack_res) {
        util::exit(pack_res.code, pack_res.message);
    }
    std::cout << "Successfully unpacked resource folder.\n";
    return 0;
}

```

### Reading from RAM

```cpp
#include <iostream>
#include <string>
#include <filesystem>
#include "librespack.hxx"

namespace fs = std::filesystem;

int main() {
    const std::string archive_path = "assets.rvlt";
    const std::string key_str = "dmPJQedEs4LtX7z55TPzMQk28vrBUrOEkXOrM_8xrrw"; // random key

    // Convert key string to respack key format
    auto key = spk::respack::key_from_string(key_str);

    // Read archive directly into memory map
    auto read_res = spk::respack::read_pack(archive_path, key);
    if (!read_res) {
        std::cerr << "Failed to read pack: " << read_res.message << "\n";
        return 1;
    }

    // Access raw file bytes from RAM
    auto file_it = read_res.files.find("textures/player.png");
    if (file_it != read_res.files.end()) {
        const std::vector<uint8_t>& buffer = file_it->second;
        std::cout << "Loaded file size: " << buffer.size() << " bytes\n";
    }

    // or
    // const auto& filebuffer = read_res.files["textures/player.png"];
    //
    // this works the same way, but the first option is way safer.

    return 0;
}
```

---

## Raylib Integration Example

```cpp
#include <iostream>
#include <string>
#include "librespack.hxx"
#include "raylib.h"

int main() {
    const std::string archive_path = "assets.rvlt";
    const std::string key_str = "dmPJQedEs4LtX7z55TPzMQk28vrBUrOEkXOrM_8xrrw"; // random key

    auto key = spk::respack::key_from_string(key_str);
    auto read_res = spk::respack::read_pack(archive_path, key);

    if (!read_res) {
        std::cerr << "Failed to read pack: " << read_res.message << "\n";
        return 1;
    }

    InitWindow(800, 600, "librespack + Raylib Example");

    Texture2D texture = { 0 };

    auto file_it = read_res.files.find("textures/player.png");
    if (file_it != read_res.files.end()) {
        const std::vector<uint8_t>& buffer = file_it->second;

        // Load image directly from memory buffer
        Image img = LoadImageFromMemory(
            ".png", 
            buffer.data(), 
            static_cast<int>(buffer.size())
        );

        // Upload pixel data to GPU memory
        texture = LoadTextureFromImage(img);

        // Unload CPU-side image data after uploading to GPU
        UnloadImage(img);
    }

    SetTargetFPS(60);

    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(RAYWHITE);

        if (texture.id > 0) {
            DrawTexture(texture, 100, 100, WHITE);
        }

        EndDrawing();
    }

    UnloadTexture(texture);
    CloseWindow();

    return 0;
}
```

---

### Tips

```cpp
// Custom exit helper using C++23 features
[[noreturn]] void exit(const spk::respack::status& code, const std::string& message) {
    std::cerr << std::format("Error [Code: {}]: {}\n", std::to_underlying(code), message);
    std::exit((int)code);
}

int main() {
    std::string key_str = "dmPJQedEs4LtX7z55TPzMQk28vrBUrOEkXOrM_8xrrw"; // random key
    auto key = spk::respack::key_from_string(key_str);
    auto pack_res = spk::respack::unpack("./testfolder.rvlt", "out", key);
    if (!pack_res) {
        ::exit(pack_res.code, pack_res.message);
    }
    return 0;
}
```

```cpp
// Logging string or text file content
#include <iostream>
#include <string>
#include <filesystem>
#include "librespack.hxx"

int main() {
    const std::string archive_path = "assets.rvlt";
    const std::string key_str = "dmPJQedEs4LtX7z55TPzMQk28vrBUrOEkXOrM_8xrrw"; // random key

    auto key = spk::respack::key_from_string(key_str);

    auto read_res = spk::respack::read_pack(archive_path, key);
    if (!read_res) {
        std::cerr << "Failed to read pack: " << read_res.message << "\n";
        return 1;
    }
    auto file_it = read_res.files.find("data/player_data.json");
    if (file_it != read_res.files.end()) {
        const std::vector<uint8_t>& buffer = file_it->second;
        std::string content(buffer.begin(), buffer.end());
        std::cout << content << "\n";
    }

    // or
    // const auto& filebuffer = read_res.files["data/player_data.json"];
    // std::string content(buffer.begin(), buffer.end());
    // std::cout << content << "\n";
    //
    // this works the same way, but the first option is way safer.

    return 0;
}
```