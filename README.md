```text
                                                            oooo
                                                            `888
oooo d8b  .ooooo.   .oooo.o oo.ooooo.   .oooo.    .ooooo.   888  oooo
`888""8P d88' `88b d88(  "8  888' `88b `P  )88b  d88' `"Y8  888 .8P'
 888     888ooo888 `"Y88b.   888   888  .oP"888  888        888888.
 888     888    .o o.  )88b  888   888 d8(  888  888   .o8  888 `88b.
d888b    `Y8bod8P' 8""888P'  888bod8P' `Y888""8o `Y8bod8P' o888o o888o
                             888
                            o888o

```

A lightweight command-line asset packaging and encryption tool written in C++26. It packs directories into single `.pkg` archives with optional Base64URL-encoded encryption.

---

## Features

- **Pack & Unpack**: Bundle directory trees into `.pkg` files and extract them back.
- **Encryption**: Optional symmetric encryption using ChaCha20.
- **Key Generation**: Generate random Base64URL keys on the fly.
- **Cross-Platform**: Zero external runtime dependencies (statically linked).

---

## Installation & Building

### Prerequisites

- C++26 compliant compiler (Clang 19+ recommended)
- CMake 3.30+
- Ninja (recommended)

### Build Steps

**Linux / macOS:**

```bash
cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build

```

**Windows (PowerShell):**

```powershell
cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build

```

The output executable (`respack` or `respack.exe`) will be generated inside your `build/` directory.

---

## Usage

```bash
respack <function> <path> [flags]

```

### Functions

| Flag   | Long Flag      | Description                                             |
| ------ | -------------- | ------------------------------------------------------- |
| `-p`   | `--pack`       | Pack a directory into a `.pkg` archive                  |
| `-u`   | `--unpack`     | Unpack a `.pkg` archive into a directory                |
| `-gk`  | `--genkey`     | Generate a new random Base64URL key                     |
| `-pgk` | `--packgenkey` | Pack a directory and encrypt with a newly generated key |
| `-h`   | `--help`       | Show usage/help message                                 |

### Options

| Flag                         | Description                                |
| ---------------------------- | ------------------------------------------ |
| `--key=<key>`                | Base64URL key for encryption or decryption |
| `-o <out>`, `--output=<out>` | Custom output destination path             |

---

## Examples

```bash
# Generate an encryption key
respack -gk

# Pack a directory without encryption
respack -p ./assets

# Pack and encrypt with an existing key
respack -p ./assets --key=YOUR_BASE64URL_KEY

# Pack, generate a new key, and output to a custom archive path
respack -pgk ./assets -o ./game_data.pkg

# Unpack an encrypted archive to a specific output folder
respack -u ./game_data.pkg --key=YOUR_BASE64URL_KEY -o ./extracted_assets

```
