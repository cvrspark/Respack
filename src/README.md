```text
                                                            oooo
CLI                                                         `888
oooo d8b  .ooooo.   .oooo.o oo.ooooo.   .oooo.    .ooooo.   888  oooo
`888""8P d88' `88b d88(  "8  888' `88b `P  )88b  d88' `"Y8  888 .8P'
 888     888ooo888 `"Y88b.   888   888  .oP"888  888        888888.
 888     888    .o o.  )88b  888   888 d8(  888  888   .o8  888 `88b.
d888b    `Y8bod8P' 8""888P'  888bod8P' `Y888""8o `Y8bod8P' o888o o888o
                             888
                            o888o

```

---

## Usage

```bash
respack <function> <path> [flags]

```

### Functions

| Flag   | Long Flag      | Description                                             |
| ------ | -------------- | ------------------------------------------------------- |
| `-p`   | `--pack`       | Pack a directory into a `.rvlt` archive                 |
| `-u`   | `--unpack`     | Unpack a `.rvlt` archive into a directory               |
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
respack -pgk ./assets -o ./game_data.rvlt

# Unpack an encrypted archive to a specific output folder
respack -u ./game_data.rvlt --key=YOUR_BASE64URL_KEY -o ./extracted_assets

```