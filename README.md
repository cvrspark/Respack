```markdown
                                                            oooo
                                                            `888
oooo d8b  .ooooo.   .oooo.o oo.ooooo.   .oooo.    .ooooo.   888  oooo
`888""8P d88' `88b d88(  "8  888' `88b `P  )88b  d88' `"Y8  888 .8P'
 888     888ooo888 `"Y88b.   888   888  .oP"888  888        888888.
 888     888    .o o.  )88b  888   888 d8(  888  888   .o8  888 `88b.
d888b    `Y8bod8P' 8""888P'  888bod8P' `Y888""8o `Y8bod8P' o888o o888o
                             888
                            o888o

A fast, lightweight asset packaging and encryption library written in C++ for game development and application runtime resources, alongside its command-line tool `respack`.

---

## Overview

[`librespack`](lib/README.md) allows you to archive, encrypt, and load embedded asset files directly from RAM without extracting them to disk. It pairs seamlessly with rendering and game frameworks like Raylib, custom OpenGL engines, and asset pipelines.

* **[`respack`](src/README.md) (CLI):** Command-line tool for packing, unpacking, and key generation during build steps.
* **[`librespack`](lib/README.md) (C++ Library):** Embeddable header/library for reading packed assets directly in memory at runtime.

---

## Features

| Feature | respack (CLI)| librespack (C++ Library) |
| --- | --- | --- |
| **Pack files** | ✓ | ✓ |
| **Unpack files** | ✓ | ✓ |
| **Encrypt packs** | ✓ | ✓ |
| **Decrypt packs** | ✓ | ✓ |
| **Generate keys** | ✓ | ✗ |
| **Convert keys** | ✓ | ✓ |
| **Read from RAM** | ✗ | ✓ |

```