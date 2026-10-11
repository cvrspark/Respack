cmake_minimum_required(VERSION 3.30)

project(respack VERSION 2.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_COLOR_DIAGNOSTICS ON)

set(SOURCES
    src/main.cpp
    src/functions/key.cpp
    src/functions/pack.cpp
    src/functions/unpack.cpp
    src/crypto/chacha20.cpp
)

add_executable(respack ${SOURCES})

target_compile_options(respack PRIVATE
    -Wall -Wextra -fansi-escape-codes
)

target_link_options(respack PRIVATE
    -static
)