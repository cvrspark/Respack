cmake_minimum_required(VERSION 3.30)

set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

project(respack VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_COLOR_DIAGNOSTICS ON)

set(SOURCES
    src/main.cxx
    src/functions/key.cxx
    src/functions/pack.cxx
    src/functions/unpack.cxx
    src/crypto/chacha20.cxx
)

add_executable(respack ${SOURCES})

target_compile_options(respack PRIVATE
    -Wall -Wextra -fansi-escape-codes -stdlib=libc++
)

target_link_options(respack PRIVATE 
    -stdlib=libc++
    -static-libgcc
    -lc++abi
)