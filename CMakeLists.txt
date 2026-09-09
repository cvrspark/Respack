cmake_minimum_required(VERSION 3.30)

option(USE_GCC "Use GCC instead of Clang" OFF)

if(USE_GCC)
    set(CMAKE_C_COMPILER "gcc")
    set(CMAKE_CXX_COMPILER "g++")
else()
    set(CMAKE_C_COMPILER "clang")
    set(CMAKE_CXX_COMPILER "clang++")
endif()

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
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -fansi-escape-codes>
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra>
)

target_link_options(respack PRIVATE
    $<$<AND:$<CONFIG:Release>,$<CXX_COMPILER_ID:GNU>>:-static-libgcc -static-libstdc++>
)