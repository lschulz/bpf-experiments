cmake_minimum_required(VERSION 3.16)

set(BPFTOOL bpftool CACHE STRING "bpftool executable")

project(scion-bpf)

find_package(Boost REQUIRED COMPONENTS json)
find_package(Threads REQUIRED)

if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR
        "BPF source files must be compiled by clang.\n"
        "Specify -D CMAKE_C_COMPILER=clang on the command line."
    )
endif()

add_compile_options(-Wall -Werror -march=native)

add_subdirectory(libbpfpp)
add_subdirectory(aes)
add_subdirectory(br)
