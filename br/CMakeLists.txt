cmake_minimum_required(VERSION 3.16)

project(xdp-br)

# XDP Border Router Loader
add_executable(br-loader
    src/br_loader.cpp
    src/config.cpp
    src/ifindex.cpp
    src/maps.cpp
    src/stats.cpp
)
target_compile_features(br-loader PRIVATE cxx_std_20)
target_include_directories(br-loader PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(br-loader PRIVATE ${CMAKE_SOURCE_DIR}/dependencies)
target_link_libraries(br-loader PRIVATE bpfpp)
target_link_libraries(br-loader PRIVATE aes)
target_link_libraries(br-loader PRIVATE Boost::json)
target_link_libraries(br-loader PRIVATE Threads::Threads)

# XDP Border Router (BPF)
add_library(xdp_br_objs OBJECT # compile without linking
    src/bpf/xdp.c
    ${CMAKE_SOURCE_DIR}/aes/src/aes.c
)
target_compile_options(xdp_br_objs PRIVATE -target bpf -O2 -g)
target_include_directories(xdp_br_objs PRIVATE ${CMAKE_SOURCE_DIR}/libbpf/src)
target_include_directories(xdp_br_objs PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(xdp_br_objs PRIVATE ${CMAKE_SOURCE_DIR}/aes/include)

add_custom_target(xdp_br ALL DEPENDS xdp_br.o) # custom target for linking
add_dependencies(xdp_br xdp_br_objs)
add_custom_command(
    OUTPUT xdp_br.o
    COMMAND ${BPFTOOL} gen object xdp_br.o "$<TARGET_OBJECTS:xdp_br_objs>"
    COMMAND_EXPAND_LISTS
    DEPENDS src/bpf/xdp.c;${CMAKE_SOURCE_DIR}/aes/src/aes.c
)

# XDP Pass Program (BPF)
add_library(xdp_pass_objs OBJECT
    src/bpf/xdp_pass.c
)
target_compile_options(xdp_pass_objs PRIVATE -target bpf -O2 -g)

add_custom_target(xdp_pass ALL DEPENDS xdp_pass.c.o) # copy object file(s) to output directory
add_dependencies(xdp_pass xdp_pass_objs)
add_custom_command(
    OUTPUT xdp_pass.c.o
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_OBJECTS:xdp_pass_objs>" ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND_EXPAND_LISTS
    DEPENDS src/bpf/xdp_pass.c
)
