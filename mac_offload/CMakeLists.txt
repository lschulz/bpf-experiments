cmake_minimum_required(VERSION 3.16)

project(mac-offload)

# Userspace Prorgam
add_executable(mac-offload
    src/mac_offload_user.cpp
)
target_compile_features(mac-offload PRIVATE cxx_std_20)
target_include_directories(mac-offload PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(mac-offload PRIVATE ${CMAKE_SOURCE_DIR}/dependencies)
target_link_libraries(mac-offload PRIVATE bpfpp)
target_link_libraries(mac-offload PRIVATE aes)
target_link_libraries(mac-offload PRIVATE Threads::Threads)

# XDP Programs
add_library(xdp_mac_objs OBJECT
    src/bpf/mac_offload.c
    ${CMAKE_SOURCE_DIR}/aes/src/aes.c
)
target_compile_options(xdp_mac_objs PRIVATE -target bpf -O2 -g)
target_include_directories(xdp_mac_objs PRIVATE ${CMAKE_SOURCE_DIR}/libbpf/src)
target_include_directories(xdp_mac_objs PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(xdp_mac_objs PRIVATE ${CMAKE_SOURCE_DIR}/aes/include)

add_custom_target(xdp_mac ALL DEPENDS xdp_mac.o) # custom target for linking
add_dependencies(xdp_mac xdp_mac_objs)
add_custom_command(
    OUTPUT xdp_mac.o
    COMMAND ${BPFTOOL} gen object xdp_mac.o "$<TARGET_OBJECTS:xdp_mac_objs>"
    COMMAND_EXPAND_LISTS
    DEPENDS "$<TARGET_OBJECTS:xdp_mac_objs>"
)
