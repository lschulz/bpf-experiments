cmake_minimum_required(VERSION 3.16)

project(xdp_pass)

# XDP Pass Program (BPF)
add_library(xdp_pass_objs OBJECT
    xdp_pass.c
)
target_compile_options(xdp_pass_objs PRIVATE -target bpf -O2 -g)

add_custom_target(xdp_pass ALL DEPENDS xdp_pass.c.o) # copy object file(s) to output directory
add_dependencies(xdp_pass xdp_pass_objs)
add_custom_command(
    OUTPUT xdp_pass.c.o
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_OBJECTS:xdp_pass_objs>"
    ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND_EXPAND_LISTS
    DEPENDS "$<TARGET_OBJECTS:xdp_pass_objs>"
)
