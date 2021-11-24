CLANG := clang
CXX := clang++
BPFTOOL := bpftool
LIBBPF := ../libbpf/src/


# Common flags
CFLAGS = -Wall -march=native -O2 -g
CXXFLAGS = -Wall -std=c++20 -march=native -O2 -g
BPF_CFLAGS = -Wall -Winline -target bpf -O2 -g
BPF_INCLUDES = -I $(LIBBPF) -I ../include/ -I /usr/include/x86_64-linux-gnu/


# Input/Output files
BUILD_DIR := ./build
HOST_BUILD_DIR := $(BUILD_DIR)/src
BPF_BUILD_DIR := $(BUILD_DIR)/bpf
LIBBPFPP_BUILD_DIR := ../build/libbpfpp

BPF_TARGET := $(BUILD_DIR)/xdp.o
BPF_SRC := src/xdp.c
BPF_OBJS := $(addprefix $(BUILD_DIR)/,$(BPF_SRC:src/%=bpf/%.o))
BPF_DEPS := $(BPF_OBJS:.o=.d)

LIBBPFPP_SRC := $(wildcard ../include/libbpfpp/*.cpp)
LIBBPFPP_OBJS := $(patsubst ../include/%,../build/%,$(LIBBPFPP_SRC:.cpp=.o))
LIBBPFPP_DEPS := $(LIBBPFPP_OBJS:.o=.d)

HOST_TARGET := $(BUILD_DIR)/int
HOST_SRC := src/main.cpp
HOST_OBJS := $(addprefix $(BUILD_DIR)/,$(HOST_SRC:%=%.o))
HOST_DEPS := $(HOST_OBJS:.o=.d)


all: $(BPF_TARGET) $(HOST_TARGET)


# Output directories
$(HOST_BUILD_DIR):
	mkdir -p $(HOST_BUILD_DIR)

$(BPF_BUILD_DIR):
	mkdir -p $(BPF_BUILD_DIR)

$(LIBBPFPP_BUILD_DIR):
	mkdir -p $(LIBBPFPP_BUILD_DIR)


# BPF Program
$(BPF_TARGET): $(BPF_OBJS)

build/bpf/%.c.o: src/%.c | $(BPF_BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -MMD -MP $(BPF_INCLUDES) -c $< -o $@


# BPF Host Progam
$(HOST_TARGET): $(HOST_OBJS) $(LIBBPFPP_OBJS)
	$(CXX) $^ -o $@ -L $(LIBBPF) -lbpf -lelf -lpthread


# libbpfpp
$(LIBBPFPP_BUILD_DIR)/%.o: ../include/libbpfpp/%.cpp | $(LIBBPFPP_BUILD_DIR)
	$(CXX) $(CXXFLAGS) -MMD -MP -I $(LIBBPF) -I ../include/ -c $< -o $@


# C/C++ Source Files
$(BUILD_DIR)/src/%.c.o: src/%.c | $(HOST_BUILD_DIR)
	$(CLANG) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/src/%.cpp.o: src/%.cpp | $(HOST_BUILD_DIR)
	$(CXX) $(CXXFLAGS) -MMD -MP -I $(LIBBPF) -I ../include/ -c $< -o $@


# Utilities
clean:
	rm -rf ./build
	rm -rf ../build


# Auto-generated dependencies
-include $(BPF_DEPS)
-include $(LIBBPFPP_DEPS)
-include $(HOST_DEPS)
