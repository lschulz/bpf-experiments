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

AES_TEST_TARGET := $(BUILD_DIR)/aes_test
AES_TEST_SRC := src/aes_test.cpp src/aes.c src/aes_hw_accel.c
AES_TEST_OBJS := $(addprefix $(BUILD_DIR)/,$(AES_TEST_SRC:%=%.o))
AES_TEST_DEPS := $(AES_TEST_OBJS:.o=.d)
# $(info $$AES_TEST_OBJS is [${AES_TEST_OBJS}])

AES_BENCH_TARGET := $(BUILD_DIR)/aes_benchmark
AES_BENCH_SRC := src/aes_benchmark.cpp src/aes.c src/aes_hw_accel.c
AES_BENCH_OBJS := $(addprefix $(BUILD_DIR)/,$(AES_BENCH_SRC:%=%.o))
AES_BENCH_DEPS := $(AES_BENCH_OBJS:.o=.d)
# $(info $$AES_BENCH_OBJS is [${AES_BENCH_OBJS}])

BPF_TARGET := $(BUILD_DIR)/xdp_combined.o
BPF_SRC := src/xdp_aes.c src/aes.c
BPF_OBJS := $(addprefix $(BUILD_DIR)/,$(BPF_SRC:src/%=bpf/%.o))
BPF_DEPS := $(BPF_OBJS:.o=.d)
# $(info $$BPF_OBJS is [${BPF_OBJS}])

LIBBPFPP_SRC := $(wildcard ../include/libbpfpp/*.cpp)
LIBBPFPP_OBJS := $(patsubst ../include/%,../build/%,$(LIBBPFPP_SRC:.cpp=.o))
LIBBPFPP_DEPS := $(LIBBPFPP_OBJS:.o=.d)
# $(info $$LIBBPFPP_OBJS is [${LIBBPFPP_OBJS}])

XDP_LOADER_TARGET := $(BUILD_DIR)/xdp_loader
XDP_LOADER_SRC := src/xdp_loader.cpp src/aes.c
XDP_LOADER_OBJS := $(addprefix $(BUILD_DIR)/,$(XDP_LOADER_SRC:%=%.o))
XDP_LOADER_DEPS := $(XDP_LOADER_OBJS:.o=.d)
# $(info $$XDP_LOADER_OBJS is [${XDP_LOADER_OBJS}])


all: $(AES_TEST_TARGET) $(AES_BENCH_TARGET) $(BPF_TARGET) $(XDP_LOADER_TARGET)


# Output directories
$(HOST_BUILD_DIR):
	mkdir -p $(HOST_BUILD_DIR)

$(BPF_BUILD_DIR):
	mkdir -p $(BPF_BUILD_DIR)

$(LIBBPFPP_BUILD_DIR):
	mkdir -p $(LIBBPFPP_BUILD_DIR)


# Unit Tests
$(AES_TEST_TARGET): $(AES_TEST_OBJS)
	$(CXX) $^ -o $@


# Benchmark
$(AES_BENCH_TARGET): $(AES_BENCH_OBJS)
	$(CXX) $^ -o $@


# BPF Program
$(BPF_TARGET): $(BPF_OBJS)
	$(BPFTOOL) gen object $@ $^

build/bpf/%.c.o: src/%.c | $(BPF_BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -MMD -MP $(BPF_INCLUDES) -c $< -o $@


# BPF Host Progam
$(XDP_LOADER_TARGET): $(XDP_LOADER_OBJS) $(LIBBPFPP_OBJS)
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
-include $(AES_TEST_DEPS)
-include $(AES_BENCH_DEPS)
-include $(BPF_DEPS)
-include $(LIBBPFPP_DEPS)
-include $(XDP_LOADER_DEPS)
