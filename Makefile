BPFTOOL ?= bpftool
CMAKE ?= cmake
MAKE ?= make

BUILD_DIR := build
ifndef CMAKE_ARGS
CMAKE_ARGS = -D CMAKE_C_COMPILER=clang -D CMAKE_CXX_COMPILER=g++ -D BPFTOOL=$(BPFTOOL)
endif

.PHONY: release
release:
	@$(MAKE) targets CMAKE_ARGS="-D CMAKE_BUILD_TYPE=Release $(CMAKE_ARGS)"

.PHONY: debug
debug:
	@$(MAKE) targets CMAKE_ARGS="-D CMAKE_BUILD_TYPE=Debug -D ENABLE_DEBUG_PRINT=1 $(CMAKE_ARGS)"

.PHONY: targets
targets: $(BUILD_DIR)/Makefile
	$(MAKE) -C $(<D)

$(BUILD_DIR)/Makefile: CMakeLists.txt | $(BUILD_DIR)
	$(CMAKE) $(CMAKE_ARGS) -S $(<D) -B $(@D)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

.PHONY: clean
clean:
	rm -r $(BUILD_DIR)
