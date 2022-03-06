#pragma once

#include "libbpfpp/libbpfpp.hpp"
#include <vector>

struct BrConfig;


void initializeMaps(
    const Bpf::Object &bpf,
    const BrConfig &config,
    const std::vector<unsigned int> &interfaces
);
