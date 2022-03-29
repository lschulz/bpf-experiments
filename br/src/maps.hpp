#pragma once

#include "libbpfpp/libbpfpp.hpp"
#include <vector>

struct BrConfig;


/// \brief Initialize the BPF maps.
/// \param[in] bpf The bpf object declaring the maps.
/// \param[in] config BR configuration
/// \param[in] interfaces Interfaces to which the border router will be attached.
void initializeMaps(
    const Bpf::Object &bpf,
    const BrConfig &config,
    const std::vector<unsigned int> &interfaces
);
