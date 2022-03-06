#pragma once

#include "libbpfpp/map.hpp"


void watchStats(const Bpf::PinnedMap &map, uint32_t ifindex);
