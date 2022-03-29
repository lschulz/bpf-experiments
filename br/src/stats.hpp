#pragma once

#include "libbpfpp/map.hpp"


/// \brief Print packet and byte counters in one seconds intervals.
/// \param[in] map BPF map containing the counters.
/// \param[in] ifindex Index of the interface to monitor.
void watchStats(const Bpf::PinnedMap &map, uint32_t ifindex);
