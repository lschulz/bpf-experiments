#pragma once


/// \brief Find the index of an interface by name.
/// \exception std::out_of_range Interface not found
unsigned int ifNameToIndex(const char *ifname);
