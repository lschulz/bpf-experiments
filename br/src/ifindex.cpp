#include "ifindex.hpp"

extern "C" {
#include <net/if.h>
#include <linux/if_link.h>
}

#include <stdexcept>
#include <sstream>


unsigned int ifNameToIndex(const char *ifname)
{
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        std::stringstream stream;
        stream << "Interface " << ifname << " not found.";
        throw std::out_of_range(stream.str());
    }
    return ifindex;
}
