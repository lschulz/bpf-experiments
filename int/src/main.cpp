extern "C" {
#include <net/if.h>
#include <linux/if_link.h>
}

#include "libbpfpp/libbpfpp.hpp"
#include "libbpfpp/buffer.hpp"
#include "libbpfpp/util.hpp"

#include <cstdint>
#include <iostream>
#include <vector>

using std::size_t;


Bpf::Util::InterruptSignalHandler signalHandler;


int telemetryCallback(void *ctx, void *data, size_t size)
{
    std::cout << std::dec << size << " bytes of telemetry received:\n";
    for (size_t i = 0; i < size; ++i)
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << +static_cast<unsigned char*>(data)[i];
    std::cout << std::endl;
    return 0; // Returning non-zero terminates the consumer loop
}

int run(const char *objPath, const std::vector<int> &interfaces)
{
    const int xdpFlags = XDP_FLAGS_DRV_MODE;

    try {
        // Load programs
        auto bpf = Bpf::Object::FromFile(objPath);
        auto xdp = bpf.findProgramByName("xdp_aes");
        if (!xdp)
        {
            std::cerr << "XDP program not found\n" << std::endl;
            return -1;
        }
        xdp->setType(BPF_PROG_TYPE_XDP);
        bpf.load();

        // Maps
        auto ringMap = bpf.findMapByName("telemetry_buffer", BPF_MAP_TYPE_RINGBUF);
        if (!ringMap)
        {
            std::cerr << "Map not found\n" << std::endl;
            return -1;
        }

        // Attach XDP
        for (int ifindex : interfaces)
            xdp->attachXDP(ifindex, xdpFlags);

        // Poll the ringbuffer
        Bpf::RingBuffer ring(*ringMap, &telemetryCallback);
        while (!signalHandler) ring.poll(100);

        // Cleanup
        for (int ifindex : interfaces)
            xdp->detachXDP(ifindex, xdpFlags);
    }
    catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        return -1;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    // Parse command line
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <bpf object> <ifindex> [ifindex...]" << std::endl;
        return 1;
    }
    const char *objPath = argv[1];

    std::vector<int> interfaces;
    interfaces.reserve(argc - 2);
    for (int i = 2; i < argc; ++i)
    {
        int ifindex = static_cast<int>(if_nametoindex(argv[i]));
        if (ifindex == 0)
        {
            std::cerr << "Interface " << argv[i] << " not found" << std::endl;
            return 1;
        }
        interfaces.push_back(ifindex);
    }

    // Load and attach program
    signalHandler.launchHandler();
    int res = run(objPath, interfaces);
    signalHandler.joinHandler();
    return res;
}
