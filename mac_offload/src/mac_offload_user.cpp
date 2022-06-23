// Copyright (c) 2022 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

extern "C" {
#include "bpf/common.h"
#include "aes/aes.h"
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf.h>
}

#include "libbpfpp/libbpfpp.hpp"
#include "libbpfpp/map.hpp"
#include "libbpfpp/util.hpp"

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>


struct Config
{
    std::string objFile;
    struct aes_key key;
    std::vector<uint32_t> cpus;
    std::vector<unsigned int> ifaces;
};

static void printUsage()
{
    std::cerr <<
        "Usage: mac_offload <xdp> <key> <mask> [iface...]\n"
        "\n"
        "Required parameters:\n"
        "    <xdp>    Object file containing the XDP programs\n"
        "    <key>    Hop field MAC verification key encoded in base64\n"
        "    <mask>   Which CPUs to use for MAC computation as hexadecimal CPU mask\n"
        "    <iface>  Name(s) of the network interface(s) to attach to\n";
}

static bool decodeKey(const std::string &base64, struct aes_key &key)
{
    using namespace boost::archive::iterators;
    using Iter = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

    if (base64.size() != 24)
    {
        std::cerr << "Key has invalid length\n";
        return false;
    }

    auto i = Iter(std::begin(base64)), end = Iter(std::end(base64) - 2);
    for (size_t j = 0; i != end && j < sizeof(key); ++i, ++j) key.b[j] = *i;

    return true;
}

static void cpuMaskToList(uint64_t mask, std::vector<uint32_t> &cpus)
{
    for (unsigned int i = 0; i < 64; ++i)
    {
        if (mask & (1ull << i))
            cpus.push_back(i);
    }
}

static bool parseInterfaces(int argc, char* argv[], std::vector<unsigned int> &ifaces)
{
    ifaces.reserve(argc);
    for (int i = 0; i < argc; ++i)
    {
        unsigned int ifindex = if_nametoindex(argv[i]);
        if (ifindex == 0)
        {
            std::cerr << "Interface " << argv[i] << " not found.\n";
            return false;
        }
        ifaces.push_back(ifindex);
    }
    return true;
}

static bool parseArguments(int argc, char* argv[], Config &conf)
{
    if (argc < 4)
    {
        printUsage();
        return false;
    }

    conf.objFile = argv[1];

    if (!decodeKey(std::string(argv[2]), conf.key))
        return false;

    char *endp = argv[3] + std::strlen(argv[3]);
    uint64_t cpuMask = std::strtoll(argv[3], &endp, 16);
    cpuMaskToList(cpuMask, conf.cpus);

    if (!parseInterfaces(argc - 4, argv + 4, conf.ifaces))
        return false;

    return true;
}

std::optional<Bpf::Object> loadAndAttach(const Config &conf)
{
    // Load programs and maps
    auto bpf = Bpf::Object::FromFile(conf.objFile);

    auto xdpBalancer = bpf.findProgramByName("xdp_round_robin");
    if (!xdpBalancer) throw std::runtime_error("XDP program not found");

    auto xdpValidator = bpf.findProgramByName("xdp_validate_hf");
    if (!xdpValidator) throw std::runtime_error("XDP program not found");
    xdpValidator->setExpectedAttachType(BPF_XDP_CPUMAP);

    auto xdpEgress = bpf.findProgramByName("xdp_pass");
    if (!xdpEgress) throw std::runtime_error("XDP program not found");
    xdpEgress->setExpectedAttachType(BPF_XDP_DEVMAP);

    bpf.load();

    // Initialize maps
    auto sbox = bpf.findMapByName("AES_SBox", BPF_MAP_TYPE_ARRAY);
    if (!sbox) throw std::runtime_error("AES_SBox not found");
    else
    {
        uint32_t key = 0;
        const uint8_t *value = AES_SBox;
        sbox->update(&key, sizeof(key), value, 256, BPF_ANY);
    }

    auto cpuMap = bpf.findMapByName("cpu_map", BPF_MAP_TYPE_ARRAY);
    if (!cpuMap) throw std::runtime_error("cpu_map not found");
    else
    {
        uint32_t key = 0;
        for (uint32_t cpu : conf.cpus)
        {
            cpuMap->update(&key, sizeof(key), &cpu, sizeof(cpu), 0);
            key++;
        }
    }

    auto cpuCount = bpf.findMapByName("cpu_count", BPF_MAP_TYPE_ARRAY);
    if (!cpuCount) throw std::runtime_error("cpu_count not found");
    else
    {
        uint32_t key = 0;
        uint32_t value = static_cast<uint32_t>(conf.cpus.size());
        cpuCount->update(&key, sizeof(key), &value, sizeof(value), 0);
    }

    auto cpuIterator = bpf.findMapByName("cpu_iterator", BPF_MAP_TYPE_PERCPU_ARRAY);
    if (!cpuIterator) throw std::runtime_error("cpu_iterator not found");
    else
    {
        uint32_t key = 0;
        // Apparently value size has to be at least 8 bytes even when the map defines 4
        std::vector<uint64_t> iterators(sysconf(_SC_NPROCESSORS_ONLN));
        cpuIterator->update(&key, sizeof(key), iterators.data(),
            iterators.size() * sizeof(uint64_t), 0);
    }

    auto cpuRedirectMap = bpf.findMapByName("cpu_redirect_map", BPF_MAP_TYPE_CPUMAP);
    if (!cpuRedirectMap) throw std::runtime_error("cpu_redirect_map not found");
    else
    {
        for (uint32_t cpu : conf.cpus)
        {
            struct bpf_cpumap_val value = {
                .qsize = 192,
                .bpf_prog{ .fd = xdpValidator->getFd() }
            };
            cpuRedirectMap->update(&cpu, sizeof(cpu), &value, sizeof(value), BPF_EXIST);
        }
    }

    auto txPort = bpf.findMapByName("tx_port", BPF_MAP_TYPE_DEVMAP);
    if (!txPort) throw std::runtime_error("tx_port not found");
    else
    {
        for (unsigned int iface : conf.ifaces)
        {
            struct bpf_devmap_val value = {
                .ifindex = iface,
                .bpf_prog{ .fd = xdpEgress->getFd() }
            };
            txPort->update(&iface, sizeof(iface), &value, sizeof(value), 0);
        }
    }

    auto hfKey = bpf.findMapByName("hf_key", BPF_MAP_TYPE_ARRAY);
    if (!hfKey) throw std::runtime_error("hf_key not found");
    else
    {
        // Key expansion and subkey derivation
        struct hf_key value = {};
        aes_key_expansion(&conf.key, &value.key);
        struct aes_block subkeys[2];
        aes_cmac_subkeys(&value.key, subkeys);
        value.subkey = subkeys[0];

        uint32_t index = 0;
        hfKey->update(&index, sizeof(index), &value, sizeof(value), 0);
    }

    // Attach XDP
    for (int ifindex : conf.ifaces)
        xdpBalancer->attachXDP(ifindex, XDP_FLAGS_DRV_MODE);

    return bpf;
};

int main(int argc, char* argv[])
{
    Config conf;
    if (!parseArguments(argc, argv, conf))
        return EXIT_FAILURE;

    try {
        auto bpf = loadAndAttach(conf);
        if (!bpf) return EXIT_FAILURE;
        std::cout << "XDP Attached" << std::endl;
    }
    catch (std::exception &e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
