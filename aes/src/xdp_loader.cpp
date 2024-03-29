// Copyright (c) 2022-2023 Lars-Christian Schulz
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

/// \file
/// \brief Userspace program for loading the AES-XDP program.
extern "C" {
#include "aes/aes.h"
#include <net/if.h>
#include <linux/if_link.h>
}

#include "libbpfpp/libbpfpp.hpp"
#include "libbpfpp/util.hpp"

#include <cstdlib>
#include <iostream>


struct key_schedule {
    struct aes_key_schedule keys;
    struct aes_block subkeys[2];
};

static const auto STATIC_AES_KEY = aes_key {{ .w = {
    0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09
}}};

extern const uint32_t AES_T0[256];
extern const uint32_t AES_T1[256];
extern const uint32_t AES_T2[256];
extern const uint32_t AES_T3[256];

Bpf::Util::InterruptSignalHandler signalHandler;


std::optional<Bpf::Program> loadProgram(Bpf::Object &bpf, const char *name)
{
    auto prog = bpf.findProgramByName(name);
    if (!prog)
    {
        std::cerr << "Program not found" << std::endl;
        return std::nullopt;
    }

    prog->setType(BPF_PROG_TYPE_XDP);
    bpf.load();
    return prog;
}

bool populateMaps(Bpf::Object &bpf)
{
    // Update SBox
    auto sboxMap = bpf.findMapByName("AES_SBox", BPF_MAP_TYPE_ARRAY);
    if (sboxMap)
    {
        uint32_t key = 0;
        const uint8_t *value = AES_SBox;
        if (!sboxMap->update(&key, sizeof(key), value, 256, BPF_ANY))
        {
            std::cerr << "SBox update failed\n";
            return false;
        }
    }
    else
    {
        std::cerr << "SBox map not found\n";
        return false;
    }

    // Update TBox
    auto tboxMap = bpf.findMapByName("AES_TBox", BPF_MAP_TYPE_ARRAY);
    if (tboxMap)
    {
        const uint32_t *t[] = {AES_T0, AES_T1, AES_T2, AES_T3};
        for (uint32_t key = 0; key < 4; ++key)
        {
            if (!tboxMap->update(&key, sizeof(key), t[key], 1024, BPF_ANY))
            {
                std::cerr << "TBox update failed\n";
                return false;
            }
        }
    }
    else
    {
        std::cerr << "TBox map not found\n";
        return false;
    }

    // Compute keys
    key_schedule sched = {};
    aes_key_expansion(&STATIC_AES_KEY, &sched.keys);
    aes_cmac_subkeys(&sched.keys, sched.subkeys);

    // Update keys
    auto keyMap = bpf.findMapByName("aes_key_map", BPF_MAP_TYPE_ARRAY);
    if (keyMap)
    {
        uint32_t key = 0;
        if (!keyMap->update(&key, sizeof(key), &sched, sizeof(sched), BPF_ANY))
        {
            std::cerr << "Key update failed\n";
            return false;
        }
    }
    else
    {
        std::cerr << "AES key map not found\n";
        return false;
    }

    return true;
}

int run(const char *objPath, int ifindex)
{
    try {
        const int xdpFlags = XDP_FLAGS_DRV_MODE;
        auto bpf = Bpf::Object::FromFile(objPath);
        auto prog = loadProgram(bpf, "xdp_aes");
        if (!prog) return -1;
        if (!populateMaps(bpf)) return -1;

        std::cout << "Attaching program to interface " << ifindex << std::endl;
        prog->attachXDP(ifindex, xdpFlags);

        std::cout << "Trace:" << std::endl;
        Bpf::Util::tracePrint(signalHandler);

        std::cout << "Detaching program" << std::endl;
        prog->detachXDP(ifindex, xdpFlags);
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
        std::cerr << "Usage: " << argv[0] << " <bpf object> <ifindex>" << std::endl;
        return 1;
    }
    const char *objPath = argv[1];
    int ifindex = static_cast<int>(if_nametoindex(argv[2]));
    if (ifindex == 0)
    {
        std::cerr << "Interface not found" << std::endl;
        return 1;
    }

    // Load XDP program
    signalHandler.launchHandler();
    int res = run(objPath, ifindex);
    signalHandler.joinHandler();
    return res;
}
