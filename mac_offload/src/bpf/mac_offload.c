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

#include "common.h"
#include "aes/aes.h"
#include "bpf/types.h"
#include "bpf_helpers.h"

#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/types.h>

char _license[] SEC("license") = "Dual MIT/GPL";


//////////////////////////
// Packet Bridge Header //
//////////////////////////

#define ETH_P_BRIDGE 0x9999

#define BR_CHECK_HF1 (1 << 0)
#define BR_CHECK_HF2 (1 << 1)
#define BR_HF1_OK (1 << 4)
#define BR_HF2_OK (1 << 5)

struct bridge_hdr
{
    u8 flags;
    u8 reserved;
    u16 switch_data;
    u32 ingress_port;
    u64 first_mac;
    u8 first_hf[16];
    u64 second_mac;
    u8 second_hf[16];
};

//////////
// Maps //
//////////

// List of CPUs that are available for redirection
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} cpu_map SEC(".maps");

// Contains the number of available CPUs in cpu_map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1);
} cpu_count SEC(".maps");

// A counter for each CPU that is used for round-robin distribution of packets
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1);
} cpu_iterator SEC(".maps");

// Map for redirecting frames to another CPU
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct bpf_cpumap_val));
    __uint(max_entries, 64);
} cpu_redirect_map SEC(".maps");

// Map for redirecting frames to an interface
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(unsigned int));
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 128);
} tx_port SEC(".maps");

// Hop field authentication key
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct hf_key));
    __uint(max_entries, 1);
} hf_key SEC(".maps");

////////////////////
// Device Program //
////////////////////

SEC("xdp")
int xdp_round_robin(struct xdp_md *ctx)
{
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    // Parse Ethernet
    struct ethhdr *eth = data;
    data += sizeof(struct ethhdr);
    if (data >= data_end || eth->h_proto != ETH_P_BRIDGE)
        return XDP_PASS; // packet does not contain bridge header

    // Parse bridge header
    struct bridge_hdr *hdr = data;
    if ((void*)(hdr + 1) > data_end)
        return XDP_DROP; // invalid bridge header

    // Store ingress port so we can retransmit on the same port
    hdr->ingress_port = ctx->ingress_ifindex;

    // Redirect to next CPU
    u32 key = 0;
    u32 *count = bpf_map_lookup_elem(&cpu_count, &key);
    if (!count) return XDP_ABORTED;

    u32 *index = bpf_map_lookup_elem(&cpu_iterator, &key);
    if (!index) return XDP_ABORTED;

    u32 *cpu = bpf_map_lookup_elem(&cpu_map, index);
    if (!cpu) return XDP_ABORTED;

    (*index)++;
    if (*index >= *count) *index = 0;

    return bpf_redirect_map(&cpu_redirect_map, *cpu, 0);
}

////////////////////
// CPUMAP Program //
////////////////////

__attribute__((__always_inline__))
inline int verify_hop_field(u8 input[16], struct hf_key *key, u64 expected)
{
    struct aes_cmac mac;
    aes_cmac_16bytes((struct aes_block*)input, &key->key, &key->subkey, &mac);

    u64 actual = *(u64*)mac.w & 0x0000ffffffffffff;
    return actual == expected;
}

SEC("xdp")
int xdp_validate_hf(struct xdp_md *ctx)
{
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct bridge_hdr *hdr = data + sizeof(struct ethhdr);
    if ((void*)(hdr + 1) > data_end)
        return XDP_DROP;

    // Verify hop fields
    if (hdr->flags & (BR_CHECK_HF1 | BR_CHECK_HF2))
    {
        u32 index = 0;
        struct hf_key *key = bpf_map_lookup_elem(&hf_key, &index);
        if (key)
        {
            if (hdr->flags & BR_CHECK_HF1)
            {
                if (verify_hop_field(hdr->first_hf, key, hdr->first_mac))
                    hdr->flags |= BR_HF1_OK;
            }
            if (hdr->flags & BR_CHECK_HF2)
            {
                if (verify_hop_field(hdr->second_hf, key, hdr->second_mac))
                    hdr->flags |= 0x20;
            }
        }
    }

    u32 egress_port = hdr->ingress_port;
    return bpf_redirect_map(&tx_port, egress_port, 0);
}

////////////////////
// DEVMAP Program //
////////////////////

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}
