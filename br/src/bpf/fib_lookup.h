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

#ifndef FIB_LOOKUP_H_GUARD
#define FIB_LOOKUP_H_GUARD

#include "common.h"
#include "constants.h"
#include "headers.h"
#include "maps.h"

#include "bpf/types.h"
#include "bpf/builtins.h"
#include "bpf/scion.h"

#include "bpf_helpers.h"
#include <linux/bpf.h>

#include <stdbool.h>


/// Indicates that the XDP program should return immediately without modifying the packet.
#define LKUP_RES_RETURN -1


/// \brief Initialize the xdp_fib_lookup structure with common data.
__attribute__((__always_inline__))
inline void init_fib_lookup(struct scratchpad *this, struct headers *hdr, struct xdp_md *ctx)
{
    memset(&this->fib_lookup, 0, sizeof(struct bpf_fib_lookup));
    this->fib_lookup.family = this->ip.family;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->fib_lookup.l4_protocol = hdr->ip.v4->protocol;
        this->fib_lookup.tot_len = ntohs(hdr->ip.v4->tot_len);
        this->fib_lookup.tos = hdr->ip.v4->tos;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        this->fib_lookup.l4_protocol = hdr->ip.v6->nexthdr;
        this->fib_lookup.tot_len = ntohs(hdr->ip.v6->payload_len) + sizeof(struct ipv6hdr);
        this->fib_lookup.flowinfo = *((u32*)hdr->ip.v6) & ~0xf0; // mask out the version field
        break;
#endif
    default:
        break;
    }
    this->fib_lookup.ifindex = ctx->ingress_ifindex;
}

// Ignore warning on call to bpf_fib_lookup in inline functions
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstatic-in-inline"

/// Forward packet to given destination host or router in the internal network.
/// \return Nonnegative egress interface index if the packet is to be rewritten and redirected.
///         LKUP_RES_RETURN if the packet is not to be redirected.
__attribute__((__always_inline__))
inline int forward_internal(
    struct scratchpad *this, struct xdp_md *ctx, struct endpoint *dest)
{
    // Copy destination port and IP to lookup structure
    this->udp.dst = this->fib_lookup.dport = dest->port;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->ip.v4.dst = this->fib_lookup.ipv4_dst = dest->ipv4;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->fib_lookup.ipv6_dst, dest->ipv6, sizeof(this->fib_lookup.ipv6_dst));
        memcpy(this->ip.v6.dst, dest->ipv6, sizeof(this->ip.v6.dst));
        break;
#endif
    default:
        break;
    }

    // FIB lookup
    int res = bpf_fib_lookup(ctx, &this->fib_lookup, sizeof(struct bpf_fib_lookup), 0);
    if (res != BPF_FIB_LKUP_RET_SUCCESS)
    {
        switch (res)
        {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            this->verdict = VERDICT_FIB_LKUP_DROP;
            return LKUP_RES_RETURN;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            this->verdict = VERDICT_FIB_LKUP_PASS;
            return LKUP_RES_RETURN;
        }
    }

    // Store MAC addresses from lookup result for eventual packet rewriting
    memcpy(this->eth.dst, this->fib_lookup.dmac, ETH_ALEN);
    memcpy(this->eth.src, this->fib_lookup.smac, ETH_ALEN);

    // Find IP address and UDP port of the internal BR interface returned by the FIB lookup
    struct endpoint *src_iface;
    u32 key = this->fib_lookup.ifindex;
    src_iface = bpf_map_lookup_elem(&int_iface_map, &key);
    if (!src_iface)
    {
        this->verdict = VERDICT_ABORT;
        return LKUP_RES_RETURN;
    }
    if (src_iface->ip_family != this->ip.family)
    {
        this->verdict = VERDICT_UNDERLAY_MISMATCH;
        return LKUP_RES_RETURN;
    }

    // Set internal interface address as new source IP and port
    this->udp.src = src_iface->port;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->ip.v4.src = src_iface->ipv4;
        this->ip.v4.ttl = DEFAULT_TTL;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->ip.v6.src, src_iface->ipv6, sizeof(this->ip.v6.src));
        this->ip.v6.hop_limit = DEFAULT_TTL;
        break;
#endif
    default:
        break;
    }

    return this->fib_lookup.ifindex;
}

/// \brief Forward packet to destination address from SCION header.
/// \return Nonnegative egress interface index if the packet is to be rewritten and redirected.
///         LKUP_RES_RETURN if the packet is not to be redirected.
__attribute__((__always_inline__))
inline int forward_to_endhost(struct scratchpad *this, struct headers *hdr, struct xdp_md *ctx)
{
    void *data_end = (void*)(long)ctx->data_end;

    this->verdict = VERDICT_UNDERLAY_MISMATCH;
    if (SC_GET_DT(hdr->scion) != SC_ADDR_TYPE_IP)
        return LKUP_RES_RETURN;

    struct endpoint dest = {};
    u32 *dst_addr = (u32*)(hdr->scion + 1);
    if (SC_GET_DL(hdr->scion) == 0)
    {
        dest.ip_family = AF_INET;
        if (dst_addr + 1 < (u32*)data_end)
            dest.ipv4 = *dst_addr;
    }
    else if (SC_GET_DL(hdr->scion) == 3)
    {
        dest.ip_family = AF_INET6;
        if (dst_addr + 4 < (u32*)data_end)
            memcpy(dest.ipv6, dst_addr, sizeof(dest.ipv6));
    }
    else
    {
        this->verdict = VERDICT_NOT_IMPLEMENTED;
        return LKUP_RES_RETURN;
    }

    dest.port = this->host_port;
    return forward_internal(this, ctx, &dest);
}

/// \brief Forward packet based on outer IP header.
/// \return Nonnegative egress interface index if the packet is to be rewritten and redirected.
///         LKUP_RES_RETURN if the packet is not to be redirected.
__attribute__((__always_inline__))
inline int forward_outer_ip(
    struct scratchpad *this, struct xdp_md* ctx)
{
    // Copy source and destination IP and port to lookup structure
    this->fib_lookup.dport = this->udp.dst;
    this->fib_lookup.sport = this->udp.src;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->fib_lookup.ipv4_dst = this->ip.v4.dst;
        this->fib_lookup.ipv4_src = this->ip.v4.src;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->fib_lookup.ipv6_dst, this->ip.v6.dst, sizeof(this->fib_lookup.ipv6_dst));
        memcpy(this->fib_lookup.ipv6_src, this->ip.v6.src, sizeof(this->fib_lookup.ipv6_src));
        break;
#endif
    default:
        break;
    }

    // FIB lookup
    int res = bpf_fib_lookup(ctx, &this->fib_lookup, sizeof(struct bpf_fib_lookup), 0);
    if (res != BPF_FIB_LKUP_RET_SUCCESS)
    {
        switch (res)
        {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            this->verdict = VERDICT_FIB_LKUP_DROP;
            return LKUP_RES_RETURN;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            this->verdict = VERDICT_FIB_LKUP_PASS;
            return LKUP_RES_RETURN;
        }
    }

    // Store new Ethernet addresses for packet rewriting
    memcpy(this->eth.dst, this->fib_lookup.dmac, ETH_ALEN);
    memcpy(this->eth.src, this->fib_lookup.smac, ETH_ALEN);
    --this->ip.v4.ttl;
    return this->fib_lookup.ifindex;
}

/// \brief Forward packet on an inter-AS SCION link.
/// \return Nonnegative egress interface index if the packet is to be rewritten and redirected.
///         LKUP_RES_RETURN if the packet is not to be redirected.
__attribute__((__always_inline__))
inline int forward_scion_link(
    struct scratchpad *this, struct xdp_md *ctx, struct ext_link *link)
{
    // Set destination and source addresses based on link configuration
    this->udp.dst = this->fib_lookup.dport = link->remote_port;
    this->udp.src = this->fib_lookup.sport = link->local_port;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->ip.v4.dst = this->fib_lookup.ipv4_dst = link->ipv4.remote;
        this->ip.v4.src = this->fib_lookup.ipv4_src = link->ipv4.local;
        this->ip.v4.ttl = DEFAULT_TTL;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->fib_lookup.ipv6_dst, link->ipv6.remote, sizeof(this->fib_lookup.ipv6_dst));
        memcpy(this->ip.v6.dst, link->ipv6.remote, sizeof(this->ip.v6.dst));
        memcpy(this->fib_lookup.ipv6_src, link->ipv6.local, sizeof(this->fib_lookup.ipv6_src));
        memcpy(this->ip.v6.src, link->ipv6.local, sizeof(this->ip.v6.src));
        this->ip.v6.hop_limit = DEFAULT_TTL;
        break;
#endif
    default:
        break;
    }

    // FIB lookup
    int res = bpf_fib_lookup(ctx, &this->fib_lookup, sizeof(struct bpf_fib_lookup), 0);
    if (res != BPF_FIB_LKUP_RET_SUCCESS)
    {
        switch (res)
        {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            this->verdict = VERDICT_FIB_LKUP_DROP;
            return LKUP_RES_RETURN;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            this->verdict = VERDICT_FIB_LKUP_PASS;
            return LKUP_RES_RETURN;
        }
    }

    // Store new Ethernet addresses for packet rewriting
    memcpy(this->eth.dst, this->fib_lookup.dmac, ETH_ALEN);
    memcpy(this->eth.src, this->fib_lookup.smac, ETH_ALEN);

    return this->fib_lookup.ifindex;
}

#pragma clang diagnostic pop

#endif // FIB_LOOKUP_H_GUARD
