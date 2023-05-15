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

#ifndef REWRITE_H_GUARD
#define REWRITE_H_GUARD

#include "common.h"
#include "constants.h"
#include "headers.h"
#include "debug.h"

#include "bpf/types.h"
#include "bpf/builtins.h"
#include "bpf/scion.h"

inline void rewrite(struct scratchpad *this, struct headers *hdr, void *data_end);
inline void rewrite_scion_path(struct scratchpad *this, struct headers *hdr, void *data_end);

#define FOLD_CHECKSUM(csum) do { \
    csum = (csum & 0xffff) + (csum >> 16); \
    csum = (csum & 0xffff) + (csum >> 16); \
    csum = ~csum; \
    if (csum == 0) csum = 0xffff; \
} while (0)


/// \brief Write pending changes into the packet and update the checksums.
__attribute__((__always_inline__))
inline void rewrite(struct scratchpad *this, struct headers *hdr, void *data_end)
{
    // Ethernet
    printf("    ## Rewrite Ethernet ##\n");
    printf("      dst %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
        hdr->eth->h_dest[0], hdr->eth->h_dest[1], hdr->eth->h_dest[2],
        hdr->eth->h_dest[3], hdr->eth->h_dest[4], hdr->eth->h_dest[5],
        this->eth.dst[0], this->eth.dst[1], this->eth.dst[2],
        this->eth.dst[3], this->eth.dst[4], this->eth.dst[5]);
    printf("      src %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
        hdr->eth->h_source[0], hdr->eth->h_source[1], hdr->eth->h_source[2],
        hdr->eth->h_source[3], hdr->eth->h_source[4], hdr->eth->h_source[5],
        this->eth.src[0], this->eth.src[1], this->eth.src[2],
        this->eth.src[3], this->eth.src[4], this->eth.src[5]);
    memcpy(hdr->eth->h_dest, this->eth.dst, ETH_ALEN);
    memcpy(hdr->eth->h_source, this->eth.src, ETH_ALEN);

    // IP
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
    {
        printf("    ## Rewrite IPv4 ##\n");
        printf("      dst 0x%08x -> 0x%08x\n", ntohl(hdr->ip.v4->daddr), ntohl(this->ip.v4.dst));
        printf("      src 0x%08x -> 0x%08x\n", ntohl(hdr->ip.v4->saddr), ntohl(this->ip.v4.src));
        printf("      ttl %d -> %d\n", hdr->ip.v4->ttl, this->ip.v4.ttl);
        u64 csum = (hdr->ip.v4->daddr = this->ip.v4.dst);
        csum += (hdr->ip.v4->saddr = this->ip.v4.src);
        this->ip_residual += csum;
        this->udp_residual += csum;
        this->ip_residual += (hdr->ip.v4->ttl = this->ip.v4.ttl);

        // Update checksum
        csum = ~hdr->ip.v4->check + this->ip_residual + 1;
        FOLD_CHECKSUM(csum);
        hdr->ip.v4->check = csum;

        break;
    }
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
    {
        printf("    ## Rewrite IPv6 ##\n");
        struct in6_addr *daddr = &hdr->ip.v6->daddr;
        struct in6_addr *saddr = &hdr->ip.v6->saddr;
        if ((void*)daddr + sizeof(struct in6_addr) < data_end
            && (void*)saddr + sizeof(struct in6_addr) < data_end)
        {
            printf("      dst %08x:%08x:%08x:%08x -> %08x:%08x:%08x:%08x\n",
                ntohl(daddr->in6_u.u6_addr32[0]), ntohl(daddr->in6_u.u6_addr32[1]),
                ntohl(daddr->in6_u.u6_addr32[2]), ntohl(daddr->in6_u.u6_addr32[3]),
                ntohl(this->ip.v6.dst[0]), ntohl(this->ip.v6.dst[1]),
                ntohl(this->ip.v6.dst[2]), ntohl(this->ip.v6.dst[3]));
            printf("      src %08x:%08x:%08x:%08x -> %08x:%08x:%08x:%08x\n",
                ntohl(saddr->in6_u.u6_addr32[0]), ntohl(saddr->in6_u.u6_addr32[1]),
                ntohl(saddr->in6_u.u6_addr32[2]), ntohl(saddr->in6_u.u6_addr32[3]),
                ntohl(this->ip.v6.src[0]), ntohl(this->ip.v6.src[1]),
                ntohl(this->ip.v6.src[2]), ntohl(this->ip.v6.src[3]));
            #pragma unroll
            for (uint64_t i = 0; i < 4; ++i)
            {
                daddr->in6_u.u6_addr32[i] = this->ip.v6.dst[i];
                this->udp_residual += this->ip.v6.dst[i];
                saddr->in6_u.u6_addr32[i] = this->ip.v6.src[i];
                this->udp_residual += this->ip.v6.src[i];
            }
        }
        printf("      hop limit %d -> %d\n", hdr->ip.v6->hop_limit, this->ip.v6.hop_limit);
        hdr->ip.v6->hop_limit = this->ip.v6.hop_limit;
        break;
    }
#endif
    default:
        break;
    }

    // UDP
    printf("    ## Rewrite UDP ##\n");
    printf("      dst %d -> %d\n", ntohs(hdr->udp->dest), ntohs(this->udp.dst));
    printf("      src %d -> %d\n", ntohs(hdr->udp->source), ntohs(this->udp.src));
    hdr->udp->dest = this->udp.dst;
    hdr->udp->source = this->udp.src;
    this->udp_residual += this->udp.dst;
    this->udp_residual += this->udp.src;

    // SCION
    switch (this->path_type)
    {
#ifdef ENABLE_SCION_PATH
    case SC_PATH_TYPE_SCION:
        rewrite_scion_path(this, hdr, data_end);
        break;
#endif
    default:
        break;
    }

    // Update UDP checksum
    u64 csum = ~hdr->udp->check + this->udp_residual + 1;
    FOLD_CHECKSUM(csum);
    printf("  ## Chksum 0x%04x -> 0x%04x ##\n", hdr->udp->check, csum & 0xffff);
    hdr->udp->check = csum;
}

#ifdef ENABLE_SCION_PATH
/// \brief Update the SCION path headers.
__attribute__((__always_inline__))
inline void rewrite_scion_path(struct scratchpad *this, struct headers *hdr, void *data_end)
{
    printf("    ## Rewrite SCION ##\n");

    // Meta header
    u32 meta = (this->path.scion.h_meta & 0x00ffffff)
        | ((this->path.scion.curr_hf & 0x3f) << 24)
        | (this->path.scion.curr_inf << 30);
    printf("      meta hdr 0x%08x -> 0x%08x\n", ntohl(*hdr->scion_path.meta), meta);
    *hdr->scion_path.meta = htonl(meta);
    this->udp_residual += htonl(meta);

    // Info field(s)
    struct infofield *inf = hdr->scion_path.inf;
    printf("      first seg_id 0x%08x -> 0x%08x\n",
        ntohs(inf->seg_id), ntohs(this->path.scion.seg_id[0]));
    inf->seg_id = this->path.scion.seg_id[0];
    this->udp_residual += this->path.scion.seg_id[0];
    if (this->path.scion.segment_switch)
    {
        ++inf;
        if ((void*)(inf + 1) > data_end) return;
        // For the info field it is more convenient to subtract the old value here.
        this->udp_residual -= inf->seg_id;
        this->udp_residual += this->path.scion.seg_id[1];
        printf("      second seg_id 0x%08x -> 0x%08x\n",
            ntohs(inf->seg_id), ntohs(this->path.scion.seg_id[1]));
        inf->seg_id = this->path.scion.seg_id[1];
    }
}
#endif // ENABLE_SCION_PATH

#endif //REWRITE_H_GUARD
