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
#include "constants.h"
#include "maps.h"
#include "headers.h"
#include "parser.h"
#include "path_processing.h"
#include "fib_lookup.h"
#include "rewrite.h"
#include "debug.h"

#ifdef ENABLE_HF_CHECK
#include "aes/aes.h"
#endif
#include "bpf/types.h"
#include "bpf/builtins.h"
#include "bpf/scion.h"

#include "bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

char _license[] SEC("license") = "Dual MIT/GPL";

//////////////////////////
// BPF Global Functions //
//////////////////////////

/// \brief Update the port statistics with the current packet.
/// \param[in] ctx
/// \param[in] verdict Final verdict on the packet.
int record_verdict(struct xdp_md *ctx, enum verdict verdict)
{
    if (!ctx) return XDP_ABORTED;

#ifdef XDP_DEBUG_PRINT
    switch (verdict)
    {
    case VERDICT_ABORT:
        printf("VERDICT: ABORT (XDP_ABORTED)\n");
        break;
    case VERDICT_DROP:
        printf("VERDICT: DROP (XDP_DROP)\n");
        break;
    case VERDICT_PASS:
        printf("VERDICT: PASS (XDP_PASS)\n");
        break;
    case VERDICT_TX:
        printf("VERDICT: TX (XDP_TX)\n");
        break;
    case VERDICT_SCION_FORWARD:
        printf("VERDICT: SCION_FORWARD (XDP_REDIRECT)\n");
        break;
    case VERDICT_PARSE_ERROR:
        printf("VERDICT: PARSE_ERROR (XDP_DROP)\n");
        break;
    case VERDICT_NOT_SCION:
        printf("VERDICT: NOT_SCION (XDP_PASS)\n");
        break;
    case VERDICT_NOT_IMPLEMENTED:
        printf("VERDICT: NOT_IMPLEMENTED (XDP_PASS)\n");
        break;
    case VERDICT_NO_INTERFACE:
        printf("VERDICT: NO_INTERFACE (XDP_DROP)\n");
        break;
    case VERDICT_UNDERLAY_MISMATCH:
        printf("VERDICT: UNDERLAY_MISMATCH (XDP_PASS)\n");
        break;
    case VERDICT_ROUTER_ALERT:
        printf("VERDICT: ROUTER_ALERT (XDP_PASS)\n");
        break;
    case VERDICT_FIB_LKUP_DROP:
        printf("VERDICT: FIB_LKUP_DROP (XDP_DROP)\n");
        break;
    case VERDICT_FIB_LKUP_PASS:
        printf("VERDICT: FIB_LKUP_PASSORT (XDP_PASS)\n");
        break;
    case VERDICT_INVALID_HF:
        printf("VERDICT: INVALID_HF (XDP_DROP)\n");
        break;
    }
#endif

    // We don't need atomic operations since we are using a percpu map.
    u32 ingress_ifindex = ctx->ingress_ifindex;
    struct port_stats *stats = bpf_map_lookup_elem(&port_stats_map, &ingress_ifindex);

    unsigned int index = (verdict >> 3) & 0x0f;
    if (stats && index < COUNTER_ENUM_COUNT)
    {
        stats->verdict_bytes[index] += (ctx->data_end - ctx->data);
        stats->verdict_pkts[index] += 1;
    }

    return (verdict & 0x07);
}

#ifdef ENABLE_HF_CHECK
/// \brief Verify a SCION path hop field.
/// \param[in] input 16 byte HF calculation input block
/// \param[in] expected Expected MAC truncated to 48 bits
/// \return Nonzero if hop field is valid
int verify_hop_field(struct macinput *input, u64 expected)
{
    if (!input) return false;

    // Key lookup
    u32 index = 0;
    struct hop_key *key = bpf_map_lookup_elem(&mac_key_map, &index);
    if (!key)
    {
        printf("    ERROR: No verification key\n");
        return false; // can't verify hop field without a key
    }

    struct aes_cmac mac;
    aes_cmac_16bytes((struct aes_block*)input, &key->key, &key->subkey, &mac);

    u64 actual = *(u64*)mac.w & 0x0000ffffffffffff;

    printf("    Computed MAC %012x (expected: %012x)\n", actual, expected);
    return actual == expected;
}
#endif // ENABLE_HF_CHECK


/// \brief Main packet processing function, does almost everything except hop field verification
/// and setting up the packet redirection.
/// \return Negative value if the packet should be forwarded, nonnegative verdict
/// (VERDICT_ABORT, VERDICT_DROP, VERDICT_PASS) if the packet should be dropped/passed to userspace.
int process_packet(struct xdp_md* ctx, struct scratchpad *this)
{
    if (!ctx || !this) return -1;

    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    printf("  packet length = %d\n", data_end - data);

    // Headers pointers must be kept on the stack
    struct headers hdr = {};

    this->last_hop = 0;
    this->ip_residual = 0;
    this->udp_residual = 0;
    this->egress_ifindex = -1;
#ifdef ENABLE_HF_CHECK
    this->verify_mac_mask = 0;
#endif

    /////////////
    // Parsing //
    /////////////

    printf("  === Parser ===\n");

    data = parse_underlay(this, &hdr, data, data_end);
    if (!data) return record_verdict(ctx, this->verdict);

    data = parse_scion(this, &hdr, data, data_end);
    if (!data) return record_verdict(ctx, this->verdict);

    ////////////////////////////////////
    // Determine AS Ingress Interface //
    ////////////////////////////////////

    printf("  === Ingress ===\n");

    u32 as_ing_ifid = INTERNAL_IFACE;
    u32 key = ctx->ingress_ifindex;
    if (!bpf_map_lookup_elem(&int_iface_map, &key))
    {
        // This lookup is necessary, because there can be multiple logical interfaces using
        // different UDP ports behind the same physical interface.
        struct ingress_addr ingress = {
            .ifindex = ctx->ingress_ifindex,
            .port = this->udp.dst,
        };
#ifdef ENABLE_IPV4
        ingress.ipv4 = this->ip.v4.dst;
#endif
#ifdef ENABLE_IPV6
        memcpy(ingress.ipv6, &this->ip.v6.dst, sizeof(ingress.ipv6));
#endif
        u32 *ifid = bpf_map_lookup_elem(&ingress_map, &ingress);
        if (!ifid) return record_verdict(ctx, VERDICT_NO_INTERFACE);
        as_ing_ifid = *ifid;

        // Make sure the packet entered through the same ingress interface as specified in the hop
        // field.
        u16 hf_ingress;
        if (INF_GET_CONS(hdr.scion_path.inf))
            hf_ingress = hdr.scion_path.hf->ingress;
        else
            hf_ingress = hdr.scion_path.hf->egress;
        printf("    hf ingress ifid = %d\n", as_ing_ifid);
        if (ntohs(hf_ingress) != as_ing_ifid)
            return record_verdict(ctx, VERDICT_NO_INTERFACE);
    }
    printf("    ingress ifid = %d\n", as_ing_ifid);

    ///////////////////////////
    // AS Ingress Processing //
    ///////////////////////////

    if (as_ing_ifid != INTERNAL_IFACE)
    {
        // Perform ingress processing if the packet came from another AS
        switch (this->path_type)
        {
#ifdef ENABLE_SCION_PATH
        case SC_PATH_TYPE_SCION:
            if (!scion_as_ingress(this, &hdr, data_end))
                return record_verdict(ctx, this->verdict);
            break;
#endif
        default:
            break;
        }
    }

    ///////////////////////////////
    // FIB Lookup and Forwarding //
    ///////////////////////////////

    printf("  === Forwarding ===\n");

    int lkup_res = -1;
    init_fib_lookup(this, &hdr, ctx);

    if (this->last_hop)
    {
        // Forward to the destination host in our AS
        printf("     ## FIB lookup for destination host in local AS ##\n");
        lkup_res = forward_to_endhost(this, &hdr, ctx);
    }
    else
    {
        // Determine AS egress interface
        printf("    ## Determine AS egress interface ##\n");
        struct infofield *inf = hdr.scion_path.inf;
        if (this->path.scion.segment_switch)
        {
            ++inf;
            if ((void*)(inf + 1) > data_end) return false;
        }
        key = ntohs(INF_GET_CONS(inf)
            ? hdr.scion_path.hf->egress
            : hdr.scion_path.hf->ingress);
        struct fwd_info *fwd = bpf_map_lookup_elem(&egress_map, &key);
        if (!fwd)
        {
            printf("      ERROR: Egress interface not found\n");
            return record_verdict(ctx, VERDICT_DROP);
        }
        printf("      fwd_external = %d\n", fwd->fwd_external);

        // Forwarding
        printf("    ## FIB lookup ##\n");
        if (fwd->fwd_external)
        {
            // Forward to next AS on path
            printf("      Forward to next AS on path\n");
            switch (this->path_type)
            {
#ifdef ENABLE_SCION_PATH
            case SC_PATH_TYPE_SCION:
                if (!scion_as_egress(this, &hdr, as_ing_ifid, data_end))
                    return record_verdict(ctx, this->verdict);
            break;
#endif
            default:
                break;
            }
            if (fwd->link.ip_family != this->ip.family)
                return record_verdict(ctx, VERDICT_UNDERLAY_MISMATCH);
            lkup_res = forward_scion_link(this, ctx, &fwd->link);
        }
        else
        {
            if (as_ing_ifid != INTERNAL_IFACE)
            {
                // Forward packet from another AS to another border router in our AS
                printf("      Forward to sibling\n");
                if (fwd->sibling.ip_family != this->ip.family)
                    return record_verdict(ctx, VERDICT_UNDERLAY_MISMATCH);
                lkup_res = forward_internal(this, ctx, &fwd->sibling);
            }
            else
            {
                // Forward a SCION packet between other (border) routers in our AS
                printf("      Forward between siblings\n");
                lkup_res = forward_outer_ip(this, ctx);
            }
        }
    }

    printf("    egress interface = %d\n", lkup_res);
    if (lkup_res == LKUP_RES_RETURN)
        return record_verdict(ctx, this->verdict);

    //////////////////////
    // Packet Rewriting //
    //////////////////////

    printf("  === Rewrite ===\n");
    rewrite(this, &hdr, data_end);
    this->egress_ifindex = lkup_res;
    return -1;
}

/// \brief Entry point of the XDP border router.
SEC("xdp")
int border_router(struct xdp_md* ctx)
{
    printf("=== Packet ingress at port %d ===\n", ctx->ingress_ifindex);
    u32 key = 0;
    struct scratchpad *this = bpf_map_lookup_elem(&scratchpad_map, &key);
    if (!this) return XDP_ABORTED;

    int verdict = process_packet(ctx, this);
    if (verdict > 0) return verdict;

#ifdef ENABLE_HF_CHECK
    //////////////////////
    // MAC Verification //
    //////////////////////

    printf("  === MAC Verification ===\n");

    if (this->verify_mac_mask & 0x01)
    {
        printf("    Verify first HF\n");
        if(!verify_hop_field(&this->macinput[0], this->mac[0]))
            return record_verdict(ctx, VERDICT_INVALID_HF);
    }
    if (this->verify_mac_mask & 0x02)
    {
        printf("    Verify second HF\n");
        if(!verify_hop_field(&this->macinput[1], this->mac[1]))
            return record_verdict(ctx, VERDICT_INVALID_HF);
    }
#endif

    ////////////
    // Output //
    ////////////

    printf("Redirect to port %d\n", this->egress_ifindex);
    verdict = XDP_ABORTED;
    if (bpf_redirect_map(&tx_port_map, this->egress_ifindex, XDP_ABORTED) == XDP_REDIRECT)
        verdict = VERDICT_SCION_FORWARD;
    else
        printf("ERROR: Egress port not found\n");
    return record_verdict(ctx, verdict);
}
