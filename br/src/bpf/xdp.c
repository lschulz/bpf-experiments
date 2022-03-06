#include "bpf/types.h"
#include "bpf/builtins.h"
#include "bpf/scion.h"
#include "aes/aes.h"
#include "common.h"

#include "bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

char _license[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define AF_INET6 10
#define DEFAULT_TTL 64


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ingress_addr)); // Destination IP, port and ingress interface
    __uint(value_size, sizeof(u32)); // Corresponding AS interface
    __uint(max_entries, 16);
} ingress_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32)); // AS egress interface
    __uint(value_size, sizeof(struct fwd_info)); // Information on how to forward the packet
    __uint(max_entries, 16);
} egress_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32)); // Interface index
    __uint(value_size, sizeof(struct interface)); // Corresponding IP and UDP port
    __uint(max_entries, 16);
} int_iface_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32)); // Index
    __uint(value_size, sizeof(struct hop_key)); // AES key for MAC verification
    __uint(max_entries, 8);
} mac_key_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(u32)); // AS egress interface
    __uint(value_size, sizeof(u32)); // Redirection target interface index
    __uint(max_entries, 16);
} tx_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct port_stats));
    __uint(max_entries, COUNTER_ENUM_COUNT);
} port_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct scratchpad));
    __uint(max_entries, 1);
} scratchpad_map SEC(".maps");

// Pointers to relevant headers
struct headers {
    struct ethhdr *eth;
    union {
        struct iphdr *v4;
        struct ipv6hdr *v6;
    } ip;
    struct udphdr *udp;
    struct scionhdr *scion;
    union {
#ifdef ENABLE_SCION_PATH
        struct {
            u32 *meta;
            struct infofield *inf;
            struct hopfield *hf;
        } scion_path;
    };
#endif
};

// Forward delcarations
int record_verdict(struct xdp_md *ctx, enum verdict verdict);
int verify_hop_field(struct macinput *block, u64 expected);
inline void* parse_underlay(struct scratchpad *this, struct headers *hdr, void *data, void *data_end);
inline void* parse_scion(struct scratchpad *this, struct headers *hdr, void *data, void *data_end);
inline void* parse_scion_path(struct scratchpad *this, struct headers *hdr, void *data, void *data_end);
inline void defer_verify_hop_field(struct scratchpad *this, unsigned int which, struct infofield *info, struct hopfield *hop, u16 beta);
inline bool scion_as_ingress(struct scratchpad *this, struct headers *hdr, void *data_end);
inline bool scion_as_egress(struct scratchpad *this, struct headers *hdr, u32 as_ing_ifid, void *data_end);
inline void init_fib_lookup(struct scratchpad *this, struct headers *hdr, struct xdp_md* ctx);
inline int fib_lookup_as_egress(struct scratchpad *this, struct xdp_md* ctx, struct fwd_info *fwd);
inline int fib_lookup_egress_br(struct scratchpad *this, struct xdp_md* ctx, struct fwd_info *fwd);
inline int fib_lookup_ip_forward(struct scratchpad *this, struct headers *hdr, struct xdp_md* ctx, struct fwd_info *fwd);
inline void rewrite(struct scratchpad *this, struct headers *hdr, void *data_end);
inline void rewrite_scion_path(struct scratchpad *this, struct headers *hdr, void *data_end);


int record_verdict(struct xdp_md *ctx, enum verdict verdict)
{
    if (!ctx) return XDP_ABORTED;

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

int verify_hop_field(struct macinput *input, u64 expected)
{
    if (!input) return false;

    // Key lookup
    u32 index = 0;
    struct hop_key *key = bpf_map_lookup_elem(&mac_key_map, &index);
    if (!key) return false; // can't verify hop field without a key

    struct aes_cmac mac;
    aes_cmac_16bytes((struct aes_block*)input, &key->key, &key->subkey, &mac);

    u64 actual = *(u64*)mac.w & 0x0000ffffffffffff;
    return actual == expected;
}

/// \brief Parse the Ethernet header and IP/UDP underlay.
__attribute__((__always_inline__))
inline void* parse_underlay(struct scratchpad *this, struct headers *hdr, void *data, void *data_end)
{
    this->verdict = VERDICT_NOT_SCION;

    // Ethernet
    hdr->eth = data;
    data += sizeof(*hdr->eth);
    if (data > data_end) return NULL;
    memcpy(this->eth.dst, hdr->eth->h_dest, ETH_ALEN);
    memcpy(this->eth.src, hdr->eth->h_source, ETH_ALEN);

    // IP
    switch (hdr->eth->h_proto)
    {
#ifdef ENABLE_IPV4
    case htons(ETH_P_IP):
        hdr->ip.v4 = data;
        data += sizeof(*hdr->ip.v4);
        if (data > data_end) return NULL;
        this->ip.family = AF_INET;
        this->ip_residual -= (this->ip.v4.dst = hdr->ip.v4->daddr);
        this->ip_residual -= (this->ip.v4.src = hdr->ip.v4->saddr);
        this->udp_residual = this->ip_residual;
        // TTL is not part of UDP checksum
        this->ip_residual -= (this->ip.v4.ttl = hdr->ip.v4->ttl);
        // Skip options
        size_t skip = 4 * (size_t)hdr->ip.v4->ihl - sizeof(*hdr->ip.v4);
        if (skip > 40) return NULL;
        data += skip;
    #ifdef ENABLE_IPV6
        memset(this->ip.v6, 0, sizeof(this->ip.v6));
    #endif
        if (hdr->ip.v4->protocol != IPPROTO_UDP) return NULL;
        break;
#endif
#ifdef ENABLE_IPV6
    case htons(ETH_P_IPV6):
        this->hdr.ip.v6 = data;
        data += sizeof(*this->hdr.ip.v6);
        if (data > data_end) return NULL;
        this->ip.family = AF_INET6;
        memcpy(this->ip.v6.dst, &this->hdr.ip.v6->daddr, 16);
        memcpy(this->ip.v6.src, &this->hdr.ip.v6->saddr, 16);
        this->ip.v6.hop_limit = this->hdr.ip.v6->hop_limit;
        // TODO: checksum residual
    #ifdef ENABLE_IPV4
        memset(this->ip.v4, 0, sizeof(this->ip.v4));
    #endif
        if (this->hdr.ip.v6->nexthdr != IPPROTO_UDP) return NULL;
#endif
    default:
        return NULL;
    }

    // UDP
    hdr->udp = data;
    data += sizeof(*hdr->udp);
    if (data > data_end) return NULL;
    this->udp_residual -= (this->udp.dst = hdr->udp->dest);
    this->udp_residual -= (this->udp.src = hdr->udp->source);

    return data;
};

/// \brief Parse the SCION headers.
__attribute__((__always_inline__))
inline void* parse_scion(struct scratchpad *this, struct headers *hdr, void *data, void *data_end)
{
    this->verdict = VERDICT_PARSE_ERROR;

    // SCION common and address header
    hdr->scion = data;
    data += sizeof(*hdr->scion);
    if (data > data_end) return NULL;
    if (SC_GET_VER(hdr->scion) != 0)
    {
        this->verdict = VERDICT_NOT_IMPLEMENTED;
        return NULL;
    }

    // Skip over AS-internal addresses
    data += 8 + 4 * SC_GET_DL(hdr->scion) + 4 * SC_GET_SL(hdr->scion);
    if (data > data_end) return NULL;

    // Path
    this->path_type = hdr->scion->type;
    switch (hdr->scion->type)
    {
#ifdef ENABLE_SCION_PATH
    case SC_PATH_TYPE_SCION:
        return parse_scion_path(this, hdr, data, data_end);
#endif
    default:
        this->verdict = VERDICT_NOT_IMPLEMENTED;
        return NULL;
    }
}

#ifdef ENABLE_SCION_PATH
/// \brief Parse standard SCION path
__attribute__((__always_inline__))
inline void* parse_scion_path(struct scratchpad *this, struct headers *hdr, void *data, void *data_end)
{
    this->verdict = VERDICT_PARSE_ERROR;

    // Meta header
    hdr->scion_path.meta = data;
    data += sizeof(*hdr->scion_path.meta);
    if (data > data_end) return NULL;
    this->udp_residual -= *hdr->scion_path.meta;

    this->path.scion.h_meta = ntohl(*hdr->scion_path.meta);
    this->path.scion.seg0 = PATH_GET_SEG0_HOST(this->path.scion.h_meta);
    this->path.scion.seg1 = PATH_GET_SEG1_HOST(this->path.scion.h_meta);
    this->path.scion.seg2 = PATH_GET_SEG2_HOST(this->path.scion.h_meta);

    // Calculate number of info and hop fields
    u32 num_inf = (this->path.scion.seg0 > 0) + (this->path.scion.seg1 > 0)
        + (this->path.scion.seg2 > 0);
    u32 num_hf = this->path.scion.seg0 + this->path.scion.seg1 + this->path.scion.seg2;
    this->path.scion.num_inf = num_inf;
    this->path.scion.num_hf = num_hf;

    // Find current info and hop field
    // A second info field is needed if the path changes over from one segment to the next and
    // the same router is both the AS ingress and egress point.
    u32 curr_inf = this->path.scion.curr_inf = PATH_GET_CURR_INF_HOST(this->path.scion.h_meta);
    u32 curr_hf = this->path.scion.curr_hf = PATH_GET_CURR_HF_HOST(this->path.scion.h_meta);
    this->path.scion.segment_switch = 0;

    // Current info field
    struct infofield *inf = data + curr_inf * sizeof(struct infofield);
    hdr->scion_path.inf = inf;
    if (((void*)inf + sizeof(struct infofield)) > data_end) return NULL;
    this->path.scion.seg_id[0] = inf->seg_id;
    this->udp_residual -= inf->seg_id;

    // Next info field
    if (curr_inf + 1 < num_inf)
    {
        ++inf;
        if (((void*)inf + sizeof(struct infofield)) > data_end) return NULL;
        this->path.scion.seg_id[1] = inf->seg_id;
    }

    // Current hop field
    hdr->scion_path.hf = data
        + num_inf *sizeof(struct infofield) + curr_hf * sizeof(struct hopfield);
    if (((void*)hdr->scion_path.hf + sizeof(struct hopfield)) > data_end) return NULL;

    return data;
}
#endif

__attribute__((__always_inline__))
inline void defer_verify_hop_field(
    struct scratchpad *this, unsigned int which,
    struct infofield *info, struct hopfield *hop, u16 beta)
{
    // Set flag to enable mac verification at the end of packet processing
    this->verify_mac_mask |= (1 << which);

    // Prepare input for MAC calculation
    memset(&this->macinput[which], 0, sizeof(struct macinput));
    this->macinput[which].beta = beta;
    this->macinput[which].ts = info->ts;
    this->macinput[which].exp = hop->exp;
    this->macinput[which].ingress = hop->ingress;
    this->macinput[which].egress = hop->egress;

    // Store MAC from HF for comparison
    this->mac[which] = 0;
    memcpy(&this->mac[which], hop->mac, sizeof(hop->mac));
}

/// \brief AS ingress processing
__attribute__((__always_inline__))
inline bool scion_as_ingress(struct scratchpad *this, struct headers *hdr, void *data_end)
{
    // Full router must handle the packet if router alert flags are set
    if (hdr->scion_path.hf->flags & 0x03)
    {
        this->verdict = VERDICT_ROUTER_ALERT;
        return false;
    }

    // Hop field verifiaction and MAC chaining
    u16 beta = ntohs(this->path.scion.seg_id[0]);
    if (!INF_GET_CONS(hdr->scion_path.inf))
    {
        struct hopfield *hf = hdr->scion_path.hf;
        beta ^= (u16)hf->mac[1] | (((u16)hf->mac[0]) << 8);
    }
    defer_verify_hop_field(this, 0, hdr->scion_path.inf, hdr->scion_path.hf, htons(beta));
    if (!INF_GET_CONS(hdr->scion_path.inf))
        this->path.scion.seg_id[0] = htons(beta);

    // Switch to next path segment if necessary
    u32 seg_end = this->path.scion.seg0;
    if (this->path.scion.curr_inf >= 1) seg_end += this->path.scion.seg0;
    if (this->path.scion.curr_inf >= 2) seg_end += this->path.scion.seg0;
    u32 next_hf = this->path.scion.curr_hf + 1;
    if (next_hf >= this->path.scion.num_hf)
    {
        // Path ends in our AS
        // TODO: Deliver packet to the dispatcher
        this->verdict = VERDICT_NOT_IMPLEMENTED;
        return false;
    }
    if (next_hf < this->path.scion.num_hf && next_hf == seg_end)
    {
        // Advance to next path segment
        this->path.scion.segment_switch = 1;
        ++this->path.scion.curr_inf;
        ++this->path.scion.curr_hf;
        ++hdr->scion_path.hf;
        if (((void*)hdr->scion_path.hf + sizeof(struct hopfield)) > data_end)
        {
            this->verdict = VERDICT_PARSE_ERROR;
            return false;
        }
    }

    return true;
}

/// \brief AS egress processing
/// \return True if processing can continue, false on error (check this->verdict).
__attribute__((__always_inline__))
inline bool scion_as_egress(struct scratchpad *this, struct headers *hdr, u32 as_ing_ifid, void *data_end)
{
    this->verdict = XDP_ABORTED;

    // Full router must handle the packet if router alert flags are set
    if (hdr->scion_path.hf->flags & 0x03)
    {
        this->verdict = VERDICT_ROUTER_ALERT;
        return false;
    }

    // If segment_switch is one, we need to work with the second segment identifier.
    u32 seg_switch = this->path.scion.segment_switch;
    if (seg_switch > 1) return false;

    // If we have switched from one segment to another at the end of ingress processing,
    // we must use and update the new current hop field during egress processing.
    struct infofield *inf = hdr->scion_path.inf;
    if (seg_switch)
    {
        ++inf;
        if ((void*)(inf + 1) > data_end) return false;
    }

    u16 beta = ntohs(this->path.scion.seg_id[seg_switch]);
    if (as_ing_ifid == INTERNAL_IFACE) // avoid checking the same hop field twice
        defer_verify_hop_field(this, 1, hdr->scion_path.inf, hdr->scion_path.hf, htons(beta));
    if (INF_GET_CONS(inf))
    {
        struct hopfield *hf = hdr->scion_path.hf;
        u16 seg_id = beta ^ ((u16)hf->mac[1] | ((u16)hf->mac[0] << 8));
        this->path.scion.seg_id[seg_switch] = htons(seg_id);
    }
    ++this->path.scion.curr_hf;

    return true;
}

/// \brief Initialize the xdp_fib_lookup structure with common data.
__attribute__((__always_inline__))
inline void init_fib_lookup(struct scratchpad *this, struct headers *hdr, struct xdp_md* ctx)
{
    memset(&this->fib_lookup, 0, sizeof(struct bpf_fib_lookup));
    this->fib_lookup.family = this->ip.family;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->fib_lookup.l4_protocol = hdr->ip.v4->protocol;
        this->fib_lookup.tos = hdr->ip.v4->tos;
        this->fib_lookup.tot_len = ntohs(hdr->ip.v4->tot_len);
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        this->fib_lookup.l4_protocol = this->hdr.ip.v6->nexthdr;
        this->fib_lookup.tot_len = ntohs(this->hdr.ip.v6->payload_len);
        break;
#endif
    default:
        break;
    }
    this->fib_lookup.ifindex = ctx->ingress_ifindex;
}

/// \brief Prepare forwarding the packet to the next AS.
/// \return Index of the switch egress interface or -1 on error.
__attribute__((__always_inline__))
inline int fib_lookup_as_egress(struct scratchpad *this, struct xdp_md* ctx, struct fwd_info *fwd)
{
    this->udp.dst = this->fib_lookup.dport = fwd->redirect.dst_port;
    this->udp.src = this->fib_lookup.sport = fwd->redirect.src_port;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->ip.v4.dst = this->fib_lookup.ipv4_dst = fwd->redirect.ipv4.dst;
        this->ip.v4.src = this->fib_lookup.ipv4_src = fwd->redirect.ipv4.src;
        this->ip.v4.ttl = DEFAULT_TTL;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->fib_lookup.ipv6_dst, fwd->redirect.ipv6.dst, 16);
        memcpy(this->ip.v6.dst, fwd->redirect.ipv6.dst, 16);
        memcpy(this->fib_lookup.ipv6_src, fwd->redirect.ipv6.src, 16);
        memcpy(this->ip.v6.dst, fwd->redirect.ipv6.src, 16);
        this->ip.v6.hop_limit = DEFAULT_TTL;
        break;
#endif
    default:
        break;
    }

    int res = bpf_fib_lookup(ctx, &this->fib_lookup, sizeof(struct bpf_fib_lookup), 0);
    if (res != BPF_FIB_LKUP_RET_SUCCESS)
    {
        switch (res)
        {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            this->verdict = VERDICT_FIB_LKUP_DROP;
            return -1;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            this->verdict = VERDICT_FIB_LKUP_PASS;
            return -1;
        }
    }

    memcpy(this->eth.dst, this->fib_lookup.dmac, ETH_ALEN);
    memcpy(this->eth.src, this->fib_lookup.smac, ETH_ALEN);

    return this->fib_lookup.ifindex;
}

/// \brief Prepare forwarding the packet to another border router in the same AS.
/// \return Index of the switch egress interface or -1 on error.
__attribute__((__always_inline__))
inline int fib_lookup_egress_br(struct scratchpad *this, struct xdp_md* ctx, struct fwd_info *fwd)
{
    this->udp.dst = this->fib_lookup.dport = fwd->egress_br.port;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->ip.v4.dst = this->fib_lookup.ipv4_dst = fwd->egress_br.ipv4;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->fib_lookup.ipv6_dst, fwd->egress_br.ipv6, 16);
        memcpy(this->ip.v6.dst, fwd->egress_br.ipv6, 16);
        break;
#endif
    default:
        break;
    }

    int res = bpf_fib_lookup(ctx, &this->fib_lookup, sizeof(struct bpf_fib_lookup), 0);
    if (res != BPF_FIB_LKUP_RET_SUCCESS)
    {
        switch (res)
        {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            this->verdict = VERDICT_FIB_LKUP_DROP;
            return -1;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            this->verdict = VERDICT_FIB_LKUP_PASS;
            return -1;
        }
    }

    memcpy(this->eth.dst, this->fib_lookup.dmac, ETH_ALEN);
    memcpy(this->eth.src, this->fib_lookup.smac, ETH_ALEN);

    // Internal interface lookup
    struct interface *iface;
    u32 key = this->fib_lookup.ifindex;
    iface = bpf_map_lookup_elem(&int_iface_map, &key);
    if (!iface)
    {
        this->verdict = VERDICT_ABORT;
        return -1;
    }

    this->udp.src = iface->port;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->ip.v4.src = iface->ipv4;
        this->ip.v4.ttl = DEFAULT_TTL;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->ip.v6.src, iface->ipv6, 16);
        this->ip.v6.hop_limit = DEFAULT_TTL;
        break;
#endif
    default:
        break;
    }

    return this->fib_lookup.ifindex;
}

/// \brief Prepare forwarding a packet received from a border router in our AS to another border
// router in this AS.
/// \return Index of the switch egress interface or -1 on error.
__attribute__((__always_inline__))
inline int fib_lookup_ip_forward(struct scratchpad *this, struct headers *hdr, struct xdp_md* ctx, struct fwd_info *fwd)
{
    this->fib_lookup.dport = hdr->udp->dest;
    this->fib_lookup.sport = hdr->udp->source;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->fib_lookup.ipv4_dst = hdr->ip.v4->daddr;
        this->fib_lookup.ipv4_src = hdr->ip.v4->saddr;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->fib_lookup.ipv6_dst, &this->hdr.ip.v6->daddr, 16);
        memcpy(this->fib_lookup.ipv6_src, &this->hdr.ip.v6->saddr, 16);
        break;
#endif
    default:
        break;
    }

    int res = bpf_fib_lookup(ctx, &this->fib_lookup, sizeof(struct bpf_fib_lookup), 0);
    if (res != BPF_FIB_LKUP_RET_SUCCESS)
    {
        switch (res)
        {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            this->verdict = VERDICT_FIB_LKUP_DROP;
            return -1;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            this->verdict = VERDICT_FIB_LKUP_PASS;
            return -1;
        }
    }

    memcpy(this->eth.dst, this->fib_lookup.dmac, ETH_ALEN);
    memcpy(this->eth.src, this->fib_lookup.smac, ETH_ALEN);
    --this->ip.v4.ttl;
    return this->fib_lookup.ifindex;
}

/// \brief Write pending changes into the packet and update the checksums.
__attribute__((__always_inline__))
inline void rewrite(struct scratchpad *this, struct headers *hdr, void *data_end)
{
    // Ethernet
    memcpy(hdr->eth->h_dest, this->eth.dst, ETH_ALEN);
    memcpy(hdr->eth->h_source, this->eth.src, ETH_ALEN);

    // IP
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
    {
        u64 csum = (hdr->ip.v4->daddr = this->ip.v4.dst);
        csum += (hdr->ip.v4->saddr = this->ip.v4.src);
        this->ip_residual += csum;
        this->udp_residual += csum;
        this->ip_residual += (hdr->ip.v4->ttl = this->ip.v4.ttl);
        // Update checksum
        csum = ~hdr->ip.v4->check + this->ip_residual + 1;
        csum = (csum & 0xffff) + (csum >> 16);
        csum = (csum & 0xffff) + (csum >> 16);
        csum = ~csum;
        if (csum == 0) csum = 0xffff;
        hdr->ip.v4->check = csum;
        break;
    }
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        // TODO
        break;
#endif
    default:
        break;
    }

    // UDP
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
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = ~csum;
    if (csum == 0) csum = 0xffff;
    hdr->udp->check= csum;
}

#ifdef ENABLE_SCION_PATH
/// \brief Update the SCION path headers.
__attribute__((__always_inline__))
inline void rewrite_scion_path(struct scratchpad *this, struct headers *hdr, void *data_end)
{
    // Meta header
    u32 meta = (this->path.scion.h_meta & 0x00ffffff)
        | ((this->path.scion.curr_hf & 0x3f) << 24)
        | (this->path.scion.curr_inf << 30);
    *hdr->scion_path.meta = htonl(meta);
    this->udp_residual += htonl(meta);

    // Info field(s)
    struct infofield *inf = hdr->scion_path.inf;
    inf->seg_id = this->path.scion.seg_id[0];
    this->udp_residual += this->path.scion.seg_id[0];
    if (this->path.scion.segment_switch)
    {
        ++inf;
        if ((void*)(inf + 1) > data_end) return;
        // For the info field it is more convenient to subtract the old value here.
        // TODO: Do that for all fields.
        this->udp_residual -= inf->seg_id;
        this->udp_residual += this->path.scion.seg_id[1];
        inf->seg_id = this->path.scion.seg_id[1];
    }
}
#endif // ENABLE_SCION_PATH

int process_packet(struct xdp_md* ctx, struct scratchpad *this)
{
    if (!ctx || !this) return -1;

    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    // Headers pointers must be kept on the stack
    struct headers hdr = {};

    this->ip_residual = 0;
    this->udp_residual = 0;
    this->egress_ifindex = -1;
    this->verify_mac_mask = 0;

    /////////////
    // Parsing //
    /////////////

    data = parse_underlay(this, &hdr, data, data_end);
    if (!data) return record_verdict(ctx, this->verdict);

    data = parse_scion(this, &hdr, data, data_end);
    if (!data) return record_verdict(ctx, this->verdict);

    ////////////////////////////////////
    // Determine AS Ingress Interface //
    ////////////////////////////////////

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
        memcpy(ingress.ipv6, &this->ip.v6.dst, 16);
        memcpy(this->fib_lookup.ipv6_dst, &this->hdr.ip.v6->daddr, 16);
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
        if (ntohs(hf_ingress) != as_ing_ifid)
            return record_verdict(ctx, VERDICT_NO_INTERFACE);
    }

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

    ///////////////////////////////////////
    // Determine AS and Egress Interface //
    ///////////////////////////////////////

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
    if (!fwd) return record_verdict(ctx, VERDICT_ABORT);

    /////////////////////////////////////////
    // FIB Lookup and AS Egress Processing //
    /////////////////////////////////////////

    int egress_ifindex = -1;
    init_fib_lookup(this, &hdr, ctx);
    if (fwd->as_egress)
    {
        // Forward to next AS on path
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
        egress_ifindex = fib_lookup_as_egress(this, ctx, fwd);
    }
    else
    {
        if (as_ing_ifid != INTERNAL_IFACE)
        {
            // Forward packet from another AS to another border router in our AS
            egress_ifindex = fib_lookup_egress_br(this, ctx, fwd);
        }
        else
        {
            // Forward a SCION packet between other (border) routers in our AS
            egress_ifindex = fib_lookup_ip_forward(this, &hdr, ctx, fwd);
        }
    }
    if (egress_ifindex < 0)
        return record_verdict(ctx, this->verdict);

    //////////////////////
    // Packet Rewriting //
    //////////////////////

    rewrite(this, &hdr, data_end);

    this->egress_ifindex = egress_ifindex;
    return -1;
}

SEC("xdp")
int border_router(struct xdp_md* ctx)
{
    u32 key = 0;
    struct scratchpad *this = bpf_map_lookup_elem(&scratchpad_map, &key);
    if (!this) return XDP_ABORTED;

    int verdict = process_packet(ctx, this);
    if (verdict > 0) return verdict;

    //////////////////////
    // MAC Verification //
    //////////////////////

    if (this->verify_mac_mask & 0x01)
    {
        if(!verify_hop_field(&this->macinput[0], this->mac[0]))
            return record_verdict(ctx, VERDICT_INVALID_HF);
    }
    if (this->verify_mac_mask & 0x02)
    {
        if(!verify_hop_field(&this->macinput[1], this->mac[1]))
            return record_verdict(ctx, VERDICT_INVALID_HF);
    }

    ////////////
    // Output //
    ////////////

    verdict = XDP_ABORTED;
    if (bpf_redirect_map(&tx_port_map, this->egress_ifindex, XDP_ABORTED) == XDP_REDIRECT)
        verdict = VERDICT_SCION_FORWARD;
    return record_verdict(ctx, verdict);
}
