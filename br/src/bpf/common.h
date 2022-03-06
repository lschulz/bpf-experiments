#ifndef COMMON_H_GUARD
#define COMMON_H_GUARD

#include "bpf/types.h"
#include "bpf/scion.h"
#include "aes/aes.h"

#include <linux/bpf.h>

// #define ENABLE_VLAN // not implemented
#define ENABLE_IPV4
// #define ENABLE_IPV6 // not implemented
#define ENABLE_SCION_PATH
#define ENABLE_INT_OVER_INNER_UDP

#define INTERNAL_IFACE 0

#define MAKE_VERDICT(action, reason) ((action & 0x07) | (reason << 3))

enum counter {
    COUNTER_UNDEFINED,
    COUNTER_SCION_FORWARD,
    COUNTER_PARSE_ERROR,
    COUNTER_NOT_SCION,
    COUNTER_NOT_IMPLEMENTED,
    COUNTER_NO_INTERFACE,
    COUNTER_ROUTER_ALERT,
    COUNTER_FIB_LKUP_DROP,
    COUNTER_FIN_LKUP_PASS,
    COUNTER_INVALID_HF,
    COUNTER_ENUM_COUNT, // always last
};

enum verdict {
    VERDICT_ABORT           = MAKE_VERDICT(XDP_ABORTED,  COUNTER_UNDEFINED),
    VERDICT_DROP            = MAKE_VERDICT(XDP_DROP,     COUNTER_UNDEFINED),
    VERDICT_PASS            = MAKE_VERDICT(XDP_PASS,     COUNTER_UNDEFINED),
    VERDICT_TX              = MAKE_VERDICT(XDP_TX,       COUNTER_UNDEFINED),
    VERDICT_SCION_FORWARD   = MAKE_VERDICT(XDP_REDIRECT, COUNTER_SCION_FORWARD),
    VERDICT_PARSE_ERROR     = MAKE_VERDICT(XDP_DROP,     COUNTER_PARSE_ERROR),
    VERDICT_NOT_SCION       = MAKE_VERDICT(XDP_PASS,     COUNTER_NOT_SCION),
    VERDICT_NOT_IMPLEMENTED = MAKE_VERDICT(XDP_PASS,     COUNTER_NOT_IMPLEMENTED),
    VERDICT_NO_INTERFACE    = MAKE_VERDICT(XDP_DROP,     COUNTER_NO_INTERFACE),
    VERDICT_ROUTER_ALERT    = MAKE_VERDICT(XDP_PASS,     COUNTER_ROUTER_ALERT),
    VERDICT_FIB_LKUP_DROP   = MAKE_VERDICT(XDP_DROP,     COUNTER_FIB_LKUP_DROP),
    VERDICT_FIB_LKUP_PASS   = MAKE_VERDICT(XDP_PASS,     COUNTER_FIN_LKUP_PASS),
    VERDICT_INVALID_HF      = MAKE_VERDICT(XDP_DROP,     COUNTER_INVALID_HF),
};

struct ingress_addr
{
    // Only one of ipv4 and ipv6 is allowed to be non-zero.
#ifdef ENABLE_IPV4
    u32 ipv4;      // in network byte order
#endif
#ifdef ENABLE_IPV6
    u32 ipv6[4];
#endif
    u16 port;    // in network byte order
    u16 ifindex; // in host byte order
};

struct hop_key
{
    struct aes_key_schedule key;
    struct aes_block subkey;
};

struct redirect_params
{
#ifdef ENABLE_IPV4
    struct {
        u32 dst;    // in network byte order
        u32 src;    // in network byte order
    } ipv4;
#endif
#ifdef ENABLE_IPV6
    struct {
        u32 dst[4]; // in network byte order
        u32 src[4]; // in network byte order
    } ipv6;
#endif
    u16 dst_port;   // in network byte order
    u16 src_port;   // in network byte order
};

struct interface
{
#ifdef ENABLE_IPV4
    u32 ipv4;   // in network byte order
#endif
#ifdef ENABLE_IPV6
    u32 ipv6[4];
#endif
    u16 port; // in network byte order
};

struct fwd_info
{
    u32 as_egress;
    union {
        struct redirect_params redirect;
        struct interface egress_br;
    };
};

struct port_stats {
    u64 verdict_bytes[COUNTER_ENUM_COUNT];
    u64 verdict_pkts[COUNTER_ENUM_COUNT];
};

struct scratchpad
{
    // Verdict if the last operation failed
    u32 verdict;

    // Constants set by the control plane

    // Copies of all fields we might need to update
    struct
    {
        u8 dst[6];
        u16 _padding1;
        u8 src[6];
        u16 _padding2;
    } eth;
    struct ip_struct {
        u32 family; // AF_INET or AF_INET6
#ifdef ENABLE_IPV4
        struct
        {
            u32 dst;
            u32 src;
            u8 ttl;
        } v4;
#endif
#ifdef ENABLE_IPV6
        struct
        {
            u32 dst[4];
            u32 src[4];
            u8 hop_limit;
        } v6;
#endif
    } ip;
    struct {
        u16 dst;
        u16 src;
    } udp;
    u32 path_type;
    union {
        struct {
            u32 h_meta; // path meta field in host byte order
            u32 curr_inf, curr_hf;
            u16 seg_id[2];
            u32 segment_switch; // one if a segment switch occurred
            u32 seg0, seg1, seg2;
            u32 num_inf, num_hf;
        } scion;
    } path;

    // Residuals of the IP and UDP checksum
    u64 ip_residual;
    u64 udp_residual;

    // Input/Output for FIB lookup
    struct bpf_fib_lookup fib_lookup;

    // Interface the packet will be redirected to
    int egress_ifindex;

    // Input for mac verification
    u32 verify_mac_mask;
    struct macinput macinput[2];
    u64 mac[2];
};

#endif // COMMON_H_GUARD
