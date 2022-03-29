#ifndef HEADERS_H_GUARD
#define HEADERS_H_GUARD

#include "bpf/types.h"
#include "bpf/scion.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

/// \brief Pointers into the packet buffer.
/// Must be kept on the stack so the verifier is able to keep track of pointer validity.
struct headers
{
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
#endif
    };
};

#endif // HEADERS_H_GUARD
