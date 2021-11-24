#ifndef HEADERS_H_GUARD
#define HEADERS_H_GUARD

#include "types.h"

/* Ethernet */

#define ETH_ADDR_LEN 6
#define ETH_PROTO_IP 0x0800
#define ETH_PROTO_IPV6 0x86DD

typedef struct __attribute__((packed)) ethhdr {
    unsigned char dest[ETH_ADDR_LEN];
    unsigned char source[ETH_ADDR_LEN];
    u16 proto;
} ethhdr_t;

/* IP v4 */

#define IP_PROTO_ICMP 0x01
#define IP_PROTO_TCP 0x06
#define IP_PROTO_UDP 0x11

typedef struct __attribute__((packed)) iphdr {
    u8 ihl : 4;
    u8 version : 4;
    u8 tos;
    u16 tot_len;
    u16 id;
    u16 frag_off;
    u8 ttl;
    u8 protocol;
    u16 check;
    u32 source;
    u32 dest;
} iphdr_t;

/* UDP */

typedef struct __attribute__((packed)) udphdr {
    u16 source;
    u16 dest;
    u16 len;
    u16 check;
} udphdr_t;

#endif // HEADERS_H_GUARD
