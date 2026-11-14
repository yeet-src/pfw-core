/* pfw: packet parsing — L2..L4 into a flat struct pkt (IPv4/IPv6, TCP/UDP),
 * tolerating a missing Ethernet header and non-first fragments.
 *
 * The struct types stay here (many units read pkt / pkt_ip4 / pkt_tcp); parse()
 * itself is a real cross-unit BPF function, defined in bpf/vm/parse/parse.bpf.c.
 * It is inlined into no program — linked once instead of into all six — and takes
 * the XDP context (it derives data/data_end itself), so it verifies standalone. */
#ifndef PFW_PARSE_H
#define PFW_PARSE_H

#include "core/common.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#endif
#ifndef AF_INET
#define AF_INET 2
#define AF_INET6 10
#endif

/* ---- the parsed frame --------------------------------------------------- */

struct pkt {
    __u32 l3, l4, payload, end;
    __u16 sport, dport;
    __u8 proto, family;
    __u8 l2; /* 14 when there is an Ethernet header, else 0 */
    __u8 saddr[16];
    __u8 daddr[16];
    __u32 seq;       /* TCP sequence of this segment's first payload byte */
    __u8 tcp_flags;  /* TCP flags byte (SYN/ACK/FIN...) */
};

struct pkt_ip4 { __u8 vihl, tos; __u16 tot_len, id, frag_off; __u8 ttl, protocol; __u16 check; __u32 saddr, daddr; };
struct pkt_ip6 { __u32 vtcfl; __u16 payload_len; __u8 nexthdr, hop_limit; __u8 saddr[16], daddr[16]; };
struct pkt_tcp { __u16 source, dest; __u32 seq, ack_seq; __u8 doff_res, flags; __u16 window, check, urg_ptr; };
struct pkt_udp { __u16 source, dest, len, check; };

/* Parse ctx into *p; returns 1 on a recognized IPv4/IPv6 frame, else 0. */
int parse(struct xdp_md *ctx, struct pkt *p);

#endif /* PFW_PARSE_H */
