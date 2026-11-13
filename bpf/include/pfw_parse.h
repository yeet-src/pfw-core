/* pfw: packet parsing — L2..L4 into a flat struct pkt (IPv4/IPv6, TCP/UDP),
 * tolerating a missing Ethernet header and non-first fragments. */
#ifndef PFW_PARSE_H
#define PFW_PARSE_H

#include "pfw_common.h"

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

static __always_inline int parse(void *data, void *data_end, struct pkt *p)
{
    __u32 nhoff = 0;
    __u8 version = 0;
    if (data + 15 <= data_end) {
        __u16 eth_type = bpf_ntohs(*(__u16 *) (data + 12));
        __u8 v14 = *(__u8 *) (data + 14) >> 4;
        if ((eth_type == ETH_P_IP && v14 == 4) || (eth_type == ETH_P_IPV6 && v14 == 6)) {
            nhoff = 14;
            version = v14;
        }
    }
    if (!version) {
        if (data + 1 > data_end)
            return 0;
        __u8 v0 = *(__u8 *) data >> 4;
        if (v0 != 4 && v0 != 6)
            return 0;
        version = v0;
    }
    __u32 len = (__u32) ((long) data_end - (long) data);
    __u32 end = 0;
    p->l2 = nhoff;
    if (version == 4) {
        struct pkt_ip4 *ip = data + nhoff;
        if ((void *) (ip + 1) > data_end)
            return 0;
        __u32 ihl = (__u32) (ip->vihl & 0x0f) * 4;
        if (ihl < 20)
            return 0;
        p->family = AF_INET;
        p->proto = ip->protocol;
        __builtin_memcpy(p->saddr, &ip->saddr, 4);
        __builtin_memcpy(p->daddr, &ip->daddr, 4);
        __u32 tot = bpf_ntohs(ip->tot_len);
        end = tot ? nhoff + tot : len;
        p->l4 = nhoff + ihl;
        /* A fragment other than the first has no L4 header; later
         * fragments of a first one are never seen here. Leave the
         * payload empty so a program finds nothing to scan. */
        if (bpf_ntohs(ip->frag_off) & 0x1fff) {
            p->payload = end > len ? len : end;
            p->end = p->payload;
            p->l3 = nhoff;
            return 1;
        }
    } else {
        struct pkt_ip6 *ip6 = data + nhoff;
        if ((void *) (ip6 + 1) > data_end)
            return 0;
        p->family = AF_INET6;
        p->proto = ip6->nexthdr;
        __builtin_memcpy(p->saddr, ip6->saddr, 16);
        __builtin_memcpy(p->daddr, ip6->daddr, 16);
        __u32 plen = bpf_ntohs(ip6->payload_len);
        end = plen ? nhoff + 40 + plen : len;
        p->l4 = nhoff + 40;
    }
    if (end > len)
        end = len;
    p->l3 = nhoff;
    p->end = end;
    p->payload = end;
    __u32 l4 = p->l4 & 0xff;
    if (p->proto == IPPROTO_TCP) {
        struct pkt_tcp *th = data + l4;
        if ((void *) (th + 1) > data_end)
            return 1;
        __u32 doff = (__u32) (th->doff_res >> 4) * 4;
        if (doff < 20)
            return 1;
        p->sport = bpf_ntohs(th->source);
        p->dport = bpf_ntohs(th->dest);
        p->payload = l4 + doff;
        p->seq = bpf_ntohl(th->seq);
        p->tcp_flags = th->flags;
    } else if (p->proto == IPPROTO_UDP) {
        struct pkt_udp *uh = data + l4;
        if ((void *) (uh + 1) > data_end)
            return 1;
        p->sport = bpf_ntohs(uh->source);
        p->dport = bpf_ntohs(uh->dest);
        p->payload = l4 + 8;
    }
    if (p->payload > end)
        p->payload = end;
    return 1;
}

#endif /* PFW_PARSE_H */
