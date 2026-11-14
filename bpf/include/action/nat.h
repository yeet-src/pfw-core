/* pfw: NAT — rewrite one endpoint of an IPv4 TCP/UDP packet and fix the IP and
 * L4 checksums, plus the connection table that makes `dnat` two-way.
 *
 * `dnat(ip, port)` rewrites the DESTINATION of a packet the program forwards.
 * A one-way rewrite is enough for a datagram, but a TCP connection (or any
 * request/reply exchange) also needs the reply translated back: the server we
 * diverted to answers from ITS address, which the client's socket does not know.
 * So do_dnat records the reply tuple in `nat`, and the entry rewrites the source
 * of any packet that matches it back to the address the client originally
 * dialled (nat_reverse). The program runs once per forward packet; replies are
 * translated and passed without running it.
 */
#ifndef PFW_NAT_H
#define PFW_NAT_H

#include "core/common.h"
#include "core/maps.h"

struct nat_rw {
    __u32 l3, l4, proto;
    __be32 ip;    /* the new address */
    __be16 port;  /* the new port */
    __u16 src;    /* 1 = rewrite the source endpoint, 0 = the destination */
};

static __always_inline __u16 nat_csum_apply(__u16 ck, __wsum diff)
{
    __u32 s = (__u16) ~ck;
    s += diff;
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    return (__u16) ~s;
}

/* Rewrite the chosen endpoint in place. *oldip / *oldport receive what was
 * there (the caller needs them to record the mapping). Returns 0 on success.
 * __noinline: its locals stay off the caller's frame. */
static __noinline int nat_rewrite(struct xdp_md *xdp, struct nat_rw *a, __be32 *oldip, __be16 *oldport)
{
    __u32 ipoff = a->l3 + (a->src ? 12 : 16);
    __u32 ptoff = a->l4 + (a->src ? 0 : 2);
    __be32 oip = 0, nip = a->ip;
    __be16 opt = 0, npt = a->port;
    if (bpf_xdp_load_bytes(xdp, ipoff, &oip, 4) || bpf_xdp_load_bytes(xdp, ptoff, &opt, 2))
        return -1;
    bpf_xdp_store_bytes(xdp, ipoff, &nip, 4);
    bpf_xdp_store_bytes(xdp, ptoff, &npt, 2);
    __wsum dip = bpf_csum_diff(&oip, 4, &nip, 4, 0);
    __u16 ipck = 0;                                      /* IP header checksum */
    if (bpf_xdp_load_bytes(xdp, a->l3 + 10, &ipck, 2) == 0) {
        ipck = nat_csum_apply(ipck, dip);
        bpf_xdp_store_bytes(xdp, a->l3 + 10, &ipck, 2);
    }
    __u32 coff = a->proto == IPPROTO_TCP ? a->l4 + 16 : a->l4 + 6; /* L4 checksum */
    __u16 l4ck = 0;
    if (bpf_xdp_load_bytes(xdp, coff, &l4ck, 2) == 0 && (a->proto == IPPROTO_TCP || l4ck != 0)) {
        /* the address is in the pseudo-header, the port in the L4 header */
        __wsum d = bpf_csum_diff((__be32 *) &opt, 2, (__be32 *) &npt, 2, dip);
        l4ck = nat_csum_apply(l4ck, d);
        bpf_xdp_store_bytes(xdp, coff, &l4ck, 2);
    }
    *oldip = oip;
    *oldport = opt;
    return 0;
}

/* DNAT: rewrite the destination (IPv4 + port) to imm = ip(low32) | port<<32 and
 * record the reply mapping. Per-packet, IPv4 TCP/UDP; no loop, so it is cheap. */
static __noinline void do_dnat(struct xdp_md *xdp, struct pfw_state *st, __u64 imm)
{
    __u32 proto = (__u32) st->r[R_PROTO];
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return;
    struct nat_rw a = {
        .l3 = (__u32) st->r[R_L3], .l4 = (__u32) st->r[R_L4], .proto = proto,
        .ip = bpf_htonl((__u32) imm), .port = bpf_htons((__u16) (imm >> 32)), .src = 0,
    };
    __u8 ver = 0;
    if (bpf_xdp_load_bytes(xdp, a.l3, &ver, 1) || (ver >> 4) != 4)
        return;                                      /* IPv4 only */
    /* The reply to this packet will come FROM the new destination TO this
     * packet's source: that tuple is the key the entry looks up. */
    struct nat_key k = { .saddr = a.ip, .sport = a.port, .proto = (__u8) proto };
    struct nat_val v = {};
    if (bpf_xdp_load_bytes(xdp, a.l3 + 12, &k.daddr, 4) || bpf_xdp_load_bytes(xdp, a.l4, &k.dport, 2))
        return;
    if (nat_rewrite(xdp, &a, &v.ip, &v.port))
        return;
    if (v.ip == a.ip && v.port == a.port)
        return;                                      /* already translated: nothing to undo */
    bpf_map_update_elem(&nat, &k, &v, BPF_ANY);
}

/* Reverse NAT: if this packet is a reply on a connection `dnat` diverted,
 * restore its source to the address the client dialled. Returns 1 if it was. */
static __noinline int nat_reverse(struct xdp_md *xdp, __u32 l3, __u32 l4, __u32 proto)
{
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return 0;
    struct nat_key k = { .proto = (__u8) proto };
    if (bpf_xdp_load_bytes(xdp, l3 + 12, &k.saddr, 4) || bpf_xdp_load_bytes(xdp, l3 + 16, &k.daddr, 4)
        || bpf_xdp_load_bytes(xdp, l4, &k.sport, 2) || bpf_xdp_load_bytes(xdp, l4 + 2, &k.dport, 2))
        return 0;
    struct nat_val *v = bpf_map_lookup_elem(&nat, &k);
    if (!v)
        return 0;
    struct nat_rw a = { .l3 = l3, .l4 = l4, .proto = proto, .ip = v->ip, .port = v->port, .src = 1 };
    __be32 oip; __be16 opt;
    if (nat_rewrite(xdp, &a, &oip, &opt))
        return 0;
    nat_reversed++;
    return 1;
}

#endif /* PFW_NAT_H */
