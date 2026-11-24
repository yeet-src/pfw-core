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

static __always_inline __u16 nat_csum_apply(__u16 ck, __wsum diff)
{
    __u32 s = (__u16) ~ck;
    s += diff;
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    return (__u16) ~s;
}

/* Rewrite the endpoint st->x_nat.a asks for, in place. What was there is left
 * in x_nat.oip / x_nat.opt (do_dnat needs it to record the mapping). Returns 0
 * on success. */
static __noinline int nat_rewrite(struct xdp_md *xdp, struct pfw_state *st)
{
    /* Everything here is in the per-CPU state (st->x_nat), the request and the
     * working values alike. This function ends the deepest chain of calls in
     * the VM — entry, interpreter step, do_dnat, here — and the verifier adds
     * their frames up, each rounded up to 32 bytes on kernels before 6.8,
     * against 512. Kept on the stack, these took the chain to 544. */
    struct nat_scratch *n = &st->x_nat;
    struct nat_rw *a = &n->a;
    __u32 ipoff = a->l3 + (a->src ? 12 : 16);
    __u32 ptoff = a->l4 + (a->src ? 0 : 2);
    n->oip = 0; n->nip = a->ip;
    n->opt = 0; n->npt = a->port;
    if (bpf_xdp_load_bytes(xdp, ipoff, &n->oip, 4) || bpf_xdp_load_bytes(xdp, ptoff, &n->opt, 2))
        return -1;
    bpf_xdp_store_bytes(xdp, ipoff, &n->nip, 4);
    bpf_xdp_store_bytes(xdp, ptoff, &n->npt, 2);
    __wsum dip = bpf_csum_diff(&n->oip, 4, &n->nip, 4, 0);
    n->ck = 0;                                           /* IP header checksum */
    if (bpf_xdp_load_bytes(xdp, a->l3 + 10, &n->ck, 2) == 0) {
        n->ck = nat_csum_apply(n->ck, dip);
        bpf_xdp_store_bytes(xdp, a->l3 + 10, &n->ck, 2);
    }
    __u32 coff = a->proto == IPPROTO_TCP ? a->l4 + 16 : a->l4 + 6; /* L4 checksum */
    n->ck = 0;
    if (bpf_xdp_load_bytes(xdp, coff, &n->ck, 2) == 0 && (a->proto == IPPROTO_TCP || n->ck != 0)) {
        /* the address is in the pseudo-header, the port in the L4 header */
        n->o32 = n->opt; n->n32 = n->npt;
        __wsum d = bpf_csum_diff(&n->o32, 4, &n->n32, 4, dip);
        n->ck = nat_csum_apply(n->ck, d);
        bpf_xdp_store_bytes(xdp, coff, &n->ck, 2);
    }
    return 0;
}


/* DNAT: rewrite the destination (IPv4 + port) to imm = ip(low32) | port<<32 and
 * record the reply mapping. Per-packet, IPv4 TCP/UDP; no loop, so it is cheap. */
static __noinline void do_dnat(struct xdp_md *xdp, struct pfw_state *st, __u64 imm)
{
    __u32 proto = (__u32) st->r[R_PROTO];
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return;
    struct nat_scratch *n = &st->x_nat;
    n->a.l3 = (__u32) st->r[R_L3];
    n->a.l4 = (__u32) st->r[R_L4];
    n->a.proto = proto;
    n->a.ip = bpf_htonl((__u32) imm);
    n->a.port = bpf_htons((__u16) (imm >> 32));
    n->a.src = 0;
    n->ver = 0;
    if (bpf_xdp_load_bytes(xdp, n->a.l3, &n->ver, 1) || (n->ver >> 4) != 4)
        return;                                      /* IPv4 only */
    /* The reply to this packet will come FROM the new destination TO this
     * packet's source: that tuple is the key the entry looks up. */
    __builtin_memset(&n->k, 0, sizeof(n->k));
    n->k.saddr = n->a.ip;
    n->k.sport = n->a.port;
    n->k.proto = (__u8) proto;
    if (bpf_xdp_load_bytes(xdp, n->a.l3 + 12, &n->k.daddr, 4) || bpf_xdp_load_bytes(xdp, n->a.l4, &n->k.dport, 2))
        return;
    if (nat_rewrite(xdp, st))
        return;
    if (n->oip == n->a.ip && n->opt == n->a.port)
        return;                                      /* already translated: nothing to undo */
    __builtin_memset(&n->v, 0, sizeof(n->v));
    n->v.ip = n->oip;
    n->v.port = n->opt;
    bpf_map_update_elem(&nat, &n->k, &n->v, BPF_ANY);
}

static __noinline int nat_reverse(struct xdp_md *xdp, struct pfw_state *st, __u32 l3, __u32 l4, __u32 proto)
{
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return 0;
    struct nat_scratch *n = &st->x_nat;
    __builtin_memset(&n->k, 0, sizeof(n->k));
    n->k.proto = (__u8) proto;
    if (bpf_xdp_load_bytes(xdp, l3 + 12, &n->k.saddr, 4) || bpf_xdp_load_bytes(xdp, l3 + 16, &n->k.daddr, 4)
        || bpf_xdp_load_bytes(xdp, l4, &n->k.sport, 2) || bpf_xdp_load_bytes(xdp, l4 + 2, &n->k.dport, 2))
        return 0;
    struct nat_val *v = bpf_map_lookup_elem(&nat, &n->k);
    if (!v)
        return 0;
    n->a.l3 = l3;
    n->a.l4 = l4;
    n->a.proto = proto;
    n->a.ip = v->ip;
    n->a.port = v->port;
    n->a.src = 1;
    if (nat_rewrite(xdp, st))
        return 0;
    nat_reversed++;
    return 1;
}

#endif /* PFW_NAT_H */
