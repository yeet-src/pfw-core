/* pfw: packet rewrite, applied by the pfw_rewrite tail-call stage.
 *
 * OP_REDACT/OP_REPLACE only RECORD a request (pattern, mode, cursor) in st->rw[];
 * the work runs here, in a program with its own verifier budget. Matching uses
 * the Aho-Corasick automaton the same way the scan does — ONE byte per bpf_loop
 * callback, following the failure chain — so there is no per-position unrolled
 * compare to explode the verifier's state budget. When the target pattern accepts
 * at position i, a bounded nested bpf_loop overwrites the matched span
 * [i+1-len, i] in place (fill byte for redact, replacement pattern for replace)
 * and accumulates the L4 checksum delta. Non-reasm only.
 */
#ifndef PFW_REWRITE_H
#define PFW_REWRITE_H

#include "core/common.h"
#include "core/maps.h"
#include "io/read.h"
#include "match/scan.h"   /* fold() */

struct rw_ac_ctx { struct pfw_state *st; struct pfw_prog *p;
                   __u32 pat, len, mode, repl, fill, n, woff, l4, acstate, sumo, sumn, changed; };

/* Overwrite one byte of a matched span and fold its old/new 16-bit checksum
 * contribution (placed high/low by the byte's parity within the L4 segment). */
struct fill_ctx { struct rw_ac_ctx *rc; __u32 base; };
static long fill_step(__u32 j, void *ctx_)
{
    struct fill_ctx *fc = ctx_;
    struct rw_ac_ctx *c = fc->rc;
    if (j >= c->len)
        return 1;
    __u32 idx = PFW_MASK(fc->base + j, SCAN_CAP);
    __u8 ob = c->st->buf[idx];
    __u8 nb = c->mode ? c->p->pats[PFW_MASK(c->repl, PFW_MAX_PATS)].bytes[PFW_MASK(j, PFW_PAT_CAP)]
                      : (__u8) c->fill;
    __u32 so = (c->woff + fc->base + j) - c->l4;        /* offset in the L4 segment */
    __u32 odd = so & 1;
    c->sumo += odd ? ob : ((__u32) ob << 8);
    c->sumn += odd ? nb : ((__u32) nb << 8);
    c->st->buf[idx] = nb;
    return 0;
}

/* One window byte through the automaton; on an accept of the target pattern,
 * overwrite the span that just ended. Mirrors ac_step's goto/fail resolution. */
static long rw_ac_step(__u32 i, void *ctx_)
{
    struct rw_ac_ctx *c = ctx_;
    struct pfw_state *st = c->st;
    if (!st || i >= c->n)
        return 1;
    __u8 b = fold(st->buf[PFW_MASK(i, SCAN_CAP)], st->nocase);
    if (!c->p)
        return 1;
    __u32 sbase = c->p->ac_base;
    __u32 s = c->acstate & (AC_STATES - 1);
#pragma unroll
    for (int k = 0; k < AC_MAX_FAIL; k++) {
        __u32 gkey = (PFW_MASK(sbase + s, AC_POOL) << 8) | b;
        __u16 *next = bpf_map_lookup_elem(&ac_goto, &gkey);
        if (next && *next) { s = *next & (AC_STATES - 1); goto resolved; }
        if (s == 0) goto resolved;
        __u32 fkey = PFW_MASK(sbase + s, AC_POOL);
        __u16 *f = bpf_map_lookup_elem(&ac_fail, &fkey);
        s = f ? (*f & (AC_STATES - 1)) : 0;
    }
    s = 0;
resolved:
    c->acstate = s;
    __u32 akey = PFW_MASK(sbase + s, AC_POOL);
    __u64 *acc = bpf_map_lookup_elem(&ac_accept, &akey);
    if (acc && ((*acc >> c->pat) & 1)) {
        __u32 base = (i + 1 >= c->len) ? (i + 1 - c->len) : 0;
        struct fill_ctx fc = { .rc = c, .base = base };
        bpf_loop(c->len, fill_step, &fc, 0);
        c->changed = 1;
    }
    return 0;
}

/* Like rw_ac_step, but matches with the regex DFA (re_goto/re_accept) instead of
 * the literal automaton. Only fixed-length regexes reach here (the compiler
 * rejects variable-length ones for rewrite), so an accept at i ends a span of a
 * known length c->len — the same [i+1-len, i] overwrite as the literal path.
 * c->pat is the regex accept-bit; c->acstate carries the DFA state. */
static long rw_re_step(__u32 i, void *ctx_)
{
    struct rw_ac_ctx *c = ctx_;
    struct pfw_state *st = c->st;
    if (!st || i >= c->n)
        return 1;
    __u8 b = st->buf[PFW_MASK(i, SCAN_CAP)]; /* as it is: a regex has its own case, built in */
    if (!c->p)
        return 1;
    __u32 rbase = c->p->re_base;
    __u32 rs = c->acstate & (RE_STATES - 1);
    __u32 rk = (PFW_MASK(rbase + rs, RE_POOL) << 8) + b;
    __u16 *rn = bpf_map_lookup_elem(&re_goto, &rk);
    rs = rn ? (*rn & (RE_STATES - 1)) : 0;
    c->acstate = rs;
    __u32 rak = PFW_MASK(rbase + rs, RE_POOL);
    __u64 *racc = bpf_map_lookup_elem(&re_accept, &rak);
    if (racc && ((*racc >> c->pat) & 1)) {
        __u32 base = (i + 1 >= c->len) ? (i + 1 - c->len) : 0;
        struct fill_ctx fc = { .rc = c, .base = base };
        bpf_loop(c->len, fill_step, &fc, 0);
        c->changed = 1;
    }
    return 0;
}

/* Apply one recorded rewrite request: scan its window through the automaton,
 * overwrite each match, write the window back, fold the checksum delta. */
static __noinline void do_rewrite(struct xdp_md *ctx, struct pfw_state *st, struct pfw_prog *p, __u32 ri)
{
    __u32 k = ri & (RW_MAX - 1);
    __u32 is_re = st->rw[k].is_re;
    __u32 pat = st->rw[k].pat & (PFW_MAX_PATS - 1);
    __u32 len = is_re ? st->rw[k].rlen : p->pats[pat].len; /* regex: compiler-fixed length */
    if (len == 0 || len > PFW_PAT_CAP)
        return;
    __u32 woff = st->rw[k].woff;
    struct pfw_ctx wc = { .xdp = ctx, .st = st, .prog = p, .reasm = 0, .fp = 0 };
    __u32 wn = window(&wc, woff, SCAN_CAP);            /* bytes [woff, end) -> st->buf */
    if (!wn)
        return;
    struct rw_ac_ctx c = {
        .st = st, .p = p, .pat = pat, .len = len,
        .mode = st->rw[k].mode, .repl = st->rw[k].repl & (PFW_MAX_PATS - 1),
        .fill = st->rw[k].fill, .n = wn, .woff = woff, .l4 = (__u32) st->r[R_L4],
        .acstate = is_re ? p->re_pat_start[pat] : 0, .sumo = 0, .sumn = 0, .changed = 0,
    };
    if (is_re)
        bpf_loop(wn, rw_re_step, &c, 0);
    else
        bpf_loop(wn, rw_ac_step, &c, 0);
    if (!c.changed)
        return;
    __u32 n2 = wn;
    barrier_var(n2);
    n2 = ((n2 - 1) & (SCAN_CAP - 1)) + 1;             /* [1, SCAN_CAP] for the store */
    bpf_xdp_store_bytes(ctx, woff, st->buf, n2);
    /* RFC 1624: new_total = old_total - sum_old + sum_new, folded into the csum. */
    __u32 proto = (__u32) st->r[R_PROTO];
    __u32 coff = proto == IPPROTO_TCP ? (__u32) st->r[R_L4] + 16
               : proto == IPPROTO_UDP ? (__u32) st->r[R_L4] + 6 : 0;
    if (!coff)
        return;
    __u16 chk = 0;
    if (bpf_xdp_load_bytes(ctx, coff, &chk, 2) != 0 || (proto == IPPROTO_UDP && chk == 0))
        return;
    __u32 so = c.sumo, sn = c.sumn;
    so = (so & 0xffff) + (so >> 16); so = (so & 0xffff) + (so >> 16);
    sn = (sn & 0xffff) + (sn >> 16); sn = (sn & 0xffff) + (sn >> 16);
    __u32 sum = (__u32) (__u16) ~chk;
    sum += sn + ((~so) & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    chk = (__u16) ~sum;
    bpf_xdp_store_bytes(ctx, coff, &chk, 2);
}

#endif /* PFW_REWRITE_H */
