/* pfw: the Aho-Corasick automaton and the cursor byte-ops, as bpf_loop
 * callbacks over st->buf — scan (multi-pattern match into %m), findb, cmpstr,
 * skipb. The automaton is sparse in ac_goto/ac_fail/ac_accept; the kernel
 * follows the failure chain per byte. */
#ifndef PFW_SCAN_H
#define PFW_SCAN_H

#include "core/common.h"
#include "core/maps.h"
#include "io/read.h"

static __always_inline __u8 fold(__u8 b, __u32 nocase)
{
    if (nocase && b >= 'A' && b <= 'Z')
        b += 0x20;
    return b;
}

/* One byte: resolve goto(state, b) down the failure chain, then OR the
 * accept set in and remember where a newly seen pattern ended. */
static long ac_step(__u32 i, void *pctx)
{
    struct pfw_ctx *c = pctx;
    struct pfw_state *st = c->st;
    if (!st)
        return 1;
    if (i >= st->x_scan_len)
        return 1;
    __u8 b = fold(st->buf[PFW_MASK(i, SCAN_CAP)], st->nocase);
    struct pfw_prog *p = c->prog;
    if (!p)
        return 1;
    __u32 sbase = p->ac_base;
    __u32 s = st->ac_state & (AC_STATES - 1);
#pragma unroll
    for (int k = 0; k < AC_MAX_FAIL; k++) {
        __u32 gkey = (PFW_MASK(sbase + s, AC_POOL) << 8) | b;
        __u16 *next = bpf_map_lookup_elem(&ac_goto, &gkey);
        if (next && *next) {
            s = *next & (AC_STATES - 1);
            goto resolved;
        }
        if (s == 0)
            goto resolved;
        __u32 fkey = PFW_MASK(sbase + s, AC_POOL);
        __u16 *f = bpf_map_lookup_elem(&ac_fail, &fkey);
        s = f ? (*f & (AC_STATES - 1)) : 0;
    }
    s = 0;
resolved:
    st->ac_state = s;
    __u32 akey = PFW_MASK(sbase + s, AC_POOL);
    __u64 *acc = bpf_map_lookup_elem(&ac_accept, &akey);
    if (acc && *acc) {
        __u64 fresh = *acc & ~st->r[R_M];
        st->r[R_M] |= *acc;
        if (fresh) {
            /* Branchless: a conditional store per bit would hand the
             * verifier 64 branches to explore. */
            __u32 pos = st->x_scan_off + i + 1;
#pragma unroll
            for (int k = 0; k < PFW_MAX_PATS; k++) {
                __u32 m = 0u - (__u32) ((fresh >> k) & 1);
                st->mpos[k] = (st->mpos[k] & ~m) | (pos & m);
            }
        }
    }
    /* Same byte through each regex DFA in use (complete tables, no failure
     * links), ORing the matched regexes' bits into %m. Folded into the scan so
     * there is one bpf_loop, not two (a second nested loop blows the verifier
     * budget), and written out per group rather than looped for the same reason.
     * A program with no regex walks none. */
    __u32 ng = p->re_ngroups;
    __u32 rbase = p->re_base;
#define RE_WALK(g) \
    if (ng > (g)) { \
        __u32 rs = st->x_re[g] & (RE_STATES - 1); \
        __u32 rk = (PFW_MASK(rbase + rs, RE_POOL) << 8) + b; \
        __u16 *rn = bpf_map_lookup_elem(&re_goto, &rk); \
        rs = rn ? (*rn & (RE_STATES - 1)) : 0; \
        st->x_re[g] = rs; \
        __u32 rak = PFW_MASK(rbase + rs, RE_POOL); \
        __u64 *racc = bpf_map_lookup_elem(&re_accept, &rak); \
        if (racc && *racc) \
            st->r[R_M] |= *racc; \
    }
    RE_WALK(0) RE_WALK(1) RE_WALK(2) RE_WALK(3)
#undef RE_WALK
    _Static_assert(RE_GROUPS == 4, "ac_step walks exactly four regex DFAs");
    return 0;
}

static long findb_step(__u32 i, void *pctx)
{
    struct pfw_ctx *c = pctx;
    struct pfw_state *st = c->st;
    if (!st)
        return 1;
    if (i >= st->x_scan_len)
        return 1;
    if (st->buf[PFW_MASK(i, SCAN_CAP)] == (__u8) st->x_byte) {
        st->r[R_CUR] = st->x_scan_off + i;
        st->flags &= ~FL_FF;
        return 1;
    }
    return 0;
}

/* cmpstr: one byte of the pattern against the window. */
static long cmpstr_step(__u32 i, void *pctx)
{
    struct pfw_ctx *c = pctx;
    struct pfw_state *st = c->st;
    struct pfw_prog *p = c->prog;
    if (!st || !p)
        return 1;
    if (i >= st->x_scan_len)
        return 1;
    __u8 a = st->buf[PFW_MASK(i, SCAN_CAP)];
    __u8 b = p->pats[PFW_MASK(st->x_pat, PFW_MAX_PATS)].bytes[PFW_MASK(i, PFW_PAT_CAP)];
    if (fold(a, st->nocase) != fold(b, st->nocase)) {
        st->x_eq = 0;
        return 1;
    }
    return 0;
}

/* skipb: count the run of one byte. */
static long skipb_step(__u32 i, void *pctx)
{
    struct pfw_ctx *c = pctx;
    struct pfw_state *st = c->st;
    if (!st)
        return 1;
    if (i >= st->x_scan_len)
        return 1;
    if (st->buf[PFW_MASK(i, SCAN_CAP)] != (__u8) st->x_byte)
        return 1;
    st->x_count = i + 1;
    return 0;
}

#endif /* PFW_SCAN_H */
