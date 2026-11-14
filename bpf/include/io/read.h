/* pfw: reads from the active view — the execution ctx (struct pfw_ctx), a byte
 * window into st->buf (from the packet, or a flow's reassembled stream), and a
 * single bounded scalar load. The hot loops read st->buf[i] offset-free, which
 * keeps the verifier's state budget in check. */
#ifndef PFW_READ_H
#define PFW_READ_H

#include "core/common.h"
#include "core/maps.h"

struct pfw_ctx {
    struct xdp_md *xdp;
    struct pfw_state *st;
    struct pfw_prog *prog;
    __u32 nops;
    __u32 gen;
    __u32 mark;
    __u32 user_state; /* the flow's user state at entry */
    __u32 scan_off; /* frame offset of buf[0] during a scan */
    __u32 scan_len;
    __u32 byte;     /* findb / skipb: the byte wanted */
    __u32 pat;      /* cmpstr: the pattern index */
    __u32 eq;       /* cmpstr: still equal */
    __u32 count;    /* skipb: bytes skipped */
    __u32 reasm;    /* 1 = reads come from the flow's reassembled stream */
    struct flow *flow; /* the flow whose reasm buffer backs reads in reasm mode */
};

/* Copy a window of the flow's reassembled stream into st->buf, so the scan
 * callbacks read st->buf[i] exactly as they do for a packet window — the hot
 * loops stay offset-free, which keeps the verifier's state budget in check. */
struct reasm_win_ctx { struct flow *f; struct pfw_state *st; __u32 off; __u32 n; };
static long reasm_win_step(__u32 i, void *ctx_)
{
    struct reasm_win_ctx *c = ctx_;
    if (i >= c->n)
        return 1;
    c->st->buf[i & (SCAN_CAP - 1)] = c->f->reasm[(c->off + i) & (REASM_CAP - 1)];
    return 0;
}

/* Up to SCAN_CAP bytes at `off` into st->buf — from the packet, or (reasm
 * mode) from the flow's reassembled stream. Returns the bytes made available
 * (0 past the end); the size reaches the helper bounded to [1, SCAN_CAP]. */
static __always_inline __u32 window(struct pfw_ctx *c, __u64 off, __u32 want)
{
    __u64 end = c->st->r[R_END];
    if (off >= end || off > 0xffff)
        return 0;
    __u64 avail = end - off;
    if (want > avail)
        want = (__u32) avail;
    if (want > SCAN_CAP)
        want = SCAN_CAP;
    if (want == 0)
        return 0;
    barrier_var(want);
    want = ((want - 1) & (SCAN_CAP - 1)) + 1;
    if (c->reasm) {
        if (!c->flow)
            return 0;
        struct reasm_win_ctx wc = { .f = c->flow, .st = c->st, .off = (__u32) off, .n = want };
        bpf_loop(want, reasm_win_step, &wc, 0);
        return want;
    }
    if (bpf_xdp_load_bytes(c->xdp, (__u32) off, c->st->buf, want))
        return 0;
    return want;
}

/* One scalar, sizes 1/2/4/8. Returns 0 on a read past the end. */
static __always_inline int load(struct pfw_ctx *c, __u64 off, __u32 size, int be, __u64 *out)
{
    __u64 end = c->st->r[R_END];
    if (off > 0xffff || off + size > end)
        return 0;
    __u32 o = (__u32) off;
    /* Reassembly mode: scalars come from the flow's reassembled stream.
     * Loop-free (a variable-bound loop blows the verifier's state budget). */
    if (c->reasm) {
        if (!c->flow)
            return 0;
        __u8 *b = c->flow->reasm;
        __u32 m = REASM_CAP - 1;
        __u64 v = 0;
        switch (size) {
        case 1:
            *out = b[o & m];
            return 1;
        case 2:
            v = (__u64) b[o & m] | ((__u64) b[(o + 1) & m] << 8);
            *out = be ? __builtin_bswap16((__u16) v) : v;
            return 1;
        case 4:
            v = (__u64) b[o & m] | ((__u64) b[(o + 1) & m] << 8)
              | ((__u64) b[(o + 2) & m] << 16) | ((__u64) b[(o + 3) & m] << 24);
            *out = be ? __builtin_bswap32((__u32) v) : v;
            return 1;
        case 8:
            v = (__u64) b[o & m] | ((__u64) b[(o + 1) & m] << 8)
              | ((__u64) b[(o + 2) & m] << 16) | ((__u64) b[(o + 3) & m] << 24)
              | ((__u64) b[(o + 4) & m] << 32) | ((__u64) b[(o + 5) & m] << 40)
              | ((__u64) b[(o + 6) & m] << 48) | ((__u64) b[(o + 7) & m] << 56);
            *out = be ? __builtin_bswap64(v) : v;
            return 1;
        }
        return 0;
    }
    switch (size) {
    case 1: {
        __u8 v = 0;
        if (bpf_xdp_load_bytes(c->xdp, o, &v, 1))
            return 0;
        *out = v;
        return 1;
    }
    case 2: {
        __u16 v = 0;
        if (bpf_xdp_load_bytes(c->xdp, o, &v, 2))
            return 0;
        *out = be ? bpf_ntohs(v) : v;
        return 1;
    }
    case 4: {
        __u32 v = 0;
        if (bpf_xdp_load_bytes(c->xdp, o, &v, 4))
            return 0;
        *out = be ? bpf_ntohl(v) : v;
        return 1;
    }
    case 8: {
        __u64 v = 0;
        if (bpf_xdp_load_bytes(c->xdp, o, &v, 8))
            return 0;
        *out = be ? bpf_be64_to_cpu(v) : v;
        return 1;
    }
    }
    return 0;
}

#endif /* PFW_READ_H */
