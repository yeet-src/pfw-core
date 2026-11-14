/* pfw: TCP reassembly (reasm-mode programs) — place each segment at its sequence
 * offset into the flow buffer (first-wins on overlap, the Linux policy) and
 * advance the contiguous prefix the program inspects. A SYN re-anchors; a flow
 * first seen mid-stream, or a segment past the buffer, fails closed. */
#ifndef PFW_REASM_H
#define PFW_REASM_H

#include "core/common.h"
#include "core/maps.h"

/* Place one byte of a segment into the flow buffer at its sequence offset,
 * first-wins on overlap (the Linux policy — already-received bytes are kept,
 * which is what keeps an overlapping-rewrite evasion from working). Indices
 * are masked; the caller proved off + n <= REASM_CAP so no mask ever wraps. */
struct reasm_place_ctx { struct flow *f; struct pfw_state *st; __u32 off; __u32 n; };
static long reasm_place_step(__u32 i, void *ctx_)
{
    struct reasm_place_ctx *c = ctx_;
    if (i >= c->n)
        return 1;
    __u32 pos = (c->off + i) & (REASM_CAP - 1);
    __u32 bidx = (pos >> 3) & (REASM_CAP / 8 - 1);
    __u8 bit = (__u8) (1u << (pos & 7));
    if (!(c->f->filled[bidx] & bit)) {
        c->f->reasm[pos] = c->st->buf[i & (SCAN_CAP - 1)];
        c->f->filled[bidx] |= bit;
    }
    return 0;
}

/* Advance the contiguous prefix (reasm_len) over bytes that are now filled.
 * The flow pointer is wrapped in a stack struct: bpf_loop's context arg must
 * be a frame pointer, not a map value. */
struct reasm_adv_ctx { struct flow *f; };
static long reasm_advance_step(__u32 i, void *ctx_)
{
    struct reasm_adv_ctx *c = ctx_;
    struct flow *f = c->f;
    __u32 pos = f->reasm_len;
    (void) i;
    if (pos >= REASM_CAP)
        return 1;
    __u32 bidx = (pos >> 3) & (REASM_CAP / 8 - 1);
    if (f->filled[bidx] & (__u8) (1u << (pos & 7))) { f->reasm_len = pos + 1; return 0; }
    return 1;
}

/* Place one TCP segment at its sequence offset and run the program over the
 * contiguous prefix. Returns 0 = inspect f->reasm[0, reasm_len), 1 = fail
 * closed (reset). A SYN re-anchors; a flow first seen mid-stream or a segment
 * past the buffer fails closed. Reordered and overlapping segments are placed,
 * not dropped — so a reordered-but-legit flow is delivered whole, while the
 * contiguous prefix the program sees matches what the server reassembles. */
static __always_inline int reasm_feed(struct xdp_md *ctx, struct pkt *p, struct flow *f, struct pfw_state *st)
{
    __u8 syn = p->tcp_flags & 0x02;
    __u8 rstfin = p->tcp_flags & 0x05; /* RST | FIN */
    if (rstfin) { f->reasm_len = 0; return 0; }
    if (syn) {
        /* SYN or SYN-ACK: the start of this direction's stream. */
        f->reasm_len = 0;
        f->reasm_total = 0;
        f->reasm_base = p->seq + 1;   /* SYN consumes one sequence number */
        f->synned = 1;
        __builtin_memset(f->filled, 0, sizeof(f->filled));
        return 0;                      /* a SYN carries no payload */
    }
    __u32 seglen = p->end > p->payload ? p->end - p->payload : 0;
    if (seglen == 0)
        return 0;                      /* pure ACK: nothing to add */
    if (!f->synned && f->reasm_total == 0) { reasm_midjoin++; return 1; } /* joined mid-stream */

    __s32 o = (__s32) (p->seq - f->reasm_base);
    __u32 skip = 0;
    if (o < 0) {
        __u32 before = (__u32) (-o);
        if (before >= seglen) { reasm_retrans++; return 0; } /* entirely before base: old */
        skip = before;
        o = 0;
    }
    __u32 off = (__u32) o;
    __u32 n = seglen - skip;
    if (off >= REASM_CAP || n > REASM_CAP - off) { reasm_over++; return 1; } /* past the buffer */
    if (n == 0 || n > SCAN_CAP)
        return 1;
    barrier_var(n);
    n = ((n - 1) & (SCAN_CAP - 1)) + 1;    /* n in [1, SCAN_CAP] for the load's const-size */
    if (bpf_xdp_load_bytes(ctx, p->payload + skip, st->buf, n))
        return 1;
    struct reasm_place_ctx pc = { .f = f, .st = st, .off = off, .n = n };
    bpf_loop(n, reasm_place_step, &pc, 0);
    struct reasm_adv_ctx vc = { .f = f };
    bpf_loop(REASM_CAP, reasm_advance_step, &vc, 0);
    f->reasm_total += n;
    return 0;
}

#endif /* PFW_REASM_H */
