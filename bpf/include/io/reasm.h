/* pfw: TCP reassembly (reasm-mode programs).
 *
 * Each segment is placed at its sequence offset in a REASM_CAP-byte window over
 * the stream, first-wins on overlap (the Linux policy — already-received bytes
 * are kept, which is what defeats an overlapping-rewrite evasion), and the
 * program inspects the contiguous prefix [0, reasm_len).
 *
 * The window SLIDES. When the next in-order segment does not fit, the window is
 * shifted forward to make room, keeping the last REASM_KEEP bytes so a pattern
 * that straddles the edge is still seen whole. A connection is therefore
 * followed for its whole life — a keep-alive connection or an upload is not cut
 * off after REASM_CAP bytes — and every byte delivered to the server has been in
 * a window the program saw.
 *
 * What cannot be placed is never let through un-inspected:
 *   - an out-of-order segment beyond the window is DROPPED (not reset): the
 *     sender retransmits it, by which time the window has moved;
 *   - a flow first seen mid-stream fails closed (reset), as before.
 * The one exception is a single segment larger than the window (a jumbo frame,
 * or loopback, where one segment can be 64 kB): its first REASM_CAP bytes are
 * inspected, the rest is counted in reasm_trunc — the same reach a per-packet
 * scan has.
 *
 * `decode h2` connections do not slide here: the h2 stage consumes whole frames
 * from the front of the window itself (reasm_shift), and a header block that
 * cannot fit the window fails closed.
 */
#ifndef PFW_REASM_H
#define PFW_REASM_H

#include "core/common.h"
#include "core/maps.h"

#define REASM_OK    0  /* inspect f->reasm[0, reasm_len) */
#define REASM_RESET 1  /* fail closed: reset the connection */
#define REASM_HOLD  2  /* drop this segment; the sender will retransmit it */

/* Place one byte of a segment into the flow buffer at its sequence offset,
 * first-wins on overlap. Indices are masked; the caller proved off + n <=
 * REASM_CAP so no mask ever wraps. */
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
        c->f->reasm[pos] = c->st->buf[PFW_MASK(i, SCAN_CAP)];
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

/* Slide the window forward by `by` bytes: byte i takes the value (and the fill
 * bit) of byte i + by, and the vacated tail is marked empty. Out-of-order bytes
 * already buffered beyond the prefix move with it, so nothing that was passed
 * to the server is forgotten. Moving left in place is safe: every read is ahead
 * of every write. */
struct reasm_shift_ctx { struct flow *f; __u32 by; };
static long reasm_shift_step(__u32 i, void *ctx_)
{
    struct reasm_shift_ctx *c = ctx_;
    struct flow *f = c->f;
    if (i >= REASM_CAP)
        return 1;
    __u32 src = i + c->by;
    __u32 di = (i >> 3) & (REASM_CAP / 8 - 1);
    __u8 dbit = (__u8) (1u << (i & 7));
    if (src < REASM_CAP) {
        __u32 si = (src >> 3) & (REASM_CAP / 8 - 1);
        if (f->filled[si] & (__u8) (1u << (src & 7))) {
            f->reasm[i & (REASM_CAP - 1)] = f->reasm[src & (REASM_CAP - 1)];
            f->filled[di] |= dbit;
            return 0;
        }
    }
    f->filled[di] &= (__u8) ~dbit;
    return 0;
}

/* __noinline: one copy, and its loop state stays out of the caller's frame. */
static __noinline void reasm_shift(struct flow *f, __u32 by)
{
    if (by == 0)
        return;
    if (by > REASM_CAP)
        by = REASM_CAP;
    struct reasm_shift_ctx sc = { .f = f, .by = by };
    bpf_loop(REASM_CAP, reasm_shift_step, &sc, 0);
    f->reasm_base += by;
    f->reasm_len = f->reasm_len > by ? f->reasm_len - by : 0;
}

/* Feed one TCP segment. `h2` is 1 for a `decode h2` program. Returns REASM_*.
 * __noinline so every path through it rejoins the caller in one state: the
 * interpreter loop that follows is verified once per distinct caller state. */
/* `follow` says how the stream is to be followed: REASM_H2 for an h2 decode,
 * which needs every header block whole, and REASM_FROM_START for any decode,
 * which keeps state from the connection's first byte and so cannot pick a
 * stream up part-way. */
#define REASM_H2         1u
#define REASM_FROM_START 2u
static __noinline int reasm_feed(struct xdp_md *ctx, struct pkt *p, struct flow *f, struct pfw_state *st, __u32 follow)
{
    __u32 h2 = follow & REASM_H2;
    __u8 syn = p->tcp_flags & 0x02;
    if (p->tcp_flags & 0x04) { f->reasm_len = 0; return REASM_OK; } /* RST: nothing more to see */
    if (syn) {
        /* SYN or SYN-ACK: the start of this direction's stream. */
        f->reasm_len = 0;
        f->reasm_total = 0;
        f->reasm_base = p->seq + 1;   /* SYN consumes one sequence number */
        f->synned = 1;
        f->reasm_resync = 0;
        f->h2_mode = H2_MODE_UNKNOWN;
        f->h2_skip = 0;
        f->h2_ins = 0;
        f->h2_new = 1;
        __builtin_memset(f->filled, 0, sizeof(f->filled));
        return REASM_OK;               /* a SYN carries no payload */
    }
    /* A FIN segment may carry data, and it is inspected like any other. */
    __u32 seglen = p->end > p->payload ? p->end - p->payload : 0;
    if (seglen == 0)
        return REASM_OK;               /* pure ACK: nothing to add */
    if (!f->synned && f->reasm_total == 0) {
        /* A connection whose start was not seen: it was open before the program
         * was, or its flow fell out of the table. A program that only matches
         * the stream follows it from this segment on — resetting it would cut
         * off every connection open when a first policy loads, and the sender
         * cannot have hidden the start to gain anything: the VM sees every
         * packet that arrives. A decode cannot begin part-way, and resets. */
        reasm_midjoin++;
        if (follow & REASM_FROM_START)
            return REASM_RESET;
        f->reasm_len = 0;
        f->reasm_base = p->seq;
        f->synned = 1;
        f->reasm_resync = 0;
        __builtin_memset(f->filled, 0, sizeof(f->filled));
    }

    /* The previous segment overran the window: the stream resumes past it. */
    if (f->reasm_resync) {
        f->reasm_resync = 0;
        f->reasm_base = f->reasm_resync_seq;
        f->reasm_len = 0;
        __builtin_memset(f->filled, 0, sizeof(f->filled));
    }

    __s32 o = (__s32) (p->seq - f->reasm_base);
    __u32 skip = 0;
    if (o < 0) {
        __u32 before = (__u32) (-o);
        if (before >= seglen) { reasm_retrans++; return REASM_OK; } /* entirely before base: old */
        skip = before;
        o = 0;
    }
    __u32 off = (__u32) o;
    __u32 n = seglen - skip;
    __u32 len = f->reasm_len;
    if (len > REASM_CAP)
        len = REASM_CAP;

    /* decode h2, inside a frame body being skipped (a DATA frame): the bytes are
     * not buffered at all, the window just moves past them. */
    if (h2 && f->h2_mode == H2_MODE_H2 && f->h2_skip && len == 0 && off == 0) {
        __u32 d = f->h2_skip < n ? f->h2_skip : n;
        f->h2_skip -= d;
        f->reasm_base += d;
        f->reasm_total += d;
        skip += d;
        n -= d;
        if (n == 0)
            return REASM_OK;
    }

    if (off > len && (off >= REASM_CAP || n > REASM_CAP - off)) {
        /* Out of order and beyond the window: hold it back. */
        reasm_held++;
        return REASM_HOLD;
    }
    if (off <= len && n > REASM_CAP - off) {
        /* In order (or overlapping the prefix) and it does not fit. */
        __u32 had = len - off;                  /* leading bytes already in the prefix */
        if (had >= n) { reasm_retrans++; return REASM_OK; }
        skip += had;
        n -= had;
        if (h2 && f->h2_mode != H2_MODE_RAW) { reasm_over++; return REASM_RESET; } /* a header block larger than the window */
        if (n > REASM_CAP) {
            /* One segment larger than the whole window: inspect its head. */
            reasm_trunc++;
            f->reasm_resync = 1;
            f->reasm_resync_seq = f->reasm_base + len + n;
            n = REASM_CAP;
        }
        __u32 keep = REASM_CAP - n;
        if (keep > REASM_KEEP) keep = REASM_KEEP;
        if (keep > len) keep = len;
        reasm_shift(f, len - keep);
        reasm_slid++;
        off = keep;
    }
    if (off >= REASM_CAP || n == 0 || n > REASM_CAP - off || n > SCAN_CAP)
        return REASM_RESET;
    barrier_var(n);
    n = ((n - 1) & (SCAN_CAP - 1)) + 1;    /* n in [1, SCAN_CAP] for the load's const-size */
    if (bpf_xdp_load_bytes(ctx, p->payload + skip, st->buf, n))
        return REASM_RESET;
    struct reasm_place_ctx pc = { .f = f, .st = st, .off = off, .n = n };
    bpf_loop(n, reasm_place_step, &pc, 0);
    struct reasm_adv_ctx vc = { .f = f };
    bpf_loop(REASM_CAP, reasm_advance_step, &vc, 0);
    f->reasm_total += n;
    return REASM_OK;
}

#endif /* PFW_REASM_H */
