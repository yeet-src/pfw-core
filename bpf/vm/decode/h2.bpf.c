/* pfw: the HTTP/2 (DECODE_H2) tail-call stages — frames, hpack, resolve.
 *
 * pfw_decode walks the frames at the front of the reassembled stream, gathers
 * the complete header blocks and consumes what it walked; pfw_hpack HPACK-decodes
 * them (Huffman included) into an intermediate; pfw_resolve expands that into
 * "name: value" lines in st->view, applying the dynamic table; then the matcher
 * runs over the view. Three stages because one combined machine exceeds the
 * verifier's budget. See decode/h2.h for the format and the failure policy.
 * Maps are extern (defined in core/maps.bpf.c); this unit references them.
 */
#include "core/common.h"
#include "core/maps.h"
#include "parse/parse.h"
#include "core/stage.h"
#include "io/reasm.h"
#include "decode/h2.h"

/* How the window compares to the client preface: 0 = it is not one, 1 = it is,
 * 2 = it could still become one (fewer than 24 bytes, all matching so far). */
static __noinline int h2_preface(struct flow *f, __u32 rlen)
{
    static const char pre[H2_PREFACE_LEN + 1] = H2_PREFACE;
#pragma unroll
    for (int k = 0; k < H2_PREFACE_LEN; k++) {
        if ((__u32) k >= rlen)
            return 2;
        if (f->reasm[k] != (__u8) pre[k])
            return 0;
    }
    return 1;
}

struct h2_raw { struct flow *f; struct pfw_state *st; __u32 n; };
static long h2_raw_step(__u32 i, void *x)
{
    struct h2_raw *c = x;
    if (i >= c->n)
        return 1;
    c->st->view[PFW_MASK(i, REASM_CAP)] = c->f->reasm[PFW_MASK(i, REASM_CAP)];
    return 0;
}

/* Frames stage. */
SEC("xdp")
int pfw_decode(struct xdp_md *ctx)
{
    PFW_STAGE_ENTER(ctx);
    if (!f)
        return XDP_PASS;
    __u32 rlen = PFW_CLAMP(f->reasm_len, REASM_CAP);
    PFW_SET_VIEW(st, 0);

    if (f->h2_mode == H2_MODE_UNKNOWN) {
        int m = h2_preface(f, rlen);
        if (m == 2)
            goto match;                        /* too short to tell: nothing to show yet */
        if (m == 1) {
            f->h2_mode = H2_MODE_H2;
            reasm_shift(f, H2_PREFACE_LEN);
            rlen -= H2_PREFACE_LEN;
        } else {
            f->h2_mode = H2_MODE_RAW;          /* not HTTP/2: match it as a plain stream */
            h2_raw++;
        }
    }
    if (f->h2_mode == H2_MODE_RAW) {
        struct h2_raw rc = { .f = f, .st = st, .n = rlen };
        if (rlen) bpf_loop(rlen, h2_raw_step, &rc, 0);
        PFW_SET_VIEW(st, rlen);
        goto match;
    }

    /* Bytes of a frame body being skipped that were buffered anyway. */
    if (f->h2_skip && rlen) {
        __u32 d = f->h2_skip < rlen ? f->h2_skip : rlen;
        reasm_shift(f, d);
        f->h2_skip -= d;
        rlen -= d;
    }

    __builtin_memset(&st->h2, 0, sizeof(st->h2));
    struct h2_fr fc = { .f = f, .st = st, .rlen = rlen };
    bpf_loop(H2_MAX_FRAMES, h2_frame_step, &fc, 0);
    if (st->h2.fail) {
        h2_failed++;
        return stage_reset(ctx, &p, f);
    }
    if (st->h2.skip)
        f->h2_skip = st->h2.skip;
    reasm_shift(f, st->h2.consumed);
    st->h2.hb_len = st->h2.hb_done;            /* an unfinished block waits in the window */
    if (st->h2.hb_len == 0 && st->h2.rst == 0)
        goto match;
    bpf_tail_call(ctx, &decode_jmp, SLOT_HPACK);
    return XDP_PASS;   /* slot empty: pass (host populates it before attaching) */
match:
    bpf_tail_call(ctx, &decode_jmp, SLOT_MATCH);
    return XDP_PASS;
}

/* HPACK stage: st->h2a (the header block) -> st->h2b (the intermediate). */
SEC("xdp")
int pfw_hpack(struct xdp_md *ctx)
{
    PFW_STAGE_ENTER(ctx);
    if (!f)
        return XDP_PASS;
    struct h2_work *w = &st->h2;
    __u32 n = PFW_CLAMP(w->hb_len, REASM_CAP);
    struct h2_hp hc = { .st = st, .n = n };
    if (n) bpf_loop(n, h2_hpack_step, &hc, 0);
    if (w->fail || w->phase != HP_FIELD) {     /* malformed, or the block ended mid-field */
        h2_failed++;
        return stage_reset(ctx, &p, f);
    }
    bpf_tail_call(ctx, &decode_jmp, SLOT_RESOLVE);
    return XDP_PASS;
}

/* Resolve stage: st->h2b -> "name: value" lines in st->view, plus the dynamic
 * table's insertions; then the matcher. */
SEC("xdp")
int pfw_resolve(struct xdp_md *ctx)
{
    PFW_STAGE_ENTER(ctx);
    if (!f)
        return XDP_PASS;
    struct h2_work *w = &st->h2;
    struct h2conn *hc = bpf_map_lookup_elem(&h2conns, &key);
    if (!hc) {
        bpf_map_update_elem(&h2conns, &key, (void *) &zero_h2conn, BPF_NOEXIST);
        hc = bpf_map_lookup_elem(&h2conns, &key);
    }
    if (!hc) {
        h2_failed++;
        return stage_reset(ctx, &p, f);
    }
    if (f->h2_new) {                           /* a new connection starts with an empty table */
        hc->head = 0; hc->count = 0; hc->ins = 0;
        f->h2_new = 0; f->h2_ins = 0;
    } else if (hc->ins != f->h2_ins) {         /* the table was evicted under a live connection */
        h2_failed++;
        return stage_reset(ctx, &p, f);
    }

    __u32 n = PFW_CLAMP(w->out, H2_CAP);
    struct h2_rs rc = { .st = st, .hc = hc, .n = n };
    if (n) bpf_loop(n, h2_resolve_step, &rc, 0);
    f->h2_ins = hc->ins;

    __u32 marks = PFW_CLAMP(w->rst, H2_RST_LINES);
    struct rs_mark mk = { .st = st };
    if (marks) bpf_loop(marks * 32, rs_mark_step, &mk, 0);

    __u32 len = PFW_CLAMP(w->text, REASM_CAP);
    PFW_SET_VIEW(st, len);
    bpf_tail_call(ctx, &decode_jmp, SLOT_MATCH);
    return XDP_PASS;
}
