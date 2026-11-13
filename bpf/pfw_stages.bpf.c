/* pfw: the tail-call decode stages, a separate compile unit from the entry.
 *
 * These SEC("xdp") programs are their own translation unit; `bpftool gen object`
 * statically links this with pfw.bpf.c into one bin/app.bpf.o. The maps and
 * counter globals are DEFINED in pfw.bpf.c (PFW_MAPS_DEFINE); here they are
 * `extern` (pfw_maps.h emits them that way when PFW_MAPS_DEFINE is unset) and the
 * BPF linker resolves them to the single definition. No LICENSE here — pfw.bpf.c
 * carries the one.
 *
 * The machinery is still the shared static-inline headers, so each stage inlines
 * exactly as before; only the program bodies moved to their own object.
 */
#include "pfw_common.h"
#include "pfw_maps.h"      /* extern: resolved against pfw.bpf.c's definitions */
#include "pfw_parse.h"
#include "pfw_read.h"
#include "pfw_scan.h"
#include "pfw_transform.h"
#include "pfw_interp.h"
#include "pfw_rst.h"
#include "pfw_event.h"
#include "pfw_h2.h"
#include "pfw_stage.h"

/* Decoder stage: HPACK-decode the reassembled h2 stream into st->dec (the
 * resolve stage expands it), then tail-call resolve. */
SEC("xdp")
int pfw_decode(struct xdp_md *ctx)
{
    PFW_STAGE_ENTER(ctx);
    if (f && h2_decode(f, st, f->reasm_len))
        return stage_reset(ctx, &p, f);
    bpf_tail_call(ctx, &decode_jmp, SLOT_RESOLVE);
    return XDP_PASS;   /* slot empty: pass (host populates it before attaching) */
}

/* Resolve stage: expand the HPACK intermediate in st->dec into "name: value"
 * lines in the flow buffer, then tail-call the matcher. */
SEC("xdp")
int pfw_resolve(struct xdp_md *ctx)
{
    PFW_STAGE_ENTER(ctx);
    if (f) {
        __u32 il = st->dec_len > REASM_CAP ? REASM_CAP : st->dec_len;
        struct h2_rs rs = { .f = f, .st = st, .len = il, .phase = 0 };
        bpf_loop(il, h2_resolve_step, &rs, 0);
        __u32 fl = rs.outpos > REASM_CAP ? REASM_CAP : rs.outpos;
        f->reasm_len = fl;
        st->r[R_PAYLOAD] = 0; st->r[R_CUR] = 0; st->r[R_END] = fl; st->r[R_LEN] = fl;
    }
    bpf_tail_call(ctx, &decode_jmp, SLOT_MATCH);
    return XDP_PASS;
}

/* Huffman decode stage (DECODE_HUFFMAN): HPACK-Huffman-decode the reassembled
 * stream through the baked table (built from RFC 7541 by src/huffman.js), then
 * tail-call the matcher. Invalid input fails closed, like the h2 decoder. */
SEC("xdp")
int pfw_huff(struct xdp_md *ctx)
{
    PFW_STAGE_ENTER(ctx);
    if (f) {
        __u32 inlen = f->reasm_len > REASM_CAP ? REASM_CAP : f->reasm_len;
        /* Decode f->reasm into st->dec... */
        st->huff_state = 0; st->huff_outpos = 0; st->huff_fail = 0;
        struct tf_ctx tc = { .f = f, .st = st, .n = inlen };
        if (inlen) bpf_loop(inlen, tf_step, &tc, 0);
        if (st->huff_fail)
            return stage_reset(ctx, &p, f);
        /* ...then copy the decoded bytes back into the flow buffer the matcher
         * reads. (Separate buffers: output runs ahead of input.) */
        __u32 ol = st->huff_outpos > REASM_CAP ? REASM_CAP : st->huff_outpos;
        struct cp_ctx cp = { .f = f, .st = st, .n = ol };
        if (ol) bpf_loop(ol, cp_step, &cp, 0);
        f->reasm_len = ol;
        st->r[R_PAYLOAD] = 0; st->r[R_CUR] = 0; st->r[R_END] = ol; st->r[R_LEN] = ol;
    }
    bpf_tail_call(ctx, &decode_jmp, SLOT_MATCH);
    return XDP_PASS;
}

/* General transform stage (DECODE_TRANSFORM): decode the reassembled stream
 * through a HOST-LOADED table (tt_cells[prog->transform_table], set into
 * st->tf_table by the entry), then tail-call the matcher. Same shape as
 * pfw_huff, but the table is data — any decoding the host can build (another
 * prefix code, an obfuscation) is a loaded table, no kernel change. Invalid
 * input fails closed. The P1 framework is why the stage body is this short. */
SEC("xdp")
int pfw_transform(struct xdp_md *ctx)
{
    PFW_STAGE_ENTER(ctx);
    if (f) {
        __u32 base = (st->tf_table & (TT_NTABLES - 1)) * TT_CELLS;
        __u32 inlen = f->reasm_len > REASM_CAP ? REASM_CAP : f->reasm_len;
        st->huff_state = 0; st->huff_outpos = 0; st->huff_fail = 0;
        struct tf_map_ctx tc = { .f = f, .st = st, .base = base, .n = inlen };
        if (inlen) bpf_loop(inlen, tf_map_step, &tc, 0);
        if (st->huff_fail)
            return stage_reset(ctx, &p, f);
        __u32 ol = st->huff_outpos > REASM_CAP ? REASM_CAP : st->huff_outpos;
        struct cp_ctx cp = { .f = f, .st = st, .n = ol };
        if (ol) bpf_loop(ol, cp_step, &cp, 0);
        f->reasm_len = ol;
        st->r[R_PAYLOAD] = 0; st->r[R_CUR] = 0; st->r[R_END] = ol; st->r[R_LEN] = ol;
    }
    bpf_tail_call(ctx, &decode_jmp, SLOT_MATCH);
    return XDP_PASS;
}
