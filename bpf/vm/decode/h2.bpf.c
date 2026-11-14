/* pfw: the HTTP/2 (DECODE_H2) tail-call stages — decode and resolve.
 *
 * pfw_decode HPACK-decodes the reassembled h2 stream into a compact intermediate
 * in st->dec, then tail-calls pfw_resolve, which expands it to "name: value"
 * lines in the flow buffer and tail-calls the matcher. Two stages because one
 * combined state machine exceeds the verifier's budget. Maps are extern (defined
 * in core/maps.bpf.c); this unit references them.
 */
#include "core/common.h"
#include "core/maps.h"
#include "parse/parse.h"
#include "core/stage.h"
#include "decode/h2.h"

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
        __u32 il = PFW_CLAMP(st->dec_len, REASM_CAP);
        struct h2_rs rs = { .f = f, .st = st, .len = il, .phase = 0 };
        bpf_loop(il, h2_resolve_step, &rs, 0);
        __u32 fl = PFW_CLAMP(rs.outpos, REASM_CAP);
        f->reasm_len = fl;
        PFW_SET_VIEW(st, fl);
    }
    bpf_tail_call(ctx, &decode_jmp, SLOT_MATCH);
    return XDP_PASS;
}
