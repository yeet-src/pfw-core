/* pfw: the HPACK-Huffman (DECODE_HUFFMAN) tail-call stage.
 *
 * Huffman-decode the reassembled stream through the baked table (built from RFC
 * 7541 by src/huffman.js, tf_step), copy the decoded bytes back into the flow
 * buffer, then tail-call the matcher. Invalid input fails closed.
 */
#include "core/common.h"
#include "core/maps.h"
#include "parse/parse.h"
#include "core/stage.h"
#include "decode/transform.h"

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
