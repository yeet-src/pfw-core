/* pfw: the general (loadable-table) transform (DECODE_TRANSFORM) tail-call stage.
 *
 * Decode the reassembled stream through a HOST-LOADED table
 * (tt_cells[prog->transform_table], set into st->tf_table by the entry,
 * tf_map_step), copy the decoded bytes back, then tail-call the matcher. The
 * table is data, so any decoding the host can build works with no kernel change.
 * Invalid input fails closed.
 */
#include "core/common.h"
#include "core/maps.h"
#include "parse/parse.h"
#include "core/stage.h"
#include "decode/transform.h"

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
