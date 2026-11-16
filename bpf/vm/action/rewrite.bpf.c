/* pfw: the packet-rewrite tail-call stage (pfw_rewrite).
 *
 * The matcher records redact/replace requests in st->rw[] and tail-calls here on
 * a forwarded (PASS) packet. This program applies each request in its own
 * verifier budget, then returns XDP_PASS so the (rewritten) packet continues.
 */
#include "core/common.h"
#include "core/maps.h"
#include "io/read.h"
#include "match/scan.h"
#include "action/rewrite.h"

SEC("xdp")
int pfw_rewrite(struct xdp_md *ctx)
{
    __u32 gen = active_gen & (PFW_GENS - 1);
    struct pfw_prog *prog = bpf_map_lookup_elem(&programs, &gen);
    if (!prog || prog->nops == 0)
        return XDP_PASS;
    __u32 zero = 0;
    struct pfw_state *st = bpf_map_lookup_elem(&state, &zero);
    if (!st)
        return XDP_PASS;
    __u32 n = st->rw_n;
    if (n > RW_MAX)
        n = RW_MAX;
#pragma unroll
    for (__u32 k = 0; k < RW_MAX; k++) {
        if (k >= n)
            break;
        do_rewrite(ctx, st, prog, k);
    }
    return XDP_PASS;
}
