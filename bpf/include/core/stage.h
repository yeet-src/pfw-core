/* pfw: the stage framework (P1). A tail-call decode stage is always: parse the
 * packet, get the per-cpu state and the flow, run a decode over the reassembled
 * buffer, then tail-call the next stage (or fail closed). That prologue and the
 * reset were hand-written in every stage; here they are a helper and a macro, so
 * a new decoder is just its body. Continuations live in the maps the stages
 * already share (the per-cpu `state` and the per-flow buffer) — the only state a
 * tail call may carry. The host fills decode_jmp and attaches only the entry
 * (pfw_xdp) as the XDP hook.
 *
 * This is the decode stages' half of the old stage.h; match_half (which pulls in
 * the whole interpreter) now lives in core/match.h, so a decode stage includes
 * this and not the matcher it never runs. */
#ifndef PFW_STAGE_H
#define PFW_STAGE_H

#include "core/common.h"
#include "core/maps.h"
#include "parse/parse.h"
#include "action/event.h"
#include "action/rst.h"

/* Build the flow key from the packet and look the flow up. Fills *key (a caller
 * may reuse it, e.g. to create the flow) and returns the flow or NULL. */
static __always_inline struct flow *flow_lookup(struct pkt *p, struct flow_key *key)
{
    __builtin_memcpy(key->saddr, p->saddr, 16);
    __builtin_memcpy(key->daddr, p->daddr, 16);
    __u32 sp = p->sport, dp = p->dport;
    barrier_var(sp); barrier_var(dp);
    key->sport = sp; key->dport = dp; key->proto = p->proto; key->family = p->family;
    return bpf_map_lookup_elem(&flows, key);
}

/* Fail closed: mark the flow for reset and answer with a RST (else drop). A
 * stage that cannot safely decode does `return stage_reset(ctx, &p, f)`. */
static __always_inline int stage_reset(struct xdp_md *ctx, struct pkt *p, struct flow *f)
{
    f->mark = MARK_RST; f->rule = 0; f->expires = 0;
    bans++; count_rule(0);
    if (p->family == AF_INET) {
        int v = send_rst(ctx, p->l2);
        if (v == XDP_TX) { rsts++; return v; }
    }
    dropped++; return XDP_DROP;
}

/* Stage prologue: declare `p`, `st`, `key` and `f`, and bail to XDP_PASS if the
 * packet does not parse or the state map is missing. A stage body follows, then
 * `bpf_tail_call(ctx, &decode_jmp, SLOT_NEXT); return XDP_PASS;`. */
#define PFW_STAGE_ENTER(ctx)                                        \
    struct pkt p = {};                                              \
    if (!parse((ctx), &p)) return XDP_PASS;                         \
    __u32 zero = 0;                                                 \
    struct pfw_state *st = bpf_map_lookup_elem(&state, &zero);      \
    if (!st) { passed++; return XDP_PASS; }                         \
    struct flow_key key = {};                                       \
    struct flow *f = flow_lookup(&p, &key);                         \
    (void) st; (void) f; (void) key

#endif /* PFW_STAGE_H */
