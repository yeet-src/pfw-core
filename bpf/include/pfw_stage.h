/* pfw: the match half + the stage framework (P1).
 *
 * match_half runs the interpreter over whichever view is active and applies the
 * verdict (flow write-back, event, RST/DROP/PASS). The stage framework factors
 * the prologue every tail-call decode stage shares: parse the packet, fetch the
 * per-cpu state and the flow, with a fail-closed reset helper. A new decode
 * stage is then just PFW_STAGE_ENTER(ctx), its body, and a tail call. */
#ifndef PFW_STAGE_H
#define PFW_STAGE_H

#include "pfw_common.h"
#include "pfw_maps.h"
#include "pfw_parse.h"
#include "pfw_interp.h"
#include "pfw_event.h"
#include "pfw_rst.h"

/* The match half: run the interpreter over whichever view is active and apply
 * the verdict. Inlined and handed already-computed state, so it adds no call
 * frame (the 512-byte stack is tight) and does not re-parse. The entry passes
 * its own values; the matcher tail-call target re-derives them first. It never
 * re-initialises st — the entry did that. */
static __always_inline int match_half(struct xdp_md *ctx, struct pkt *pp,
                                       struct pfw_prog *prog, struct flow *f,
                                       struct pfw_state *st, __u32 gen, __u64 now,
                                       struct flow_key *keyp, int keyed,
                                       __u32 use_reasm, __u32 use_decode)
{
    struct pkt p = *pp;
    struct flow_key key = *keyp;
    struct pfw_ctx c = {
        .xdp = ctx, .st = st, .prog = prog,
        .nops = prog->nops > PFW_MAX_OPS ? PFW_MAX_OPS : prog->nops,
        .gen = gen, .mark = f ? f->mark : 0,
        .user_state = (f && (!f->state_expires || f->state_expires > now)) ? f->user_state : 0,
        .reasm = use_reasm, .flow = f,
    };
    ran++;
    __u64 t0 = bpf_ktime_get_ns();
    bpf_loop(PFW_MAX_OPS, pfw_step, &c, 0);
    __u64 dt = bpf_ktime_get_ns() - t0;
    decide_ns += dt;
    __u32 bi = 0;
#define DECIDE_STEP(n) barrier_var(dt); bi += dt >= (n);
    DECIDE_BOUNDS(DECIDE_STEP)
#undef DECIDE_STEP
    bi &= DECIDE_BUCKETS - 1;
    __u64 *slot = bpf_map_lookup_elem(&decide_hist, &bi);
    if (slot) (*slot)++;

    __u32 verdict = st->verdict ? st->verdict : V_PASS;
    if (st->flags & FL_FF) faults++;

    if (keyed && (p.proto == IPPROTO_TCP || st->set_mark || st->set_state || st->set_hits)) {
        if (!f && (st->set_mark || st->set_state || st->set_hits || p.end > p.payload)) {
            bpf_map_update_elem(&flows, &key, (void *) &zero_flow, BPF_NOEXIST);
            f = bpf_map_lookup_elem(&flows, &key);
            if (f) flows_created++;
        }
        if (f) {
            if (p.proto == IPPROTO_TCP) { f->ac_state = st->ac_state; f->mask = st->r[R_M]; f->gen = prog->gen; }
            if (st->set_state) { f->user_state = st->new_state; f->state_expires = st->state_ttl ? now + (__u64) st->state_ttl * 1000000000ULL : 0; }
            if (st->set_hits) f->hits = st->hits;
            if (st->set_mark) { f->mark = st->set_mark; f->rule = st->rule; f->expires = st->ttl ? now + (__u64) st->ttl * 1000000000ULL : 0; }
        }
    }

    if (st->log_len) emit(ctx, &p, st, verdict);

    switch (verdict) {
    case V_DROP: count_rule(st->rule); dropped++; return XDP_DROP;
    case V_BAN: count_rule(st->rule); bans++; dropped++; return XDP_DROP;
    case V_RST:
        count_rule(st->rule); bans++;
        if (p.family == AF_INET && p.proto == IPPROTO_TCP) {
            int v = send_rst(ctx, p.l2);
            if (v == XDP_TX) { rsts++; return v; }
        }
        dropped++; return XDP_DROP;
    default: passed++; return XDP_PASS;
    }
}

/* ---- stage framework (P1) -------------------------------------------------
 * A tail-call decode stage is always: parse the packet, get the per-cpu state
 * and the flow, run a decode over the reassembled buffer, then tail-call the
 * next stage (or fail closed). That prologue and the reset were hand-written in
 * every stage; here they are a helper and a macro, so a new decoder is just its
 * body. Continuations live in the maps the stages already share (the per-cpu
 * `state` and the per-flow buffer) — the only state a tail call may carry. The
 * host fills decode_jmp and attaches only the entry (pfw_xdp) as the XDP hook. */

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
    void *data = (void *) (long) (ctx)->data;                       \
    void *data_end = (void *) (long) (ctx)->data_end;               \
    struct pkt p = {};                                              \
    if (!parse(data, data_end, &p)) return XDP_PASS;                \
    __u32 zero = 0;                                                 \
    struct pfw_state *st = bpf_map_lookup_elem(&state, &zero);      \
    if (!st) { passed++; return XDP_PASS; }                         \
    struct flow_key key = {};                                       \
    struct flow *f = flow_lookup(&p, &key);                         \
    (void) st; (void) f; (void) key

#endif /* PFW_STAGE_H */
