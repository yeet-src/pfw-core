/* pfw: the match half — run the interpreter over whichever view is active and
 * apply the verdict (flow write-back, event, RST/DROP/PASS). Inlined and handed
 * already-computed state, so it adds no call frame (the 512-byte stack is tight)
 * and does not re-parse; it takes 11 arguments, past the BPF 5-arg ABI, so it
 * must inline — it cannot be a cross-unit function. Pulls in the interpreter
 * (match/interp.h), so the decode stages include core/stage.h, not this. */
#ifndef PFW_MATCH_H
#define PFW_MATCH_H

#include "core/common.h"
#include "core/maps.h"
#include "parse/parse.h"
#include "match/interp.h"
#include "action/event.h"
#include "action/rst.h"

/* Issue the redirect in its own (__noinline) frame so the bpf_redirect() helper
 * call doesn't force register spills into match_half's already-maxed inlined
 * stack frame. Returns XDP_REDIRECT, or -1 when no redirect was requested. */
static __noinline int maybe_redirect(struct pfw_state *st)
{
    if (st->redirect_if)
        return bpf_redirect(st->redirect_if, 0);
    return -1;
}

/* The entry passes its own values; the matcher tail-call target re-derives them
 * first. It never re-initialises st — the entry did that. */
static __always_inline int match_half(struct xdp_md *ctx, struct pkt *pp,
                                       struct pfw_prog *prog, struct flow *f,
                                       struct pfw_state *st, __u32 gen, __u64 now,
                                       struct flow_key *keyp, int keyed,
                                       __u32 use_reasm, __u32 use_decode)
{
    struct pkt p = *pp;
    struct pfw_ctx c = {
        .xdp = ctx, .st = st, .prog = prog,
        .nops = prog->nops > PFW_MAX_OPS ? PFW_MAX_OPS : prog->nops,
        .gen = gen, .mark = f ? f->mark : 0,
        .user_state = (f && (!f->state_expires || f->state_expires > now)) ? f->user_state : 0,
        .reasm = use_reasm, .now = now, .flow = f,
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

    if (keyed && (p.proto == IPPROTO_TCP || st->set_mark || st->set_state || st->set_hits || st->set_rl)) {
        if (!f && (st->set_mark || st->set_state || st->set_hits || st->set_rl || p.end > p.payload)) {
            bpf_map_update_elem(&flows, keyp, (void *) &zero_flow, BPF_NOEXIST);
            f = bpf_map_lookup_elem(&flows, keyp);
            if (f) flows_created++;
        }
        if (f) {
            if (p.proto == IPPROTO_TCP) { f->ac_state = st->ac_state; f->mask = st->r[R_M]; f->gen = prog->gen; }
            if (st->set_state) { f->user_state = st->new_state; f->state_expires = st->state_ttl ? now + (__u64) st->state_ttl * 1000000000ULL : 0; }
            if (st->set_rl) { f->rl_tokens = st->rl_tokens; f->rl_ts = st->rl_ts; }
            if (st->set_hits) f->hits = st->hits;
            if (st->set_mark) { f->mark = st->set_mark; f->rule = st->rule; f->expires = st->ttl ? now + (__u64) st->ttl * 1000000000ULL : 0; }
        }
    }

    if (st->log_len) emit(ctx, &p, st, verdict);

    /* Shadow mode: an enforcement verdict is counted and logged (above), and its
     * flow mark is written, but the packet is let through — a dry run that shows
     * what a rule WOULD block without affecting traffic. Set from the host. */
    if (shadow && (verdict == V_DROP || verdict == V_BAN || verdict == V_RST)) {
        count_rule(st->rule); shadowed++; return XDP_PASS;
    }

    /* OP_REDIRECT is terminal: forward the packet out the recorded ifindex.
     * bpf_redirect() returns XDP_REDIRECT, which must be this program's return
     * value, so it takes precedence over the verdict (and over the rewrite
     * stage — redirect does not compose with redact/replace). */
    { int rv = maybe_redirect(st); if (rv != -1) { passed++; return rv; } }

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
    default:
        passed++;
        /* Forwarding the packet: if the program recorded redact/replace requests,
         * hand off to the rewrite stage (its own verifier budget) to apply them
         * before the packet continues. Falls through to PASS if the slot is empty. */
        if (st->rw_n)
            bpf_tail_call(ctx, &decode_jmp, SLOT_REWRITE);
        return XDP_PASS;
    }
}

#endif /* PFW_MATCH_H */
