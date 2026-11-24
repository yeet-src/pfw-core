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
#include "core/source.h"

/* Issue the redirect in its own (__noinline) frame so the bpf_redirect() helper
 * call doesn't force register spills into match_half's already-maxed inlined
 * stack frame. Returns XDP_REDIRECT, or -1 when no redirect was requested. */
static __noinline int maybe_redirect(struct pfw_state *st)
{
    if (st->redirect_if)
        return bpf_redirect(st->redirect_if, 0);
    return -1;
}

/* Write what a run changed of the program's per-connection state. */
static __always_inline void fprog_store(struct flow_prog *fp, struct pfw_state *st, struct pfw_prog *prog,
                                        struct pkt *pp, __u64 now)
{
    if (pp->proto == IPPROTO_TCP) { fp->ac_state = st->ac_state; fp->mask = st->r[R_M]; fp->gen = prog->gen; }
    if (st->set_state) { fp->user_state = st->new_state; fp->state_expires = st->state_ttl ? now + (__u64) st->state_ttl * 1000000000ULL : 0; }
    if (st->set_rl) { fp->rl_tokens = st->rl_tokens; fp->rl_ts = st->rl_ts; }
    if (st->set_hits) fp->hits = st->hits;
    if (st->set_ureg) __builtin_memcpy(fp->ureg, st->ureg, sizeof(fp->ureg));
    /* Pushes made while the program had no state here yet: they are its ring now. */
    if (st->pring_count) {
        __builtin_memcpy(fp->ring, st->pring, sizeof(fp->ring));
        fp->ring_head = st->pring_head & (RING_CAP - 1);
        fp->ring_count = st->pring_count > RING_CAP ? RING_CAP : st->pring_count;
    }
}

/* The entry passes its own values; the matcher tail-call target re-derives them
 * first. It never re-initialises st — the entry did that. */
static __always_inline int match_half(struct xdp_md *ctx, struct pkt *pp,
                                       struct pfw_prog *prog, struct flow *f, struct flow_prog *fp,
                                       struct pfw_state *st, __u64 now,
                                       struct flow_key *keyp, int keyed,
                                       __u32 use_reasm, __u8 *rsrc, __u32 chain)
{
    /* pp is used through the pointer: a by-value copy here cost ~60 bytes of the
     * entry's stack frame, which is at the 512-byte limit. */
    struct pfw_ctx c = {
        .xdp = ctx, .st = st, .prog = prog,
        .nops = prog->nops > PFW_MAX_OPS ? PFW_MAX_OPS : prog->nops,
        .mark = f ? f->mark : 0,
        .user_state = (fp && (!fp->state_expires || fp->state_expires > now)) ? fp->user_state : 0,
        .reasm = use_reasm, .now = now, .fp = fp, .rsrc = rsrc,
    };
    src_load(pp, st, now);
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
    /* And to the rule the packet ended on. `bi` is reused as the key: this
     * frame has no room for another local. */
    bi = st->time_rule & (RULE_POOL - 1);
    struct rule_time *rt = bpf_map_lookup_elem(&rule_time, &bi);
    if (rt) { rt->ns += dt; rt->runs++; }

    __u32 verdict = st->verdict ? st->verdict : V_PASS;
    if (st->flags & FL_FF) faults++;

    /* Write-back. What the program keeps for the connection goes to its own
     * flow_prog: inside the flow for the dispatched program, in `stage_flows`
     * for a stage. The mark is the connection's whichever program set it, and
     * the byte and packet counts are the dispatched program's run to add. */
    __u32 own = st->set_state || st->set_hits || st->set_rl || st->pring_count || st->set_ureg;
    if (keyed && chain) {
        if (prog->stage_flow && (pp->proto == IPPROTO_TCP || own)) {
            if (!fp && (own || pp->end > pp->payload)) {
                struct stage_key *sk = &st->x_sk;
                __builtin_memcpy(&sk->flow, keyp, sizeof(sk->flow));
                sk->stage = prog->stage_ix & (PFW_STAGES - 1);
                bpf_map_update_elem(&stage_flows, sk, (void *) &zero_fprog, BPF_NOEXIST);
                fp = bpf_map_lookup_elem(&stage_flows, sk);
            }
            if (fp)
                fprog_store(fp, st, prog, pp, now);
        }
        if (st->set_mark) {
            if (!f) {
                bpf_map_update_elem(&flows, keyp, (void *) &zero_flow, BPF_NOEXIST);
                f = bpf_map_lookup_elem(&flows, keyp);
                if (f) flows_created++;
            }
            if (f) { f->mark = st->set_mark; f->rule = st->rule; f->expires = st->ttl ? now + (__u64) st->ttl * 1000000000ULL : 0; }
        }
    } else if (keyed && (pp->proto == IPPROTO_TCP || st->set_mark || own || st->want_acct)) {
        if (!f && (st->set_mark || own || st->want_acct || pp->end > pp->payload)) {
            bpf_map_update_elem(&flows, keyp, (void *) &zero_flow, BPF_NOEXIST);
            f = bpf_map_lookup_elem(&flows, keyp);
            if (f) flows_created++;
        }
        if (f) {
            fprog_store(&f->own, st, prog, pp, now);
            /* Every packet of a tracked flow is counted, whether or not this
             * run of the program looked: the entry added this packet in. */
            f->bytes = st->fbytes;
            f->packets = st->fpackets;
            if (st->set_mark) { f->mark = st->set_mark; f->rule = st->rule; f->expires = st->ttl ? now + (__u64) st->ttl * 1000000000ULL : 0; }
            /* On a reassembled stream a `drop` must hold for the connection, not
             * the packet: TCP retransmits the dropped segment, and by then its
             * bytes have been consumed (decode) or the window has slid past
             * them, so the retransmission would be judged clean and delivered.
             * The connection is dead to the server from the first dropped
             * segment anyway; marking it keeps it that way. */
            else if (use_reasm && verdict == V_DROP) { f->mark = MARK_DROP; f->rule = st->rule; f->expires = 0; }
        }
    }

    /* Source write-back. `ban` is a SOURCE ban: the mark lands on the source
     * entry, so a reconnect from another port is still dropped at the entry. */
    src_store(pp, st, now, verdict);

    if (st->log_len) emit(ctx, pp, st, verdict, use_reasm ? rsrc : NULL);

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
        /* Not `bans`: nothing is banned. A reset is counted once, as `rsts`
         * when the RST goes out and as `dropped` when it cannot. */
        count_rule(st->rule);
        if (pp->family == AF_INET && pp->proto == IPPROTO_TCP) {
            int v = send_rst(ctx, pp->l2);
            if (v == XDP_TX) { rsts++; return v; }
        }
        dropped++; return XDP_DROP;
    default:
        /* A stage let it through: on to the stage after it, or from the last
         * one to the program the packet is dispatched to. If the call cannot be
         * made the packet passes, as it would with nothing after. */
        if (chain) {
            if (prog->next_on) {
                st->stage_slot = prog->next_slot;
                bpf_tail_call(ctx, &decode_jmp, SLOT_STAGE);
            }
            bpf_tail_call(ctx, &decode_jmp, SLOT_DISPATCH);
        }
        /* The window held one piece of a segment larger than it, and nothing in
         * the piece was stopped: on to the next. If the call cannot be made —
         * a decode spends several a piece, and the kernel allows 33 — the rest
         * would go by unread, so the connection is reset instead. */
        if (st->seg_more) {
            bpf_tail_call(ctx, &decode_jmp, SLOT_CONTINUE);
            reasm_over++;
            if (f) { f->mark = MARK_RST; f->rule = RULE_NONE; f->expires = 0; }
            dropped++;
            return XDP_DROP;
        }
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
