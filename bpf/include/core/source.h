/* pfw: per-source state — the `sources` map, keyed on the source address alone.
 * A flow entry dies with its 4-tuple; a source entry survives a reconnect from a
 * new port, which is what a ban, a per-source counter or a per-source rate limit
 * actually need. */
#ifndef PFW_SOURCE_H
#define PFW_SOURCE_H

#include "core/common.h"
#include "core/maps.h"
#include "parse/parse.h"
#include "action/event.h"

static const struct source zero_source;

/* Fill *k from the packet and look the source up (NULL if never seen). */
static __always_inline struct source *src_lookup(struct pkt *p, struct src_key *k)
{
    __builtin_memset(k, 0, sizeof(*k));
    __builtin_memcpy(k->addr, p->saddr, 16);
    k->family = p->family;
    return bpf_map_lookup_elem(&sources, k);
}

/* The source entry, created if absent. */
static __always_inline struct source *src_get(struct src_key *k)
{
    struct source *s = bpf_map_lookup_elem(&sources, k);
    if (s)
        return s;
    bpf_map_update_elem(&sources, k, (void *) &zero_source, BPF_NOEXIST);
    return bpf_map_lookup_elem(&sources, k);
}

/* Load the source's state into st before the program runs, and write it back
 * after. Both are __noinline and leave nothing on the caller's stack or in its
 * registers: the interpreter loop between them is verified once per distinct
 * caller state, so a live `struct source *` (NULL on one path, a map value on
 * another) would multiply that cost and blow the verifier's budget. */
static __noinline void src_load(struct pkt *p, struct pfw_state *st, __u64 now)
{
    struct src_key k;
    struct source *s = src_lookup(p, &k);
    st->src_state = (s && (!s->state_expires || s->state_expires > now)) ? s->user_state : 0;
    st->src_hits = s ? s->hits : 0;
    st->src_rl_tokens = s ? s->rl_tokens : 0;
    st->src_rl_ts = s ? s->rl_ts : 0;
    st->src_set_state = 0;
    st->src_set_hits = 0;
    st->src_set_rl = 0;
}

/* `ban` is a SOURCE ban: the mark lands on the source entry, so a reconnect
 * from another port is still dropped at the entry. */
static __noinline void src_store(struct pkt *p, struct pfw_state *st, __u64 now, __u32 verdict)
{
    int ban = verdict == V_BAN && !shadow;
    if (!ban && !st->src_set_state && !st->src_set_hits && !st->src_set_rl)
        return;
    struct src_key k;
    struct source *s = src_lookup(p, &k);
    if (!s)
        s = src_get(&k);
    if (!s)
        return;
    if (st->src_set_state) {
        s->user_state = st->src_new_state;
        s->state_expires = st->src_state_ttl ? now + (__u64) st->src_state_ttl * 1000000000ULL : 0;
    }
    if (st->src_set_hits)
        s->hits = st->src_hits;
    if (st->src_set_rl) {
        s->rl_tokens = st->src_rl_tokens;
        s->rl_ts = st->src_rl_ts;
    }
    if (ban) {
        s->mark = MARK_DROP;
        s->rule = st->rule;
        s->expires = st->ttl ? now + (__u64) st->ttl * 1000000000ULL : 0;
    }
}

/* 1 if the packet's source is under a live ban (an expired one is lifted here).
 * __noinline: its key lives in its own frame, off the entry's tight stack. */
static __noinline int src_banned(struct pkt *p)
{
    struct src_key k;
    struct source *s = src_lookup(p, &k);
    if (!s || s->mark != MARK_DROP)
        return 0;
    if (s->expires && s->expires <= bpf_ktime_get_ns()) {
        s->mark = 0;
        s->rule = 0;
        return 0;
    }
    count_enforced(s->rule);
    return 1;
}

#endif /* PFW_SOURCE_H */
