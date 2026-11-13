/* pfw: userspace-facing side effects — per-rule counters and the event ring
 * (an enforcement/log record, optionally carrying up to LOG_CAP payload bytes). */
#ifndef PFW_EVENT_H
#define PFW_EVENT_H

#include "pfw_common.h"
#include "pfw_maps.h"
#include "pfw_parse.h"

static __always_inline void count_rule(__u32 rule)
{
    __u32 key = rule & (PFW_NRULES - 1);
    __u64 *n = bpf_map_lookup_elem(&counters, &key);
    if (n)
        (*n)++;
}

static __always_inline void emit(struct xdp_md *ctx, struct pkt *p, struct pfw_state *st, __u32 verdict)
{
    struct pfw_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        ring_full++;
        return;
    }
    e->ts = bpf_ktime_get_ns();
    e->ifindex = ctx->ingress_ifindex;
    e->rule = st->rule;
    e->verdict = verdict;
    e->mask = st->r[R_M];
    e->family = p->family;
    e->proto = p->proto;
    e->sport = p->sport;
    e->dport = p->dport;
    e->_pad = 0;
    __builtin_memcpy(e->saddr, p->saddr, 16);
    __builtin_memcpy(e->daddr, p->daddr, 16);
    __u32 len = st->log_len;
    __u64 off = st->log_off;
    __u64 end = st->r[R_END];
    if (off >= end || off > 0xffff)
        len = 0;
    else if (off + len > end)
        len = (__u32) (end - off);
    if (len > LOG_CAP)
        len = LOG_CAP;
    e->len = 0;
    if (len) {
        barrier_var(len);
        len = ((len - 1) & (LOG_CAP - 1)) + 1;
        if (bpf_xdp_load_bytes(ctx, (__u32) off, e->data, len) == 0)
            e->len = len;
    }
    logged++;
    bpf_ringbuf_submit(e, 0);
}

#endif /* PFW_EVENT_H */
