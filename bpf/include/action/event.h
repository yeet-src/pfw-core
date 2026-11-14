/* pfw: userspace-facing side effects — per-rule counters and the event ring
 * (an enforcement/log record, optionally carrying up to LOG_CAP payload bytes). */
#ifndef PFW_EVENT_H
#define PFW_EVENT_H

#include "core/common.h"
#include "core/maps.h"
#include "parse/parse.h"

static __always_inline void count_rule(__u32 rule)
{
    __u32 key = rule & (PFW_NRULES - 1);
    __u64 *n = bpf_map_lookup_elem(&counters, &key);
    if (n)
        (*n)++;
}

/* Emit a console message to the host: a pfw_event tagged PFW_EV_CONSOLE, carrying
 * the format id (in rule), the arg count (in len) and the pushed fargs (packed
 * into data). The host maps the id back to the format string and prints it. */
static __always_inline void console_emit(struct xdp_md *ctx, struct pfw_state *st, __u32 fmtid)
{
    struct pfw_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { ring_full++; return; }
    __builtin_memset(e, 0, sizeof(*e));
    e->ts = bpf_ktime_get_ns();
    e->ifindex = ctx->ingress_ifindex;
    e->verdict = PFW_EV_CONSOLE;
    e->rule = fmtid;
    __u32 n = st->fargn > FARGS_MAX ? FARGS_MAX : st->fargn;
    __u32 sn = st->fsn > FSTR_MAX ? FSTR_MAX : st->fsn;
    e->len = n | (sn << 8);                          /* numeric count | string count<<8 */
    /* layout: [FARGS_MAX u64 numbers][u8 sn][per string: u8 len, STRARG_CAP bytes] */
#pragma unroll
    for (int i = 0; i < FARGS_MAX; i++) {
        __u64 v = st->fargs[i];
        __builtin_memcpy(&e->data[i * 8], &v, 8);
    }
    e->data[FARGS_MAX * 8] = (__u8) sn;
#pragma unroll
    for (int s = 0; s < FSTR_MAX; s++) {
        __u32 b = FARGS_MAX * 8 + 1 + s * (1 + STRARG_CAP);
        e->data[b] = st->fslen[s];
        __builtin_memcpy(&e->data[b + 1], st->fstr[s], STRARG_CAP);  /* 32+1+2*33 = 99 <= LOG_CAP */
    }
    bpf_ringbuf_submit(e, 0);
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
