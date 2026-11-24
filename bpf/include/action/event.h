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

/* Emit a console() message to the host on the typed console ring: the format id,
 * the numeric args, and the captured %s strings. The host maps id -> format. */
static __always_inline void console_emit(struct xdp_md *ctx, struct pfw_state *st, __u32 fmtid)
{
    struct pfw_console *e = bpf_ringbuf_reserve(&console_ring, sizeof(*e), 0);
    if (!e) { ring_full++; return; }
    e->ts = bpf_ktime_get_ns();
    e->ifindex = ctx->ingress_ifindex;
    e->fmtid = fmtid;
    e->prog = st->prog_stamp;
    e->_pad0 = 0;
    e->nnum = st->fargn > FARGS_MAX ? FARGS_MAX : st->fargn;
    e->nstr = st->fsn > FSTR_MAX ? FSTR_MAX : st->fsn;
#pragma unroll
    for (int i = 0; i < FARGS_MAX; i++)
        e->nums[i] = st->fargs[i];
#pragma unroll
    for (int s = 0; s < FSTR_MAX; s++) {
        e->slen[s] = st->fslen[s];
        __builtin_memcpy(e->strs[s], st->fstr[s], STRARG_CAP);
    }
    bpf_ringbuf_submit(e, 0);
}

/* Send an emit() to the host: the event id and the numeric args pushed so far. */
static __always_inline void emit_values(struct xdp_md *ctx, struct pfw_state *st, __u32 id)
{
    struct pfw_emit *e = bpf_ringbuf_reserve(&emits, sizeof(*e), 0);
    if (!e) { ring_full++; return; }
    e->ts = bpf_ktime_get_ns();
    e->ifindex = ctx->ingress_ifindex;
    e->id = id;
    e->n = st->fargn > FARGS_MAX ? FARGS_MAX : st->fargn;
    e->prog = st->prog_stamp;
#pragma unroll
    for (int i = 0; i < FARGS_MAX; i++)
        e->vals[i] = st->fargs[i];
    bpf_ringbuf_submit(e, 0);
}

/* Copy the frame's first `want` bytes to the host. In its own frame: the helper
 * calls and the length juggling stay out of pfw_step's. The bytes come from the
 * packet as it is now — after a `dnat` earlier in the program, the rewritten
 * one — whatever view the program itself was reading. */
static __noinline void do_sample(struct xdp_md *ctx, __u32 want, __u32 tag, __u32 prog)
{
    struct pfw_sample *e = bpf_ringbuf_reserve(&samples, sizeof(*e), 0);
    if (!e) { ring_full++; return; }
    __u32 wire = (__u32) bpf_xdp_get_buff_len(ctx);
    __u32 n = want;
    if (n > wire) n = wire;
    if (n > SAMPLE_CAP) n = SAMPLE_CAP;
    e->ts = bpf_ktime_get_ns();
    e->ifindex = ctx->ingress_ifindex;
    e->tag = tag;
    e->prog = prog;
    e->wire_len = wire;
    e->cap_len = 0;
    if (n) {
        barrier_var(n);
        n = ((n - 1) & (SAMPLE_CAP - 1)) + 1;
        if (bpf_xdp_load_bytes(ctx, 0, e->data, n) == 0)
            e->cap_len = n;
    }
    sampled++;
    bpf_ringbuf_submit(e, 0);
}

/* `rsrc` is the buffer the program was reading when it is not the packet (the
 * reassembled stream, or a decoded view): log() offsets are relative to it, so
 * that is where the logged bytes must come from. NULL = the packet. */
static __always_inline void emit(struct xdp_md *ctx, struct pkt *p, struct pfw_state *st, __u32 verdict, __u8 *rsrc)
{
    struct pfw_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        ring_full++;
        return;
    }
    e->ts = bpf_ktime_get_ns();
    e->ifindex = ctx->ingress_ifindex;
    e->rule = st->rule;
    e->prog = st->prog_stamp;
    e->_pad0 = 0;
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
        if (rsrc) {
            /* off + len <= R_END <= REASM_CAP, checked above: the read stays inside
             * the buffer. probe_read copies a variable length without a loop. */
            if (bpf_probe_read_kernel(e->data, len, rsrc + PFW_MASK((__u32) off, REASM_CAP)) == 0)
                e->len = len;
        } else if (bpf_xdp_load_bytes(ctx, (__u32) off, e->data, len) == 0)
            e->len = len;
    }
    logged++;
    bpf_ringbuf_submit(e, 0);
}

#endif /* PFW_EVENT_H */
