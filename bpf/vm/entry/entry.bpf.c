/* pfw: a pattern-matching interpreter at XDP.
 *
 * The program is data: up to PFW_MAX_OPS instructions in the `programs` map, one
 * generation active at a time, each run as a `bpf_loop` step over a per-CPU state
 * element. This unit is the entry (pfw_xdp) and the matcher (pfw_match); the
 * tail-call decode stages are their own units under decode/.
 *
 * The machinery lives in topic folders under bpf/include/, one each. The
 * `static __always_inline` helpers inline into each program (the verifier sees
 * the same code as a single file); maps are defined once in core/maps.bpf.c and
 * referenced extern; send_rst is a real cross-unit function (action/rst.h). Each
 * unit includes only the headers it uses:
 *
 *   core/common.h   base includes (vmlinux, libbpf, pfw.h)
 *   core/maps.h     control/counter globals, maps, pfw_state, decode_jmp
 *   core/match.h    match_half (runs the interpreter + applies the verdict)
 *   parse/parse.h   L2..L4 -> struct pkt
 *   io/reasm.h      TCP reassembly
 *   action/rst.h    send_rst (prototype; defined in action/rst.bpf.c)
 *   action/event.h  count_rule, emit
 *
 * bpftool gen object links all bpf/vm/ units into one bin/vm.bpf.o.
 */
#include "core/common.h"
#include "core/maps.h"
#include "parse/parse.h"
#include "io/reasm.h"
#include "action/rst.h"
#include "action/event.h"
#include "core/match.h"
#include "core/source.h"
#include "action/nat.h"

char LICENSE[] SEC("license") = "GPL";

/* The tail-call decode stages (pfw_decode/resolve/huff/transform) live in their
 * own unit, bpf/vm/decode/stages.bpf.c, statically linked into this object. */

/* Matcher stage (tail-call target): re-derive what the entry computed, then
 * run the interpreter over the active view. st and the flow buffer persist. */
SEC("xdp")
int pfw_match(struct xdp_md *ctx)
{
    struct pkt p = {};
    if (!parse(ctx, &p)) { passed++; return XDP_PASS; }
    __u32 gen = active & (PFW_GENS - 1);
    struct pfw_prog *prog = bpf_map_lookup_elem(&programs, &gen);
    if (!prog || prog->nops == 0) return XDP_PASS;
    __u32 zero = 0;
    struct pfw_state *st = bpf_map_lookup_elem(&state, &zero);
    if (!st) { passed++; return XDP_PASS; }
    __u64 now = bpf_ktime_get_ns();
    struct flow_key key = {};
    struct flow *f = NULL;
    int keyed = p.proto == IPPROTO_TCP || p.proto == IPPROTO_UDP;
    if (keyed) {
        __builtin_memcpy(key.saddr, p.saddr, 16);
        __builtin_memcpy(key.daddr, p.daddr, 16);
        __u32 sp = p.sport, dp = p.dport;
        barrier_var(sp); barrier_var(dp);
        key.sport = sp; key.dport = dp; key.proto = p.proto; key.family = p.family;
        f = bpf_map_lookup_elem(&flows, &key);
    }
    /* Only ever reached by tail call from a decode stage, which left the decoded
     * view in st->view and pointed the registers at it: that is what is read. */
    return match_half(ctx, &p, prog, f, st, gen, now, &key, keyed, 1, st->view);
}

SEC("xdp")
int pfw_xdp(struct xdp_md *ctx)
{
    seen++;
    __u32 gen = active & (PFW_GENS - 1);
    struct pfw_prog *prog = bpf_map_lookup_elem(&programs, &gen);
    if (!prog || prog->nops == 0)
        return XDP_PASS;

    struct pkt p = {};
    if (!parse(ctx, &p)) {
        passed++;
        return XDP_PASS;
    }

    /* A standing source ban drops everything from that address, on any port or
     * protocol, before any per-flow work. */
    if (src_banned(&p)) {
        src_enforced++;
        if (shadow) { shadowed++; passed++; return XDP_PASS; }
        dropped++;
        return XDP_DROP;
    }

    /* The reply half of a connection `dnat` diverted: put the address the client
     * dialled back as the source and pass it on. The program is not run on it. */
    if (p.family == AF_INET && nat_reverse(ctx, p.l3, p.l4, p.proto)) {
        passed++;
        return XDP_PASS;
    }

    /* The flow, for TCP and UDP. A 16-bit port widened in a register
     * leaves clang an undefined upper half it spills whole; the barrier
     * makes each a value it has to materialise. */
    struct flow_key key = {};
    struct flow *f = NULL;
    int keyed = p.proto == IPPROTO_TCP || p.proto == IPPROTO_UDP;
    __u64 now = bpf_ktime_get_ns();
    if (keyed) {
        __builtin_memcpy(key.saddr, p.saddr, 16);
        __builtin_memcpy(key.daddr, p.daddr, 16);
        __u32 sp = p.sport, dp = p.dport;
        barrier_var(sp);
        barrier_var(dp);
        key.sport = sp;
        key.dport = dp;
        key.proto = p.proto;
        key.family = p.family;
        f = bpf_map_lookup_elem(&flows, &key);
        if (f && f->mark && f->expires && f->expires <= now) {
            f->mark = 0;
            f->rule = 0;
        }
        /* Reassembly mode: a verdict bans one connection, not the 4-tuple. A
         * bare SYN is a new connection, which must be judged on its own bytes,
         * so clear any stale mark left on a reused ephemeral port. */
        if (f && prog->reasm && p.proto == IPPROTO_TCP
            && (p.tcp_flags & 0x02) && !(p.tcp_flags & 0x10)) {
            f->mark = 0;
            f->rule = 0;
        }
        if (f && (f->mark == MARK_DROP || f->mark == MARK_RST)) {
            enforced++;
            count_rule(f->rule);
            if (shadow) { shadowed++; passed++; return XDP_PASS; } /* shadow mode: would enforce, but pass */
            if (f->mark == MARK_RST && p.family == AF_INET && p.proto == IPPROTO_TCP) {
                int v = send_rst(ctx, p.l2);
                if (v == XDP_TX)
                    rsts++;
                else
                    dropped++;
                return v;
            }
            dropped++;
            return XDP_DROP;
        }
    }

    __u32 zero = 0;
    struct pfw_state *st = bpf_map_lookup_elem(&state, &zero);
    if (!st) {
        passed++;
        return XDP_PASS;
    }
    __builtin_memset(st->r, 0, sizeof(st->r));
    st->r[R_FRAME] = 0;
    st->r[R_L3] = p.l3;
    st->r[R_L4] = p.l4;
    st->r[R_PAYLOAD] = p.payload;
    st->r[R_END] = p.end;
    st->r[R_PROTO] = p.proto;
    st->r[R_SPORT] = p.sport;
    st->r[R_DPORT] = p.dport;
    st->r[R_CUR] = p.payload;
    st->r[R_IFINDEX] = ctx->ingress_ifindex;
    st->r[R_LEN] = p.end > p.payload ? p.end - p.payload : 0;
    if (p.family == AF_INET) {
        __u32 sa;
        __builtin_memcpy(&sa, p.saddr, 4);
        st->r[R_SADDR] = bpf_ntohl(sa); /* host order, so cidr's net is host order too */
    }
    st->r[R_SHADOW] = shadow; /* readable as %shadow */
    st->pc = 0;
    st->flags = 0;
    st->verdict = V_NONE;
    st->rule = 0;
    st->ttl = 0;
    st->set_mark = 0;
    st->set_state = 0;
    st->new_state = 0;
    st->state_ttl = 0;
    st->hits = f ? f->hits : 0;
    st->set_hits = 0;
    st->rl_tokens = f ? f->rl_tokens : 0;
    st->rl_ts = f ? f->rl_ts : 0;
    st->set_rl = 0;
    st->fargn = 0;
    st->fsn = 0;
    st->rw_n = 0;
    st->redirect_if = 0;
    st->log_len = 0;
    st->log_off = 0;
    st->nocase = prog->nocase;
    __builtin_memset(st->mpos, 0, sizeof(st->mpos));
    /* A TCP flow carries its automaton across segments, as long as the
     * program that built it is the one running. */
    if (f && p.proto == IPPROTO_TCP && f->gen == prog->gen) {
        st->ac_state = f->ac_state;
        st->r[R_M] = f->mask;
    } else {
        st->ac_state = 0;
    }

    /* Reassembly mode: rebuild the TCP stream in the flow and run the program
     * over it rather than over this one packet. A pattern split or reordered
     * across segments is then seen the way the server's TCP stack sees it. */
    __u32 use_reasm = prog->reasm && p.proto == IPPROTO_TCP
                   && (prog->reasm_dport == 0 || p.dport == prog->reasm_dport);
    if (use_reasm) {
        if (!f) {
            bpf_map_update_elem(&flows, &key, (void *) &zero_flow, BPF_NOEXIST);
            f = bpf_map_lookup_elem(&flows, &key);
            if (f)
                flows_created++;
        }
        if (!f) { passed++; return XDP_PASS; }
        int rf = reasm_feed(ctx, &p, f, st, prog->decode == DECODE_H2);
        if (rf == REASM_HOLD) {
            /* Out of order and beyond the window: drop it, TCP will resend it. */
            dropped++;
            return XDP_DROP;
        }
        if (rf) {
            /* Fail closed: mark the flow and tear it down so the peer reconnects
             * on a fresh flow we can see whole. */
            f->mark = MARK_RST;
            f->rule = 0;
            f->expires = 0;
            bans++;
            count_rule(0);
            if (p.family == AF_INET) {
                int v = send_rst(ctx, p.l2);
                if (v == XDP_TX) { rsts++; return v; }
            }
            dropped++;
            return XDP_DROP;
        }
        __u32 rl = f->reasm_len;
        if (rl > REASM_CAP) rl = REASM_CAP;
        /* Run over the reassembled stream: offsets are stream-relative, reads
         * come from f->reasm via window()/load(). No carried automaton. */
        st->r[R_PAYLOAD] = 0;
        st->r[R_CUR] = 0;
        st->r[R_END] = rl;
        st->r[R_LEN] = rl;
        st->ac_state = 0;
        st->r[R_M] = 0;
    }

    /* Dispatch. An h2-decode program tail-calls the decoder (which tail-calls
     * the matcher); everything else runs the matcher here. The entry has set up
     * st and (for reasm) the flow buffer, which persist across the tail call. */
    if (use_reasm && prog->decode == DECODE_H2 && f)
        bpf_tail_call(ctx, &decode_jmp, SLOT_DECODE);
    if (use_reasm && prog->decode == DECODE_HUFFMAN && f)
        bpf_tail_call(ctx, &decode_jmp, SLOT_HUFF);
    if (use_reasm && prog->decode == DECODE_TRANSFORM && f) {
        st->tf_table = prog->transform_table; /* carry the table id into the stage */
        bpf_tail_call(ctx, &decode_jmp, SLOT_TRANSFORM);
    }
    (void) use_reasm;
    return match_half(ctx, &p, prog, f, st, gen, now, &key, keyed, use_reasm, f ? f->reasm : NULL);
}
