/* pfw: the interpreter — one instruction per bpf_loop step over the per-cpu
 * state. The program is data (ops in the `programs` map); this is the switch
 * that executes it: arithmetic, loads, compares, forward-only jumps, scan /
 * cmpstr / findb / skipb, the verdicts, per-flow state and the ring. */
#ifndef PFW_INTERP_H
#define PFW_INTERP_H

#include "core/common.h"
#include "core/maps.h"
#include "io/read.h"
#include "match/scan.h"

/* DNAT: rewrite the destination (IPv4 + port) and fix the IP + L4 checksums.
 * __noinline so its locals get their own stack frame (pfw_step is already large).
 * Per-packet, IPv4 TCP/UDP; no loop, so it's cheap. imm = ip(low32) | port<<32. */
static __noinline void do_dnat(struct xdp_md *xdp, struct pfw_state *st, __u64 imm)
{
    __u32 proto = (__u32) st->r[R_PROTO];
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return;
    __u32 l3 = (__u32) st->r[R_L3], l4 = (__u32) st->r[R_L4];
    __u8 ver = 0;
    if (bpf_xdp_load_bytes(xdp, l3, &ver, 1) || (ver >> 4) != 4)
        return;                                      /* IPv4 only */
    __be32 oldip = 0, newip = bpf_htonl((__u32) imm);
    __be16 oldport = 0, newport = bpf_htons((__u16) (imm >> 32));
    if (bpf_xdp_load_bytes(xdp, l3 + 16, &oldip, 4) || bpf_xdp_load_bytes(xdp, l4 + 2, &oldport, 2))
        return;
    bpf_xdp_store_bytes(xdp, l3 + 16, &newip, 4);        /* dst IPv4 */
    bpf_xdp_store_bytes(xdp, l4 + 2, &newport, 2);       /* dst port */
    __wsum dip = bpf_csum_diff(&oldip, 4, &newip, 4, 0);
    __u16 ipck = 0;                                      /* IP header checksum */
    if (bpf_xdp_load_bytes(xdp, l3 + 10, &ipck, 2) == 0) {
        __u32 s = (__u16) ~ipck;
        s += dip; s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16);
        ipck = (__u16) ~s;
        bpf_xdp_store_bytes(xdp, l3 + 10, &ipck, 2);
    }
    __u32 coff = proto == IPPROTO_TCP ? l4 + 16 : l4 + 6; /* L4 checksum */
    __u16 l4ck = 0;
    if (bpf_xdp_load_bytes(xdp, coff, &l4ck, 2) == 0 && (proto == IPPROTO_TCP || l4ck != 0)) {
        __wsum d = bpf_csum_diff((__be32 *) &oldport, 2, (__be32 *) &newport, 2, dip); /* dst IP (pseudo) + port */
        __u32 s = (__u16) ~l4ck;
        s += d; s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16);
        l4ck = (__u16) ~s;
        bpf_xdp_store_bytes(xdp, coff, &l4ck, 2);
    }
}

/* Token-bucket rate limiter over the flow's rl_tokens/rl_ts (carried in st,
 * written back to the flow in finish()). Tokens are fixed-point x RL_SCALE.
 * Refill = elapsed_ns * rate / (1e9 / RL_SCALE) = elapsed_ns * rate / 1000,
 * which avoids both floats and overflow for sane rates. Returns 1 when the
 * packet is OVER the limit (no token to spend), 0 when allowed. __noinline so
 * the 64-bit math stays out of pfw_step's stack frame. */
static __noinline int do_rate(struct pfw_state *st, __u64 now, __u64 imm)
{
    __u64 rate = (__u32) imm;                 /* tokens per second */
    __u64 cap = (__u32) (imm >> 32) * RL_SCALE; /* bucket capacity, scaled */
    __u64 tokens;
    if (st->rl_ts == 0) {                     /* first sight of this flow: full bucket */
        tokens = cap;
    } else {
        __u64 elapsed = now > st->rl_ts ? now - st->rl_ts : 0;
        __u64 refill = elapsed * rate / 1000; /* ns * (tok/s) / 1000 = tokens x RL_SCALE */
        tokens = st->rl_tokens + refill;
        if (tokens > cap) tokens = cap;
    }
    st->rl_ts = now;
    st->set_rl = 1;
    if (tokens >= RL_SCALE) {                 /* spend one token: allowed */
        st->rl_tokens = tokens - RL_SCALE;
        return 0;
    }
    st->rl_tokens = tokens;                   /* over the limit */
    return 1;
}

static long pfw_step(__u32 i, void *pctx)
{
    struct pfw_ctx *c = pctx;
    struct pfw_state *st = c->st;
    struct pfw_prog *p = c->prog;
    if (!st || !p)
        return 1;
    if (st->verdict)
        return 1;
    __u32 pc = st->pc;
    if (pc >= c->nops || pc >= PFW_MAX_OPS)
        return 1;
    struct pfw_op *op = &p->ops[PFW_MASK(pc, PFW_MAX_OPS)];
    __u32 code = op->code;
    _Static_assert((NREGS & (NREGS - 1)) == 0, "NREGS must be a power of two: the index is masked");
    __u32 reg = op->reg & (NREGS - 1);
    __u64 imm = op->imm;
    __u64 cur = st->r[R_CUR];
    __u32 next = pc + 1;
    __u32 fl = st->flags;

    switch (code) {
    case OP_END:
        st->verdict = V_PASS;
        return 1;
    case OP_MOV_RC:
        cur = st->r[reg];
        break;
    case OP_MOV_CR:
        if (reg != R_CUR)
            st->r[reg] = cur;
        break;
    case OP_ADD_I:
        cur += imm;
        break;
    case OP_SUB_I:
        cur -= imm;
        break;
    case OP_ADD_R:
        cur += st->r[reg];
        break;
    case OP_SUB_R:
        cur -= st->r[reg];
        break;
    case OP_AND_I:
        cur &= imm;
        break;
    case OP_OR_I:
        cur |= imm;
        break;
    case OP_SHL_I:
        cur <<= (imm & 63);
        break;
    case OP_SHR_I:
        cur >>= (imm & 63);
        break;
    case OP_CIDR: {
        /* imm packs the network (low 32 bits, host order) and the prefix
         * length (bits 32..39). ZF is set when the cursor, taken as an IPv4
         * address, lies in network/prefix. mov %saddr, %cur feeds it. */
        __u32 net = (__u32) imm;
        __u32 prefix = (__u32) (imm >> 32) & 0xff;
        __u32 mask = prefix == 0 ? 0u
                   : (prefix >= 32 ? 0xffffffffu : (0xffffffffu << (32 - prefix)));
        __u32 a = (__u32) cur;
        fl = (fl & FL_FF) | (((a & mask) == (net & mask)) ? FL_ZF : 0);
        break;
    }
    case OP_LOAD: {
        __u32 size = op->reg & 15;
        int be = (op->reg & 16) != 0;
        __u64 v = 0;
        if (load(c, cur + imm, size, be, &v))
            cur = v;
        else
            fl |= FL_FF;
        break;
    }
    case OP_CMP_I:
        fl = (fl & FL_FF) | (cur == imm ? FL_ZF : 0) | (cur < imm ? FL_CF : 0);
        break;
    case OP_CMP_R: {
        __u64 v = st->r[reg];
        fl = (fl & FL_FF) | (cur == v ? FL_ZF : 0) | (cur < v ? FL_CF : 0);
        break;
    }
    case OP_TEST:
        fl = (fl & FL_FF) | ((st->r[R_M] & imm) == 0 ? FL_ZF : 0);
        break;
    case OP_JMP:
    case OP_JE:
    case OP_JNE:
    case OP_JB:
    case OP_JAE:
    case OP_JA:
    case OP_JBE:
    case OP_JF: {
        int take = 0;
        switch (code) {
        case OP_JMP: take = 1; break;
        case OP_JE:  take = (fl & FL_ZF) != 0; break;
        case OP_JNE: take = (fl & FL_ZF) == 0; break;
        case OP_JB:  take = (fl & FL_CF) != 0; break;
        case OP_JAE: take = (fl & FL_CF) == 0; break;
        case OP_JA:  take = (fl & (FL_CF | FL_ZF)) == 0; break;
        case OP_JBE: take = (fl & (FL_CF | FL_ZF)) != 0; break;
        case OP_JF:  take = (fl & FL_FF) != 0; if (take) fl &= ~FL_FF; break;
        }
        if (take) {
            /* Forward only: the assembler refuses anything else, and a
             * program that got past it still cannot loop. */
            if (imm <= pc || imm > PFW_MAX_OPS) {
                st->verdict = V_PASS;
                faults++;
                return 1;
            }
            next = (__u32) imm;
        }
        break;
    }
    case OP_SCAN: {
        __u32 n = window(c, cur, (__u32) (PFW_CLAMP(imm, SCAN_CAP)));
        if (n) {
            scanned_bytes += n;
            c->scan_off = (__u32) cur;
            c->scan_len = n;
            c->re_state = 0;          /* ac_step also walks the regex DFA */
            bpf_loop(n, ac_step, c, 0);
        }
        break;
    }
    case OP_MPOS: {
        __u32 pos = st->mpos[PFW_MASK(reg, PFW_MAX_PATS)];
        if (pos)
            cur = pos;
        else
            fl |= FL_FF;
        break;
    }
    case OP_CMPSTR: {
        __u32 pi = op->reg & (PFW_MAX_PATS - 1);
        __u32 len = p->pats[pi].len;
        if (len == 0 || len > PFW_PAT_CAP) {
            fl = (fl & FL_FF);
            break;
        }
        __u32 n = window(c, cur, len);
        c->eq = n == len;
        if (c->eq) {
            c->scan_len = n;
            c->pat = pi;
            bpf_loop(n, cmpstr_step, c, 0);
        }
        fl = (fl & FL_FF) | (c->eq ? FL_ZF : 0);
        break;
    }
    case OP_FINDB: {
        __u32 n = window(c, cur, (__u32) (PFW_CLAMP(imm, SCAN_CAP)));
        fl |= FL_FF; /* cleared by the step that finds it */
        st->flags = fl;
        if (n) {
            c->scan_off = (__u32) cur;
            c->scan_len = n;
            c->byte = op->reg & 0xff;
            bpf_loop(n, findb_step, c, 0);
        }
        /* findb_step wrote the cursor and the flags itself */
        st->pc = next;
        return 0;
    }
    case OP_SKIPB: {
        __u32 n = window(c, cur, (__u32) (imm == 0 || imm > PFW_PAT_CAP ? PFW_PAT_CAP : imm));
        c->count = 0;
        if (n) {
            c->scan_len = n;
            c->byte = op->reg & 0xff;
            bpf_loop(n, skipb_step, c, 0);
        }
        cur += c->count;
        break;
    }
    case OP_PASS:
        st->verdict = V_PASS;
        break;
    case OP_DROP:
        st->verdict = V_DROP;
        st->rule = op->reg & (PFW_NRULES - 1);
        break;
    case OP_COUNT: {
        __u32 key = op->reg & (PFW_NRULES - 1);
        __u64 *n = bpf_map_lookup_elem(&counters, &key);
        if (n)
            (*n)++;
        break;
    }
    case OP_LOG:
        st->log_len = (__u32) (PFW_CLAMP(imm, LOG_CAP));
        st->log_off = (__u32) cur;
        break;
    case OP_BAN:
        st->verdict = V_BAN;
        st->rule = op->reg & (PFW_NRULES - 1);
        st->ttl = (__u32) imm;
        st->set_mark = MARK_DROP;
        break;
    case OP_RST:
        st->verdict = V_RST;
        st->rule = op->reg & (PFW_NRULES - 1);
        st->ttl = (__u32) imm;
        st->set_mark = MARK_RST;
        break;
    case OP_FLOW:
        cur = c->mark;
        break;
    case OP_MARK:
        st->set_mark = op->reg;
        st->ttl = (__u32) imm;
        break;
    case OP_SLOAD:
        cur = c->user_state;
        break;
    case OP_SSTORE:
        st->new_state = (__u32) imm;
        st->set_state = 1;
        st->state_ttl = reg;
        break;
    case OP_BUMP:
        st->hits++;
        st->set_hits = 1;
        cur = st->hits;
        break;
    case OP_RPUSH:
        /* Push cur onto the flow's ring (newest at head). Needs a tracked flow
         * — reasm mode always has one; otherwise it is a no-op until the flow
         * exists. Written straight to the flow value, like the ring is read. */
        if (c->flow) {
            __u32 h = c->flow->ring_head & (RING_CAP - 1);
            c->flow->ring[h] = (__u32) cur;
            c->flow->ring_head = (h + 1) & (RING_CAP - 1);
            if (c->flow->ring_count < RING_CAP)
                c->flow->ring_count++;
        }
        break;
    case OP_RGET: {
        /* cur = the (cur)-th most recent entry, 0 = newest. Out of range (or no
         * flow) yields 0 and faults, so `jf` can tell absent from a stored 0. */
        __u32 idx = (__u32) cur;
        if (c->flow && idx < c->flow->ring_count) {
            __u32 slot = (c->flow->ring_head - 1 - idx) & (RING_CAP - 1);
            cur = c->flow->ring[slot];
        } else {
            cur = 0;
            fl |= FL_FF;
        }
        break;
    }
    case OP_RLEN:
        cur = c->flow ? c->flow->ring_count : 0;
        break;
    case OP_REDACT:
    case OP_REPLACE:
        /* Wire rewrite is per-packet only (in reasm mode the matcher reads a
         * reconstructed buffer, not the packet). Record the request; the
         * pfw_rewrite tail-call stage applies it after matching, in its own
         * verifier budget. */
        if (!c->reasm && st->rw_n < RW_MAX) {
            __u32 k = st->rw_n & (RW_MAX - 1);
            st->rw[k].pat = op->reg & (PFW_MAX_PATS - 1);
            st->rw[k].mode = (code == OP_REPLACE);
            st->rw[k].repl = (__u32) (imm & (PFW_MAX_PATS - 1));
            st->rw[k].fill = (__u32) (imm & 0xff);
            st->rw[k].woff = (__u32) st->r[R_PAYLOAD]; /* whole payload, not cursor */
            st->rw_n++;
        }
        break;
    case OP_DNAT:
        /* Rewrite dst IPv4 + port and fix both checksums, then the program
         * forwards (PASS) and the stack routes the rewritten packet. In its own
         * (__noinline) frame so its locals don't bloat pfw_step's stack. */
        if (!c->reasm)
            do_dnat(c->xdp, st, imm);
        break;
    case OP_LPM: {
        /* ZF = cur (an IPv4 address, host order) is in the lpm_trie CIDR set.
         * LPM key data is the address in network byte order (matched MSB-first). */
        struct lpm_key key = { .prefixlen = 32 };
        __be32 a = bpf_htonl((__u32) cur);
        __builtin_memcpy(key.data, &a, 4);
        __u32 *v = bpf_map_lookup_elem(&lpm, &key);
        fl = (fl & FL_FF) | (v ? FL_ZF : 0);
        break;
    }
    case OP_HASH: {
        /* ZF = cur (low 32 bits) is a key in the hashset. */
        __u32 k = (__u32) cur;
        __u32 *v = bpf_map_lookup_elem(&hashset, &k);
        fl = (fl & FL_FF) | (v ? FL_ZF : 0);
        break;
    }
    case OP_BLOOM: {
        /* ZF = cur (low 32 bits) is (probably) in the bloom filter. peek returns
         * 0 when present, an error when definitely absent. */
        __u32 e = (__u32) cur;
        fl = (fl & FL_FF) | (bpf_map_peek_elem(&bloom, &e) == 0 ? FL_ZF : 0);
        break;
    }
    case OP_LPM6: {
        /* ZF = the IPv6 source (read from the packet, l3+8, 16 bytes network
         * order) is in the lpm6 CIDR set. IPv6 only (version nibble == 6). */
        __u32 l3 = (__u32) st->r[R_L3];
        __u8 ver = 0;
        if (bpf_xdp_load_bytes(c->xdp, l3, &ver, 1) || (ver >> 4) != 6)
            break;
        struct lpm6_key key = { .prefixlen = 128 };
        if (bpf_xdp_load_bytes(c->xdp, l3 + 8, key.data, 16))
            break;
        __u32 *v = bpf_map_lookup_elem(&lpm6, &key);
        fl = (fl & FL_FF) | (v ? FL_ZF : 0);
        break;
    }
    case OP_RATE:
        /* Token-bucket rate limit on this flow. ZF = 1 when over the limit
         * (the packet consumed no token). __noinline so the 64-bit refill math
         * gets its own frame. imm = rate/sec (low 32) | burst (high 32). */
        fl = (fl & FL_FF) | (do_rate(st, c->now, imm) ? FL_ZF : 0);
        break;
    case OP_ARG: {
        /* cur = args[idx] when the host set that many args, else the inline
         * default. idx in imm bits 32..47, default in the low 32. */
        __u32 idx = (__u32) (imm >> 32) & 0xffff;
        cur = idx < p->argc ? p->args[idx & (PFW_ARGC - 1)] : (__u64) (__u32) imm;
        break;
    }
    case OP_ARGC:
        cur = p->argc;
        break;
    case OP_REDIRECT:
        /* Record the target ifindex; the actual bpf_redirect() is issued in
         * finish() on the pass path (it returns XDP_REDIRECT, which must be the
         * program's return value). imm is the ifindex. */
        st->redirect_if = (__u32) imm;
        break;
    default:
        st->verdict = V_PASS;
        faults++;
        return 1;
    }
    st->r[R_CUR] = cur;
    st->flags = fl;
    st->pc = next;
    return st->verdict ? 1 : 0;
}

#endif /* PFW_INTERP_H */
