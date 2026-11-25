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
#include "action/event.h"   /* console_emit */
#include "action/nat.h"     /* do_dnat */

/* Token-bucket rate limiter over the flow's rl_tokens/rl_ts (carried in st,
 * written back to the flow in finish()). Tokens are fixed-point x RL_SCALE.
 * Refill = elapsed_ns * rate / (1e9 / RL_SCALE) = elapsed_ns * rate / 1000,
 * which avoids both floats and overflow for sane rates. Returns 1 when the
 * packet is OVER the limit (no token to spend), 0 when allowed. __noinline so
 * the 64-bit math stays out of pfw_step's stack frame. */
static __noinline int do_rate(struct pfw_state *st, __u64 now, __u64 imm, __u32 scope)
{
    __u64 ts = scope == SCOPE_SRC ? st->src_rl_ts : st->rl_ts;
    __u64 have = scope == SCOPE_SRC ? st->src_rl_tokens : st->rl_tokens;
    int over = 0;
    __u64 rate = (__u32) imm;                 /* tokens per second */
    __u64 cap = (__u32) (imm >> 32) * RL_SCALE; /* bucket capacity, scaled */
    __u64 tokens;
    if (ts == 0) {                            /* first sight of this flow/source: full bucket */
        tokens = cap;
    } else {
        __u64 elapsed = now > ts ? now - ts : 0;
        __u64 refill = elapsed * rate / 1000; /* ns * (tok/s) / 1000 = tokens x RL_SCALE */
        tokens = have + refill;
        if (tokens > cap) tokens = cap;
    }
    if (tokens >= RL_SCALE)                   /* spend one token: allowed */
        tokens -= RL_SCALE;
    else
        over = 1;                             /* over the limit */
    if (scope == SCOPE_SRC) { st->src_rl_ts = now; st->src_rl_tokens = tokens; st->src_set_rl = 1; }
    else { st->rl_ts = now; st->rl_tokens = tokens; st->set_rl = 1; }
    return over;
}

/* Substring search for a live host-set string knob in the payload window.
 * Loads up to KNOB_SCAN payload bytes into st->kbuf once, then checks each start
 * position for the needle (knob_strs[slot], length L<=KNOBSTR_CAP) with an
 * unrolled, length-masked compare. __noinline so it keeps its own stack frame.
 * Returns 1 if found. Non-reasm (reads the packet). */
/* The window's length and the result ride in the per-CPU state (x_kn,
 * x_kfound), not here: this frame is one of a chain the verifier adds up, a
 * frame at a time and each rounded up to 32 bytes on kernels before 6.8, and
 * the chain has to come in under 512. */
struct khas_ctx { struct pfw_state *st; const struct knob_str *ns; };
static long khas_step(__u32 i, void *ctx_)
{
    struct khas_ctx *c = ctx_;
    __u32 L = c->ns->len;
    if (i + L > c->st->x_kn)
        return 1;                        /* no room for the needle from here on */
    int eq = 1;
#pragma unroll
    for (int j = 0; j < KNOBSTR_CAP; j++) {
        if ((__u32) j >= L) break;
        if (c->st->kbuf[(i + j) & (KNOB_SCAN - 1)] != c->ns->b[j & (KNOBSTR_CAP - 1)]) { eq = 0; break; }
    }
    if (eq) { c->st->x_kfound = 1; return 1; }
    return 0;
}
static __noinline int do_knobhas(struct pfw_ctx *pc, __u32 slot)
{
    struct pfw_state *st = pc->st;
    __u32 k = slot & (PFW_KNOBSTRS - 1);
    const struct knob_str *ns = bpf_map_lookup_elem(&knob_strs, &k);
    if (!ns || ns->len == 0 || ns->len > KNOBSTR_CAP || pc->reasm)
        return 0;
    __u32 end = (__u32) st->r[R_END], off = (__u32) st->r[R_PAYLOAD];
    if (off >= end)
        return 0;
    __u32 n = end - off;
    if (n > KNOB_SCAN) n = KNOB_SCAN;
    if (n < ns->len)
        return 0;
    __u32 ln = ((n - 1) & (KNOB_SCAN - 1)) + 1;   /* [1, KNOB_SCAN] for the load */
    if (bpf_xdp_load_bytes(pc->xdp, off, st->kbuf, ln))
        return 0;
    struct khas_ctx c = { .st = st, .ns = ns };
    st->x_kn = n;
    st->x_kfound = 0;
    bpf_loop(n, khas_step, &c, 0);
    return st->x_kfound;
}

/* The flow hash (OP_FHASH): the two addresses, folded to 32 bits each at the
 * entry, with the ports and the protocol, through the murmur3 finaliser. The
 * same packet hashes the same on every host and in the reference interpreter
 * (flowHash in src/interp.js): a table built on the host from this hash is
 * indexed the same way in the kernel. Not keyed: it spreads, it does not hide. */
static __always_inline __u32 fh_mix(__u32 h)
{
    h ^= h >> 16; h *= 0x85ebca6bu; h ^= h >> 13; h *= 0xc2b2ae35u; h ^= h >> 16;
    return h;
}
static __always_inline __u32 flow_hash(const struct pfw_state *st)
{
    __u32 h = fh_mix(st->fh_src);
    h = fh_mix(h ^ st->fh_dst);
    h = fh_mix(h ^ (((__u32) st->r[R_SPORT] << 16) | ((__u32) st->r[R_DPORT] & 0xffff)));
    return fh_mix(h ^ (__u32) st->r[R_PROTO]);
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
    __u32 opk = PFW_MASK(p->ops_base + pc, OPS_POOL);
    struct pfw_op *op = bpf_map_lookup_elem(&ops, &opk);
    if (!op)
        return 1;
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
    case OP_MUL_I:
        cur *= imm;
        break;
    case OP_MUL_R:
        cur *= st->r[reg];
        break;
    case OP_MOD_I:
    case OP_MOD_R: {
        /* No trap to take: a zero divisor leaves 0 and the fault flag. */
        __u64 d = code == OP_MOD_I ? imm : st->r[reg];
        if (d) cur %= d;
        else { cur = 0; fl |= FL_FF; }
        break;
    }
    case OP_FHASH:
        cur = flow_hash(st);
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
        /* reg bit 0 = a fresh scan (`within`): the mask and the automaton start
         * empty, so the result is exactly what lies in this window — not what an
         * earlier scan, or an earlier segment of the connection, already found. */
        if (op->reg & 1) { st->ac_state = 0; st->r[R_M] = 0; }
        __u32 n = window(c, cur, (__u32) (PFW_CLAMP(imm, SCAN_CAP)));
        if (n) {
            scanned_bytes += n;
            st->x_scan_off = (__u32) cur;
            st->x_scan_len = n;
            /* ac_step also walks the regex DFAs, each from its own start */
            st->x_re[0] = p->re_start[0];
            st->x_re[1] = p->re_start[1];
            st->x_re[2] = p->re_start[2];
            st->x_re[3] = p->re_start[3];
            bpf_loop(n, ac_step, c, 0);
        }
        break;
    }
    case OP_MPOS: {
        __u32 pos = st->mpos[op->reg & (PFW_MAX_PATS - 1)] /* a pattern id (6 bits), not a register index */;
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
        st->x_eq = n == len;
        if (st->x_eq) {
            st->x_scan_len = n;
            st->x_pat = pi;
            bpf_loop(n, cmpstr_step, c, 0);
        }
        fl = (fl & FL_FF) | (st->x_eq ? FL_ZF : 0);
        break;
    }
    case OP_FINDB: {
        __u32 n = window(c, cur, (__u32) (PFW_CLAMP(imm, SCAN_CAP)));
        fl |= FL_FF; /* cleared by the step that finds it */
        st->flags = fl;
        if (n) {
            st->x_scan_off = (__u32) cur;
            st->x_scan_len = n;
            st->x_byte = op->reg & 0xff;
            bpf_loop(n, findb_step, c, 0);
        }
        /* findb_step wrote the cursor and the flags itself */
        st->pc = next;
        return 0;
    }
    case OP_SKIPB: {
        __u32 n = window(c, cur, (__u32) (imm == 0 || imm > SKIP_CAP ? SKIP_CAP : imm));
        st->x_count = 0;
        if (n) {
            st->x_scan_len = n;
            st->x_byte = op->reg & 0xff;
            bpf_loop(n, skipb_step, c, 0);
        }
        cur += st->x_count;
        break;
    }
    case OP_PASS:
        st->verdict = V_PASS;
        break;
    case OP_DROP:
        st->verdict = V_DROP;
        st->rule = PFW_MASK(p->rule_base + (op->reg & (PFW_NRULES - 1)), RULE_POOL);
        st->time_rule = st->rule;
        break;
    case OP_COUNT: {
        __u32 key = PFW_MASK(p->rule_base + (op->reg & (PFW_NRULES - 1)), RULE_POOL);
        __u64 *n = bpf_map_lookup_elem(&counters, &key);
        if (n)
            (*n)++;
        st->time_rule = key;
        break;
    }
    case OP_LOG:
        st->log_len = (__u32) (PFW_CLAMP(imm, LOG_CAP));
        st->log_off = (__u32) cur;
        break;
    case OP_BAN:
        st->verdict = V_BAN;
        st->rule = PFW_MASK(p->rule_base + (op->reg & (PFW_NRULES - 1)), RULE_POOL);
        st->time_rule = st->rule;
        st->ttl = (__u32) imm;
        st->set_mark = MARK_DROP;
        break;
    case OP_RST:
        st->verdict = V_RST;
        st->rule = PFW_MASK(p->rule_base + (op->reg & (PFW_NRULES - 1)), RULE_POOL);
        st->time_rule = st->rule;
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
        cur = op->reg == SCOPE_SRC ? st->src_state : c->user_state;
        break;
    case OP_SSTORE:
        /* op->reg is the TTL in seconds (unmasked); the scope rides in imm bit 32. */
        if ((imm >> 32) & 1) {
            st->src_new_state = (__u32) imm;
            st->src_set_state = 1;
            st->src_state_ttl = op->reg;
        } else {
            st->new_state = (__u32) imm;
            st->set_state = 1;
            st->state_ttl = op->reg;
        }
        break;
    case OP_FLOAD: {
        __u32 which = op->reg & 7;
        if (which == FF_BYTES) { cur = st->fbytes; st->want_acct = 1; }
        else if (which == FF_PACKETS) { cur = st->fpackets; st->want_acct = 1; }
        else cur = st->ureg[which & (FLOW_REGS - 1)];
        break;
    }
    case OP_FSTORE:
        /* Unlike flow.state, a store is seen by a later read in the same run. */
        st->ureg[op->reg & (FLOW_REGS - 1)] = cur;
        st->set_ureg = 1;
        break;
    case OP_BUMP:
        if (op->reg == SCOPE_SRC) {
            st->src_hits++;
            st->src_set_hits = 1;
            cur = st->src_hits;
        } else {
            st->hits++;
            st->set_hits = 1;
            cur = st->hits;
        }
        break;
    case OP_RPUSH:
        /* Push cur onto the flow's ring (newest at head), written straight to
         * the flow value, like the ring is read. A flow with no entry yet (its
         * first packet) pushes to st->pring, which the write-back turns into the
         * new entry's ring. */
        if (c->fp) {
            __u32 h = c->fp->ring_head & (RING_CAP - 1);
            c->fp->ring[h] = (__u32) cur;
            c->fp->ring_head = (h + 1) & (RING_CAP - 1);
            if (c->fp->ring_count < RING_CAP)
                c->fp->ring_count++;
        } else {
            __u32 h = st->pring_head & (RING_CAP - 1);
            st->pring[h] = (__u32) cur;
            st->pring_head = (h + 1) & (RING_CAP - 1);
            if (st->pring_count < RING_CAP)
                st->pring_count++;
        }
        break;
    case OP_RGET: {
        /* cur = the (cur)-th most recent entry, 0 = newest. Out of range yields
         * 0 and faults, so `jf` can tell absent from a stored 0. */
        __u32 idx = (__u32) cur;
        if (c->fp && idx < c->fp->ring_count) {
            __u32 slot = (c->fp->ring_head - 1 - idx) & (RING_CAP - 1);
            cur = c->fp->ring[slot];
        } else if (!c->fp && idx < st->pring_count) {
            __u32 slot = (st->pring_head - 1 - idx) & (RING_CAP - 1);
            cur = st->pring[slot];
        } else {
            cur = 0;
            fl |= FL_FF;
        }
        break;
    }
    case OP_RLEN:
        cur = c->fp ? c->fp->ring_count : st->pring_count;
        break;
    case OP_REDACT:
    case OP_REPLACE:
        /* Wire rewrite is per-packet only (in reasm mode the matcher reads a
         * reconstructed buffer, not the packet). Record the request; the
         * pfw_rewrite tail-call stage applies it after matching, in its own
         * verifier budget. */
        if (!c->reasm && st->rw_n < RW_MAX) {
            __u32 k = st->rw_n & (RW_MAX - 1);
            st->rw[k].pat = op->reg & (PFW_MAX_PATS - 1);   /* literal pat id or regex accept-bit */
            st->rw[k].is_re = (op->reg >> 15) & 1;           /* reg bit 15 = regex */
            st->rw[k].rlen = (__u32) ((imm >> 8) & 0x1ff);   /* fixed match length (regex only): 9 bits, as PFW_PAT_CAP is 256 */
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
        if (!c->reasm) {
            /* reg bit 0: the target was computed (a knob, a table cell) and is in
             * the cursor. A computed address of 0 is "nowhere", not 0.0.0.0: an
             * unset knob or an empty slot leaves the packet where it was going. */
            if (!(op->reg & 1)) do_dnat(c->xdp, st, imm);
            else if ((__u32) cur) do_dnat(c->xdp, st, cur);
        }
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
    case OP_KVGET: {
        /* cur = the value stored under key cur. A key that is not there yields
         * the op's default and sets the fault flag, so "absent" and "present
         * with value 0" can be told apart by whoever needs to. */
        __u64 k = cur;
        __u64 *v = bpf_map_lookup_elem(&kv, &k);
        if (v) cur = *v;
        else { cur = imm; fl |= FL_FF; }
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
        fl = (fl & FL_FF) | (do_rate(st, c->now, (op->reg & 2) ? cur : imm, op->reg & 1) ? FL_ZF : 0);
        break;
    case OP_ARG: {
        /* cur = args[idx] when the host set that many args, else the inline
         * default. idx in imm bits 32..47, default in the low 32. */
        __u32 idx = (__u32) (imm >> 32) & 0xffff;
        cur = idx < p->argc ? p->args[idx & (PFW_ARGC - 1)] : (__u64) (__u32) imm;
        break;
    }
    case OP_NOW:
        cur = c->now;
        break;
    case OP_ARGC:
        cur = p->argc;
        break;
    case OP_KNOB: { /* cur = knobs[slot] — a live host-set control value */
        __u32 slot = (__u32) imm & (PFW_KNOBS - 1);
        __u64 *v = bpf_map_lookup_elem(&knobs, &slot);
        cur = v ? *v : 0;
        break;
    }
    case OP_TLOAD: { /* cur = the declared table's cell at index cur */
        __u32 size = (__u32) (imm >> 32);
        if (cur < size) {
            __u32 k = PFW_MASK(p->tbl_base + (((__u32) imm + (__u32) cur) & (TABLE_CELLS - 1)), TABLE_POOL);
            __u64 *v = bpf_map_lookup_elem(&tables, &k);
            cur = v ? *v : 0;
        } else {
            cur = 0;        /* past the table's end: nothing there, and say so */
            fl |= FL_FF;
        }
        break;
    }
    case OP_KNOBHAS: /* ZF = the live host-set string knob occurs in the payload window */
        fl = (fl & FL_FF) | (do_knobhas(c, (__u32) imm) ? FL_ZF : 0);
        break;
    case OP_FARG: /* push cur as the next console/printk format argument */
        if (st->fargn < FARGS_MAX)
            st->fargs[st->fargn++ & (FARGS_MAX - 1)] = cur;
        break;
    case OP_FARGS: { /* capture a %s string: cur is a packet offset, copy up to STRARG_CAP bytes */
        if (st->fsn < FSTR_MAX) {
            __u32 s = st->fsn & (FSTR_MAX - 1);
            __u32 off = (__u32) cur;
            __u64 end = st->r[R_END];
            __u32 len = (__u32) imm;
            if (len > STRARG_CAP) len = STRARG_CAP;
            if (off >= end) len = 0;
            else if (off + len > end) len = (__u32) (end - off);
            __builtin_memset(st->fstr[s], 0, STRARG_CAP);
            st->fslen[s] = 0;
            if (len && !c->reasm) {   /* packet read; reasm streams aren't supported for %s */
                len = ((len - 1) & (STRARG_CAP - 1)) + 1;
                if (bpf_xdp_load_bytes(c->xdp, off, st->fstr[s], len) == 0)
                    st->fslen[s] = len;
            }
            st->fsn++;
        }
        break;
    }
    case OP_CONSOLE: /* flush the gathered args to the host as a console message */
        console_emit(c->xdp, st, (__u32) imm);
        st->fargn = 0;
        break;
    case OP_SAMPLE: /* a copy of the frame for the host */
        do_sample(c->xdp, (__u32) imm, op->reg & 0xff, st->prog_stamp);
        break;
    case OP_EMIT: /* flush the gathered numbers to the host as a typed event */
        emit_values(c->xdp, st, (__u32) imm);
        st->fargn = 0;
        break;
    case OP_PRINTK: { /* bpf_trace_printk to the kernel trace pipe (up to 3 numeric args) */
        const char *fmt = (const char *) p->fmts[(__u32) imm & (PFW_FMTS - 1)];
        __u32 n = st->fargn;
        if (n == 0) bpf_trace_printk(fmt, PFW_FMT_CAP);
        else if (n == 1) bpf_trace_printk(fmt, PFW_FMT_CAP, st->fargs[0]);
        else if (n == 2) bpf_trace_printk(fmt, PFW_FMT_CAP, st->fargs[0], st->fargs[1]);
        else bpf_trace_printk(fmt, PFW_FMT_CAP, st->fargs[0], st->fargs[1], st->fargs[2]);
        st->fargn = 0;
        break;
    }
    case OP_PUSH: { /* push cur onto the data stack (stack map), sp++ */
        __u32 z = 0;
        struct vmstack *vs = bpf_map_lookup_elem(&stack, &z);
        __u32 sp = (__u32) st->r[R_SP];
        if (vs && sp < STACK_CAP) { vs->s[sp & (STACK_CAP - 1)] = cur; st->r[R_SP] = sp + 1; }
        break;
    }
    case OP_POP: { /* sp--, cur = top of the data stack */
        __u32 z = 0;
        struct vmstack *vs = bpf_map_lookup_elem(&stack, &z);
        __u32 sp = (__u32) st->r[R_SP];
        if (vs && sp > 0) { sp--; cur = vs->s[sp & (STACK_CAP - 1)]; st->r[R_SP] = sp; }
        break;
    }
    case OP_CALL: { /* push the return pc, jump to imm (subroutine via the data stack) */
        __u32 z = 0;
        struct vmstack *vs = bpf_map_lookup_elem(&stack, &z);
        __u32 sp = (__u32) st->r[R_SP];
        if (vs && sp < STACK_CAP) { vs->s[sp & (STACK_CAP - 1)] = next; st->r[R_SP] = sp + 1; next = (__u32) imm; }
        break;
    }
    case OP_RET: { /* pop the data stack into pc (return) */
        __u32 z = 0;
        struct vmstack *vs = bpf_map_lookup_elem(&stack, &z);
        __u32 sp = (__u32) st->r[R_SP];
        if (vs && sp > 0) { sp--; next = (__u32) vs->s[sp & (STACK_CAP - 1)]; st->r[R_SP] = sp; }
        break;
    }
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
