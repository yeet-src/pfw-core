/* pfw: shared state — control/counter globals, the BPF maps, the per-cpu
 * execution state, the zeroed flow template, and the tail-call program array.
 * Everything the stages and the interpreter read or write in common lives here.
 */
#ifndef PFW_MAPS_H
#define PFW_MAPS_H

#include "core/common.h"

/* Modular link mode. One unit defines the maps and globals (it does
 * `#define PFW_MAPS_DEFINE` before including this); every other unit gets
 * `extern` declarations and the BPF static linker (bpftool gen object) resolves
 * them to the single definition. Define-everywhere would make the linker reject
 * the duplicate map symbols. */
#ifdef PFW_MAPS_DEFINE
#  define PFW_LINK
#else
#  define PFW_LINK extern
#endif

/* ---- control and counters, read and patched from the host ---------------- */

/* Not plain `active`: vmlinux.h is generated from the build host's BTF, and some
 * kernels have an enum constant of that name. */
PFW_LINK volatile __u32 active_gen;      /* the generation packets run */
PFW_LINK volatile __u32 shadow;          /* 1 = shadow mode: enforcement verdicts are logged/counted but the packet passes */
PFW_LINK volatile __u64 nat_reversed; /* reply packets whose source `dnat`'s reverse path restored */
PFW_LINK volatile __u64 src_enforced; /* packets dropped by a standing source ban */
PFW_LINK volatile __u64 seen, ran, passed, dropped, rsts, bans, enforced, faults, logged, ring_full, shadowed;
/* Reassembly accounting (reasm-mode programs): segments skipped as
 * retransmits, forward-gap resyncs, flows joined mid-stream (fail closed),
 * and segments that overran the reassembly buffer (fail closed). */
PFW_LINK volatile __u64 reasm_retrans, reasm_gaps, reasm_midjoin, reasm_over;
/* reasm_slid: times a window slid forward to keep following a long stream;
 * reasm_held: out-of-order segments beyond the window, dropped so TCP resends
 * them once the window has moved; reasm_trunc: segments larger than the window
 * (only their first REASM_CAP bytes were inspected). */
PFW_LINK volatile __u64 reasm_slid, reasm_held, reasm_trunc;
/* decode h2: header blocks decoded, connections matched raw (no h2 preface),
 * references the kept dynamic table could not resolve (shown as "?"), decoded
 * views truncated at H2_CAP, and connections reset because they could not be
 * followed (malformed, a header block larger than the window, a lost table). */
PFW_LINK volatile __u64 h2_blocks, h2_raw, h2_unresolved, h2_trunc, h2_failed;

/* Per-packet decision time: total nanoseconds spent evaluating the
 * program (summed over `ran` packets) and a histogram of it. The bucket
 * bounds, in ns, are mirrored on the host. */
PFW_LINK volatile __u64 decide_ns;
/* decide_hist: the decision-time histogram, one slot per bucket (bounds
 * are DECIDE_BOUNDS in pfw.h, the last bucket is +inf). A per-CPU array
 * rather than a global: every CPU counts in its own slot with no shared
 * cache line, and the host sums the slots when it scrapes. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DECIDE_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} decide_hist SEC(".maps");

/* rule_time: the same clock, split by rule. A packet's decision time goes to
 * the last rule it touched — a `count`, or the rule of its verdict — and to
 * rule 0 if it touched none. The global mean is dominated by packets that leave
 * at the first port check; this is what the path that reached a rule cost. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PFW_NRULES);
    __type(key, __u32);
    __type(value, struct rule_time);
} rule_time SEC(".maps");

#define DECIDE_COUNT_ONE(n) +1
_Static_assert((0 DECIDE_BOUNDS(DECIDE_COUNT_ONE)) == DECIDE_BUCKETS - 1, "DECIDE_BOUNDS must list DECIDE_BUCKETS - 1 bounds");
_Static_assert((DECIDE_BUCKETS & (DECIDE_BUCKETS - 1)) == 0, "DECIDE_BUCKETS must be a power of two: the index is masked");
PFW_LINK volatile __u64 scanned_bytes;  /* bytes the automaton walked (L7 inspection volume) */
PFW_LINK volatile __u64 flows_created;  /* flow-table entries opened (connection tracking rate) */

/* ---- maps ---------------------------------------------------------------- */

PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFW_GENS);
    __type(key, __u32);
    __type(value, struct pfw_prog);
} programs SEC(".maps");

PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFW_GENS * AC_STATES * 256);
    __type(key, __u32);
    __type(value, __u16);
} ac_goto SEC(".maps");

PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFW_GENS * AC_STATES);
    __type(key, __u32);
    __type(value, __u16);
} ac_fail SEC(".maps");

PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFW_GENS * AC_STATES);
    __type(key, __u32);
    __type(value, __u64);
} ac_accept SEC(".maps");

PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow);
} flows SEC(".maps");

/* Per-source state (struct source), keyed on the source address: the source ban
 * and src.state / src.count / src.rate. LRU, so a flood of spoofed sources
 * evicts the coldest entries instead of filling the table. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SRC_MAX);
    __type(key, struct src_key);
    __type(value, struct source);
} sources SEC(".maps");

/* Connections diverted by `dnat`, keyed by the reply tuple, so the entry can
 * translate the reply's source back (action/nat.h). */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, NAT_MAX);
    __type(key, struct nat_key);
    __type(value, struct nat_val);
} nat SEC(".maps");

PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PFW_NRULES);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* The event struct is only reached through the ring's void *, so it
 * needs an anchor or it never makes it into the object's BTF. */
__attribute__((used)) static const struct pfw_event __pfw_event_anchor;

/* console() messages go on their own ring (typed pfw_console), so enforcement
 * events stay lean and the host reads args by field instead of unpacking bytes. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} console_ring SEC(".maps");
__attribute__((used)) static const struct pfw_console __pfw_console_anchor;

/* emit() events, on a ring of their own: typed pfw_emit records, small enough
 * that a program can report every connection it sees. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} emits SEC(".maps");
__attribute__((used)) static const struct pfw_emit __pfw_emit_anchor;

/* sample() copies of frames, for the host: a capture, an IDS feed, a look at
 * what a rule is matching. XDP cannot clone a packet to another interface, so
 * this is how traffic is mirrored — to userspace, which can send it on. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} samples SEC(".maps");
__attribute__((used)) static const struct pfw_sample __pfw_sample_anchor;
PFW_LINK volatile __u64 sampled; /* frames copied to the samples ring */

/* The VM data stack (push/pop), one struct vmstack per CPU. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vmstack);
} stack SEC(".maps");

/* Live control values the host sets at any time, read per-packet by OP_KNOB
 * (`knob("name")`). One shared value per slot (not percpu); the host maps a name
 * to a slot at compile time and writes knobs[slot] whenever it wants. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFW_KNOBS);
    __type(key, __u32);
    __type(value, __u64);
} knobs SEC(".maps");

/* Host-loaded lookup tables, read by OP_TLOAD (`NAME[i]`). One flat array of
 * u64 cells per generation; the compiler gives each declared table a base and
 * a size within it. Per generation, like the automaton, because a table's
 * place is the program's to decide: apply() lays the next program's tables out
 * in the idle half and they come into force with the flip, whole. The host
 * rewrites cells of the live half whenever it likes. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFW_GENS * TABLE_CELLS);
    __type(key, __u32);
    __type(value, __u64);
} tables SEC(".maps");

/* Live host-set string knobs: the needle OP_KNOBHAS searches for in the payload. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFW_KNOBSTRS);
    __type(key, __u32);
    __type(value, struct knob_str);
} knob_strs SEC(".maps");

struct pfw_state {
    __u64 r[NREGS];
    __u32 pc;
    __u32 flags;
    __u32 verdict;
    __u32 rule;
    __u32 ttl;
    __u32 fh_src, fh_dst; /* the source and destination addresses folded to 32 bits, for OP_FHASH */
    __u32 time_rule; /* the last rule this packet touched (count or verdict): who its decision time is charged to */
    __u32 set_mark;
    __u32 set_state; /* 1 = write new_state to the flow */
    __u32 new_state;
    __u32 state_ttl; /* seconds the new state stays valid (0 = forever) */
    /* The flow's registers, loaded at entry and written back if the program
     * stored to one; and its byte and packet counts, this packet included.
     * want_acct asks for a flow entry to be made so the counts have somewhere
     * to live (a flow the program never asks about is not tracked for it). */
    __u64 ureg[FLOW_REGS];
    __u64 fbytes, fpackets;
    __u32 set_ureg, want_acct;
    __u32 hits;      /* running per-connection hit count during this packet */
    __u32 set_hits;  /* 1 = write hits back to the flow */
    __u32 log_len;
    __u32 log_off;
    __u32 ac_state;
    __u32 nocase;
    __u32 mpos[PFW_MAX_PATS];
    __u8 buf[SCAN_CAP];
    __u8 dec[REASM_CAP];   /* decoded plaintext view (DECODE_H2), what the program scans */
    __u32 dec_len;
    /* Transform (DECODE_HUFFMAN) state, kept here — not in the loop's stack ctx —
     * so each iteration reloads it through the map and the verifier launders its
     * precision, the way ac_step carries the automaton state in ac_state. A
     * data-dependent state on the stack explodes the state budget. */
    __u32 huff_state;
    __u32 huff_outpos;
    __u32 huff_fail;
    __u32 tf_table; /* DECODE_TRANSFORM: active tt_cells table id, set by the entry */
    /* What a decode stage hands the matcher: the decoded plaintext the program
     * scans in place of the raw stream (REASM_CAP bytes, like the stream window,
     * so the same masked reads serve both). */
    __u8 view[REASM_CAP];
    /* DECODE_H2 work area. h2a holds the header block (frames -> HPACK input),
     * h2b the intermediate between the HPACK and resolve stages (Huffman output
     * can be larger than its input, hence H2_CAP); the resolved "name: value\n"
     * lines land in `view`. All the
     * evolving cursors live here, in the map, and are reloaded on every loop
     * iteration, so the verifier does not track them precisely (see transform.h). */
    __u8 h2a[REASM_CAP];
    __u8 h2b[H2_CAP];
    struct h2_work {
        /* frames */
        __u32 pos, consumed, hb_len, hb_done, in_hdr, done, fail, rst, skip;
        /* hpack */
        __u32 phase, target, kind, val, shift, strings_left, huff, str_rem, lenpos, slen, out, hstate;
        /* resolve */
        __u32 rphase, rkind, ridx, rstrings, rlo, rrem, text, ins, slot, spos, nlen;
    } h2;
    /* Deferred packet-rewrite requests recorded by OP_REDACT/REPLACE; applied
     * after matching by the pfw_rewrite tail-call stage (its own verifier budget).
     * Each: match pattern, replacement pattern (replace) / fill byte (redact),
     * mode, and the cursor at the op (the window start). */
    __u32 rw_n;
    /* is_re: pat is a regex accept-bit, matched by the regex DFA with a fixed
     * span length rlen (vs. a literal Aho-Corasick pattern). */
    struct { __u32 pat, repl, mode, fill, woff, is_re, rlen; } rw[RW_MAX];
    __u32 redirect_if; /* OP_REDIRECT target ifindex; 0 = no redirect (ifindex 0 is never valid) */
    __u64 rl_tokens;   /* OP_RATE token bucket (scaled x RL_SCALE), loaded from / written back to the flow */
    __u64 rl_ts;       /* OP_RATE last-refill ktime ns */
    __u32 set_rl;      /* 1 = write rl_tokens/rl_ts back to the flow */
    /* The source-scoped twins (SCOPE_SRC), loaded from / written back to the
     * `sources` entry by match_half exactly as the flow fields are. */
    __u32 src_state; /* the source's user state at entry (what src.state reads) */
    __u32 src_set_state, src_new_state, src_state_ttl;
    __u32 src_hits, src_set_hits;
    __u32 src_set_rl;
    __u64 src_rl_tokens, src_rl_ts;
    __u64 fargs[FARGS_MAX]; /* OP_FARG numeric format-arg buffer, flushed by console()/printk() */
    __u32 fargn;
    __u8 fstr[FSTR_MAX][STRARG_CAP]; /* OP_FARGS captured %s strings */
    __u16 fslen[FSTR_MAX];
    __u32 fsn;
    __u8 kbuf[KNOB_SCAN]; /* OP_KNOBHAS: the payload window loaded for the string search */
    /* The ring of a flow that has no entry yet. A flow is created at write-back,
     * after the program ran, so its first packet has nowhere to push: the ring
     * ops work on this instead, and it becomes the flow's ring when the entry is
     * made (pring_count != 0 is also what asks for the entry to be made). */
    __u32 pring[RING_CAP];
    __u32 pring_head;
    __u32 pring_count;
    /* Scratch a step hands to its inner bpf_loop (see struct pfw_ctx). */
    __u32 x_scan_off; /* frame offset of buf[0] during a scan */
    __u32 x_scan_len;
    __u32 x_byte;     /* findb / skipb: the byte wanted */
    __u32 x_pat;      /* cmpstr: the pattern index */
    __u32 x_eq;       /* cmpstr: still equal */
    __u32 x_count;    /* skipb: bytes skipped */
    __u32 x_re[RE_GROUPS]; /* scan: each regex DFA's current state, carried across bytes */
};

PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pfw_state);
} state SEC(".maps");

/* Host-loaded transform-table cells, flat like ac_goto: key is
 * table_id * TT_CELLS + (state * 16 + nibble). A per-cell array map (not one
 * big value indexed by a variable offset) is what lets pfw_transform's decode
 * loop verify over a full window — the same reason the automaton lives here. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TT_NTABLES * TT_CELLS);
    __type(key, __u32);
    __type(value, __u32);
} tt_cells SEC(".maps");

/* IPv4 CIDR set for `src in set` (P5, set form): one host-loaded LPM trie,
 * longest-prefix match. Key is {prefixlen, 4 address bytes (network order)}. */
struct lpm_key { __u32 prefixlen; __u8 data[4]; };
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAX);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm SEC(".maps");

/* IPv6 CIDR set for `src6 in set6`: one host-loaded LPM trie over 16-byte
 * addresses (network order), longest-prefix match. */
struct lpm6_key { __u32 prefixlen; __u8 data[16]; };
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM6_MAX);
    __type(key, struct lpm6_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm6 SEC(".maps");

/* Exact-set membership for `x in hash`: a host-loaded set of u32 keys (ports,
 * 32-bit hashes/fingerprints, …). Value is unused (presence is the answer). */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASH_MAX);
    __type(key, __u32);
    __type(value, __u32);
} hashset SEC(".maps");

/* A host-loaded map from a 64-bit key to a 64-bit value, read by OP_KVGET
 * (`lookup(key)`): where `hashset` says whether a key is known, this says what
 * goes with it — the tenant behind an API key, the policy for a port. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KV_MAX);
    __type(key, __u64);
    __type(value, __u64);
} kv SEC(".maps");

/* Probabilistic membership for `x in bloom`: a host-loaded Bloom filter of u32
 * values, for very large sets where an exact hash would be too big (may yield
 * false positives, never false negatives). No key; map_extra = hash functions. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, BLOOM_MAX);
    __type(value, __u32);
    __uint(map_extra, BLOOM_HASHES);
} bloom SEC(".maps");

/* Regex DFA (fuzzy matching): a complete transition table (re_goto, key =
 * gen*RE_STATES*256 + state*256 + byte -> next state) and a per-state accept
 * bitmask (re_accept). The host builds these from `regex` patterns; the scan's
 * OP_RESCAN walks them one byte per step, ORing accept bits into %m. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFW_GENS * RE_STATES * 256);
    __type(key, __u32);
    __type(value, __u16);
} re_goto SEC(".maps");

PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFW_GENS * RE_STATES);
    __type(key, __u32);
    __type(value, __u64);
} re_accept SEC(".maps");

/* HPACK dynamic tables, one per decoded HTTP/2 connection (struct h2conn). A
 * separate map from `flows` so only h2 connections pay for a table. */
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, H2_CONNS);
    __type(key, struct flow_key);
    __type(value, struct h2conn);
} h2conns SEC(".maps");
PFW_LINK const struct h2conn zero_h2conn;

/* A zeroed flow lives in rodata, not on the 512-byte BPF stack: the flow
 * struct now carries a REASM_CAP buffer and will not fit as a local. */
PFW_LINK const struct flow zero_flow;

/* Tail-call targets: the entry (pfw_xdp) reassembles, then tail-calls the
 * decoder (which decodes and tail-calls the matcher) or the matcher directly.
 * Splitting decode and match into separate programs keeps each within the
 * verifier's per-program budget. Slots are populated by the host before the
 * entry is attached. */
#define SLOT_DECODE    0
#define SLOT_MATCH     1
#define SLOT_RESOLVE   2
#define SLOT_HUFF      3
#define SLOT_TRANSFORM 4
#define SLOT_REWRITE   5
#define SLOT_HPACK     6
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 7);
    __type(key, __u32);
    __type(value, __u32);
} decode_jmp SEC(".maps");

#endif /* PFW_MAPS_H */
