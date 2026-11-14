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

PFW_LINK volatile __u32 active;          /* the generation packets run */
PFW_LINK volatile __u64 seen, ran, passed, dropped, rsts, bans, enforced, faults, logged, ring_full;
/* Reassembly accounting (reasm-mode programs): segments skipped as
 * retransmits, forward-gap resyncs, flows joined mid-stream (fail closed),
 * and segments that overran the reassembly buffer (fail closed). */
PFW_LINK volatile __u64 reasm_retrans, reasm_gaps, reasm_midjoin, reasm_over;

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

struct pfw_state {
    __u64 r[NREGS];
    __u32 pc;
    __u32 flags;
    __u32 verdict;
    __u32 rule;
    __u32 ttl;
    __u32 set_mark;
    __u32 set_state; /* 1 = write new_state to the flow */
    __u32 new_state;
    __u32 state_ttl; /* seconds the new state stays valid (0 = forever) */
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
PFW_LINK struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} decode_jmp SEC(".maps");

#endif /* PFW_MAPS_H */
