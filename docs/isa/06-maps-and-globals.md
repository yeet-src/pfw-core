# 6. Maps and globals

| map | type | key → value | purpose |
|---|---|---|---|
| `programs` | ARRAY (2) | u32 → `pfw_prog` | the program, per generation |
| `ac_goto` | ARRAY | u32 → u16 | AC goto table (`gen·AC_STATES·256 + state·256 + byte`) |
| `ac_fail` | ARRAY | u32 → u16 | AC failure links |
| `ac_accept` | ARRAY | u32 → u64 | AC per-state accept bitmask |
| `re_goto` | ARRAY | u32 → u16 | regex DFA transitions |
| `re_accept` | ARRAY | u32 → u64 | regex DFA accept masks |
| `tt_cells` | ARRAY | u32 → u32 | loadable byte-transform tables |
| `lpm` / `lpm6` | LPM_TRIE | `lpm_key`/`lpm6_key` → u32 | `src in set` / `src6 in set6` |
| `hashset` | HASH | u32 → u32 | `x in hash` |
| `bloom` | BLOOM_FILTER | u32 value | `x in bloom` (`map_extra = 5`) |
| `flows` | LRU_HASH | `flow_key` → `flow` | connection state (`MAX_FLOWS = 16384`) |
| `knobs` | ARRAY | u32 → u64 | live numeric control values (`knob("name")`, `PFW_KNOBS = 32`) |
| `knob_strs` | ARRAY | u32 → `knob_str` | live string knobs (`kstr("name")`, `PFW_KNOBSTRS = 16`) |
| `sources` | LRU_HASH | `src_key` → `source` | per-source state and the source ban (`SRC_MAX = 65536`) |
| `nat` | LRU_HASH | `nat_key` → `nat_val` | reply path of `dnat`: reply tuple → original destination (`NAT_MAX = 16384`) |
| `h2conns` | LRU_HASH | `flow_key` → `h2conn` | `decode h2` dynamic tables (`H2_CONNS = 1024`) |
| `state` | PERCPU_ARRAY (1) | u32 → `pfw_state` | per-CPU execution state |
| `stack` | PERCPU_ARRAY (1) | u32 → `vmstack` | the data stack |
| `counters` | PERCPU_ARRAY (64) | u32 → u64 | per-rule counters |
| `decide_hist` | PERCPU_ARRAY (16) | u32 → u64 | decision-time histogram |
| `rule_time` | PERCPU_ARRAY (64) | u32 → `rule_time` | decision time by rule: `{ ns, runs }` for the packets whose last-touched rule (a `count`, or the verdict's rule) this was; rule 0 for packets that touched none |
| `events` | RINGBUF (1 MiB) | — | verdict/log events (`pfw_event`) |
| `console_ring` | RINGBUF (256 KiB) | — | `console()` messages (`pfw_console`) |
| `decode_jmp` | PROG_ARRAY (7) | u32 → prog | tail-call targets (§8) |

### Globals (in `vm.bss`, host-readable/patchable)

- `active_gen` — the generation packets run.
- `shadow` — 1 = shadow mode (enforcement is logged/counted but passed).
- Counters: `seen, ran, passed, dropped, rsts, bans, enforced, faults, logged,
  ring_full, shadowed`, the reassembly counters (`reasm_retrans, reasm_gaps,
  reasm_midjoin, reasm_over, reasm_slid, reasm_held, reasm_trunc`), the h2 counters
  (`h2_blocks, h2_raw, h2_unresolved, h2_trunc, h2_failed`), `src_enforced`,
  `nat_reversed`, `decide_ns`, `scanned_bytes`, `flows_created`.

### Event records

```c
struct pfw_event {                      // events ring
    __u64 ts; __u32 ifindex, rule, verdict, len; __u64 mask;
    __u8 family, proto; __u16 sport, dport, _pad;
    __u8 saddr[16], daddr[16], data[LOG_CAP];   // data = the log() snapshot
};
struct pfw_console {                    // console_ring
    __u64 ts; __u32 ifindex, fmtid, nnum, nstr;
    __u64 nums[FARGS_MAX];              // numeric args
    __u16 slen[FSTR_MAX]; __u8 strs[FSTR_MAX][STRARG_CAP];  // %s args
};
struct knob_str { __u32 len; __u8 b[KNOBSTR_CAP]; };  // knob_strs: a live needle
```

### The live control plane (`knobs` / `knob_strs`)

Both knob maps are **plain ARRAY** maps the host rewrites at any time — a running
program picks up the new value on the next packet, with no reload. The compiler
maps each name to a slot (`compile()` returns `knobs[slot] = name`,
`knobStrs[slot] = name`, and `knobDefaults[slot]` for a declared default); the
loader seeds defaults and writes host-supplied values into those slots.

- `knobs` — `PFW_KNOBS = 32` `__u64` slots. `OP_KNOB` reads one into `%cur`.
  Zero-initialized (unset = `0`); a `knob("x") ?? d` default is written by the
  loader, not applied at run time, so the host can still override it to `0`.
- `knob_strs` — `PFW_KNOBSTRS = 16` `struct knob_str` slots, each a length +
  `KNOBSTR_CAP = 64`-byte needle. `OP_KNOBHAS` searches it over the first
  `KNOB_SCAN = 256` payload bytes (copied into `pfw_state.kbuf`) and sets `ZF`.

---
