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
| `state` | PERCPU_ARRAY (1) | u32 → `pfw_state` | per-CPU execution state |
| `stack` | PERCPU_ARRAY (1) | u32 → `vmstack` | the data stack |
| `counters` | PERCPU_ARRAY (64) | u32 → u64 | per-rule counters |
| `decide_hist` | PERCPU_ARRAY (16) | u32 → u64 | decision-time histogram |
| `events` | RINGBUF (1 MiB) | — | verdict/log events (`pfw_event`) |
| `console_ring` | RINGBUF (256 KiB) | — | `console()` messages (`pfw_console`) |
| `decode_jmp` | PROG_ARRAY (6) | u32 → prog | tail-call targets (§8) |

### Globals (in `vm.bss`, host-readable/patchable)

- `active` — the generation packets run.
- `shadow` — 1 = shadow mode (enforcement is logged/counted but passed).
- Counters: `seen, ran, passed, dropped, rsts, bans, enforced, faults, logged,
  ring_full, shadowed`, the reassembly counters (`reasm_retrans, reasm_gaps,
  reasm_midjoin, reasm_over`), `decide_ns`, `scanned_bytes`, `flows_created`.

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
```

---
