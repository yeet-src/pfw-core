# 3. Memory model

### Packet reads

Reads are unrestricted up to `%end`. `load` reads 1/2/4/8 bytes at `%cur + imm`,
little- or big-endian; out of bounds sets `FF` and leaves `%cur` unchanged.
`scan`/`findb`/`cmpstr`/`skipb` read a bounded window starting at `%cur`; the
window never crosses `%end` and is clamped (`scan`/`findb` to `SCAN_CAP = 2048`,
`skipb`/`cmpstr` to `PFW_PAT_CAP = 64`). The kernel copies the window into
`st->buf` via `window()` and matches over that; in reassembly mode the bytes come
from the flow's `reasm` buffer instead of the wire.

Packet **writes** are only the deliberate rewrite ops — `redact`/`replace`
(recorded, applied by the rewrite stage) and `dnat` — each with checksum fixup.

### Scratch

`%s0`–`%s7` are eight general registers; the compilers allocate `let` locals onto
them by live range (so more than eight live locals is a compile error).

### The data stack

A per-CPU `struct vmstack { u64 s[STACK_CAP]; }` (`STACK_CAP = 64`) in the
`stack` map, indexed by `%sp`. `push` stores `%cur` and increments `%sp`; `pop`
decrements `%sp` and loads `%cur`. `%bp` is a free register for marking a frame
(`%bp = %sp`) and unwinding (`%sp = %bp`). `call`/`ret` use the **same** stack for
return addresses, so a subroutine must keep it balanced across a call. Depth is
capped at 64; `push` past the top and `pop`/`ret` below the bottom are no-ops.

### Per-flow state

Keyed on the 5-tuple `struct flow_key` (`saddr[16]`, `daddr[16]`, `sport`,
`dport`, `proto`, `family`) in the `flows` LRU hash (`MAX_FLOWS = 16384`). Each
`struct flow` carries:

| field | op surface | meaning |
|---|---|---|
| `mark`, `rule`, `expires` | `ban`/`rst`/`mark`, `flow` | enforcement mark + TTL (enforced on later packets at the entry fast path) |
| `user_state`, `state_expires` | `flow.state` (`sload`/`sstore`) | a program state machine with a TTL |
| `hits` | `flow.count` (`bump`) | per-connection hit counter |
| `rl_tokens`, `rl_ts` | `rate` | token-bucket state |
| `ring[16]`, `ring_head`, `ring_count` | `ring.push/get/len` (`rpush`/`rget`/`rlen`) | newest-wins ring (`RING_CAP = 16`) |
| `ac_state`, `mask`, `gen` | `scan` / `%m` | automaton state carried across TCP segments |
| `reasm*`, `filled`, `synned` | reassembly mode | contiguous-prefix TCP reassembly (`REASM_CAP = 2048`) |

State **writes are deferred**: a `flow.state = N` (etc.) is written back after the
program finishes, so it is visible on the *next* packet, not the one that set it.
The reference interpreter models this exactly.

### Host-loaded lookup maps

Written by the loader, read by instructions:

| map | op | type | key → value |
|---|---|---|---|
| `lpm` | `lpm` (`src in set`) | `LPM_TRIE` | `{prefixlen, u8[4]}` (net order) → u32 |
| `lpm6` | `lpm6` (`src6 in set6`) | `LPM_TRIE` | `{prefixlen, u8[16]}` → u32 |
| `hashset` | `hash` (`x in hash`) | `HASH` | u32 → u32 (presence) |
| `bloom` | `bloom` (`x in bloom`) | `BLOOM_FILTER` | u32 value, `map_extra = 5` hashes |
| `ac_goto`/`ac_fail`/`ac_accept` | `scan` | `ARRAY` | Aho-Corasick automaton (per gen) |
| `re_goto`/`re_accept` | `scan` (regex) | `ARRAY` | regex DFA table + accept masks (per gen) |
| `tt_cells` | `decode transform` | `ARRAY` | byte-transform tables (`TT_NTABLES = 8`) |
| `programs[gen].args[]` | `arg`/`argc` | in `pfw_prog` | runtime scalar params (`PFW_ARGC = 16`) |
| `programs[gen].fmts[]` | `printk` | in `pfw_prog` | in-kernel format strings (`PFW_FMTS = 8` × `PFW_FMT_CAP = 64`) |

---
