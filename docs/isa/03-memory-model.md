# 3. Memory model

### Packet reads

Reads are unrestricted up to `%end`. `load` reads 1/2/4/8 bytes at `%cur + imm`,
little- or big-endian; out of bounds sets `FF` and leaves `%cur` unchanged.
`scan`/`findb`/`cmpstr`/`skipb` read a bounded window starting at `%cur`; the
window never crosses `%end` and is clamped (`scan`/`findb` to `SCAN_CAP = 4096`,
`cmpstr` to `PFW_PAT_CAP = 256`, `skipb` to `SKIP_CAP = 64`). The kernel copies the window into
`st->buf` via `window()` and matches over that; in reassembly mode the bytes come
from the flow's `reasm` buffer instead of the wire.

Packet **writes** are only the deliberate rewrite ops — `redact`/`replace`
(recorded, applied by the rewrite stage) and `dnat` — each with checksum fixup.

### Scratch

`%s0`–`%s39` are forty general registers; the compilers allocate `let` locals
and their own temporaries onto them by live range (so more than forty live at
once is a compile error, and the error says what holds each).

### The data stack

A per-CPU `struct vmstack { u64 s[STACK_CAP]; }` (`STACK_CAP = 256`) in the
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
| `reasm*`, `filled`, `synned` | reassembly mode | a sliding `REASM_CAP = 4096`-byte window over the TCP stream (below) |
| `h2_mode`, `h2_skip`, `h2_ins`, `h2_new` | `decode h2` | frame-parsing state (§8) |

State **writes are deferred**: a `flow.state = N` (etc.) is written back after the
program finishes, so it is visible on the *next* packet, not the one that set it.
The reference interpreter models this exactly.

### Per-source state

Keyed on the source address alone (`struct src_key`: `addr[16]`, `family`) in the
`sources` LRU hash (`SRC_MAX = 262144`). A flow entry dies with its 4-tuple; a
source entry survives a reconnect from a new port. Each `struct source` carries:

| field | op surface | meaning |
|---|---|---|
| `mark`, `rule`, `expires` | `ban` | the source ban: every packet from the address is dropped at the entry, on any port or protocol, until the TTL |
| `user_state`, `state_expires` | `src.state` (`sload`/`sstore`, source scope) | a per-source state with a TTL |
| `hits` | `src.count` (`bump`, source scope) | per-source hit counter |
| `rl_tokens`, `rl_ts` | `src.rate` (`rate`, source scope) | one token bucket per source |

These are the per-flow ops with the scope operand set (`reg = SCOPE_SRC` for
`sload`/`bump`/`rate`, bit 32 of `imm` for `sstore`); writes are deferred the
same way. An address is easy to spoof on a connectionless protocol: per-source
state is only as trustworthy as the source address.

### TCP reassembly

In reassembly mode each segment is placed at its sequence offset in the flow's
window, first-wins on overlap (the Linux policy), and the program inspects the
contiguous prefix. The window **slides**: when the next in-order segment does not
fit, the window shifts forward to make room, keeping the last `REASM_KEEP = 256`
bytes (the maximum pattern length) so a pattern straddling the edge is still seen
whole. A connection is therefore followed for its whole life.

| situation | behaviour |
|---|---|
| out-of-order segment inside the window | placed; inspected once the gap fills |
| out-of-order segment beyond the window | **dropped**, not reset — the sender retransmits it after the window has moved (`reasm_held`) |
| a flow first seen mid-stream (no SYN: open before the program was, or dropped from the table) | followed from that segment on, and counted (`reasm_midjoin`); reset if the program decodes, since a decode cannot begin part-way |
| one segment larger than the window (loopback and jumbo frames carry up to 64 kB) | read whole, `REASM_CHUNK` bytes at a time: the program runs over each piece in turn (`pfw_continue`), and the packet passes only if every piece does. A decode spends several tail calls a piece, so past about 20 kB a decoded connection is reset instead (`reasm_over`) |
| a FIN segment carrying data | inspected like any other |

`decode h2` connections do not slide here; the h2 stage consumes whole frames
itself (§8).

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
| `programs[gen].fmts[]` | `printk` | in `pfw_prog` | in-kernel format strings (`PFW_FMTS = 16` × `PFW_FMT_CAP = 64`) |

---
