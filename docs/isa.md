# The pfw ISA — architecture reference

This is the authoritative reference for the pfw virtual machine: the register
file, the memory model, every instruction, the bytecode encoding, and the maps
the program runs against. It is the contract shared by the host
(`src/isa.js`, `src/interp.js`) and the kernel (`bpf/include/pfw.h`,
`bpf/include/match/interp.h`); a test (`test/node/check-isa.mjs`) asserts the two
enums agree.

Counts, verified against `src/isa.js`:

- **62 opcodes** (`OP_END = 0` … `OP_RET = 61`; `OP_COUNT_OPCODES = 62`).
- **32 physical registers** (indices `0`–`31`, `NREGS = 32`). The host register
  map has **33 names** because `%src` is an assembler alias for `%saddr`
  (both index 20).

pfw is a **forward-only cursor machine**. A program inspects one packet (or a
per-flow reassembled stream), walks a single cursor through the bytes front to
back, and reaches a verdict. It is compiled to this ISA, run on the host by a
reference interpreter, and run in the kernel by a once-verified eBPF/XDP
interpreter that reads the exact same bytecode. The design is shaped by one hard
requirement: the kernel program must pass the eBPF verifier, so **termination is
provable by construction**.

---

## 1. Machine model

### Execution

A program is an array of `struct pfw_op` in the `programs` map. The interpreter
(`pfw_step`) executes **one instruction per step**, driven by
`bpf_loop(PFW_MAX_OPS, pfw_step, …)` — so a run is **at most 8192 steps**. A step
ends the run early (returns non-zero) when:

- a verdict has been set (`st->verdict != V_NONE`),
- the program counter runs past the program (`pc >= nops` or `pc >= PFW_MAX_OPS`),
- `OP_END` or an unknown opcode is reached (both set `V_PASS`).

Each step reads the op at `pc`, executes it, and sets `pc = next` (normally
`pc + 1`; a taken jump/call/ret sets it otherwise).

### The accumulator (`%cur`)

`%cur` (register 13) is the **working accumulator**: loads land in it, arithmetic
operates on it, comparisons read it, the cursor *is* it (scan/find/pointer ops
read and advance `%cur`), and membership/rate tests read it. Most instructions
are implicitly "about `%cur`." It is 64-bit and wraps mod 2⁶⁴.

### Flags

Three 1-bit flags live in `st->flags`:

| flag | bit | meaning |
|---|---|---|
| `ZF` | `FL_ZF = 1` | zero / equal / condition-true |
| `CF` | `FL_CF = 2` | carry / unsigned less-than |
| `FF` | `FL_FF = 4` | fault (a read went out of bounds, or a lookup found nothing) |

Flag discipline:

- **Comparison / test ops** (`cmp_i`, `cmp_r`, `test`, `cidr`, `cmpstr`, `lpm`,
  `hash`, `bloom`, `lpm6`, `rate`) recompute `ZF`/`CF` from scratch but
  **preserve `FF`** (`fl = (fl & FL_FF) | …`). So each comparison clears the
  previous `ZF`/`CF`.
- **Fault producers** set `FF`: `load` (read past `%end`), `mpos` (no match),
  `findb` (byte not found), `rget` (index out of range). `FF` is *sticky* — it
  stays set until a `jf` consumes it.
- `jf` is the only consumer of `FF`: when taken, it **clears** `FF`.
- Conditional branches read the flags; they do not change them.

### The match mask (`%m`)

`%m` (register 12) is a 64-bit **bitmask of pattern matches**. `scan` runs the
Aho-Corasick automaton (and the regex DFA) over a window and ORs a bit per
matched pattern/regex into `%m`; `test $MASK` sets `ZF` from `(%m & MASK) == 0`.
Pattern *i* owns bit *i* (so at most `PFW_MAX_PATS = 64` patterns). On a TCP flow
`%m` and the automaton state persist across segments.

### Control flow and the forward-only rule

All **label** jumps go **forward**: a jump target `imm` must satisfy
`pc < imm <= PFW_MAX_OPS`. The assembler refuses a backward label, and the
interpreter fails closed (sets `V_PASS`, bumps `faults`) if a bytecode jump
violates it anyway. This is what makes loops impossible and termination trivial
for the verifier.

The **one controlled exception is `call`/`ret`.** `call` pushes the return
address (`pc + 1`) onto the data stack and sets `pc = imm` (which may be
backward — the assembler exempts `call` from the forward check); `ret` pops an
address off the data stack into `pc`. Backward control flow is therefore
possible at run time, but it is still bounded by the overall 8192-step
`bpf_loop` budget, so termination holds regardless. Repetition that isn't a
subroutine is a **compile-time unroll** (`repeat`, `frame … up to N`) with a
fixed ceiling.

### Host vs. kernel

`src/interp.js` is the executable spec; `bpf/include/match/interp.h` is the
kernel. They implement identical semantics for matching, arithmetic, flow state,
and the ring. A few ops are **kernel-only side effects** the payload-only host
model represents differently (noted per-op in §4): `dnat`/`redirect` are host
no-ops; `rate`, the membership tests, `console`, `shadow`, and the data stack are
modelled through `exec` options.

---

## 2. Registers

32 registers (`NREGS = 32`), 64-bit each, in `st->r[]`. The index is masked
`& (NREGS - 1)`, so `NREGS` must stay a power of two. Read with `mov %reg, %cur`
(`MOV_RC`); write with `mov %cur, %reg` (`MOV_CR`, which ignores a write to
`%cur`).

| idx | name(s) | role | set by |
|---|---|---|---|
| 0 | `%frame` | offset 0 of the L2 frame | entry |
| 1 | `%l3` | offset of the IP header | entry (parse) |
| 2 | `%l4` | offset of the TCP/UDP header | entry (parse) |
| 3 | `%payload` | first byte after L4 | entry (parse) |
| 4 | `%end` | one past the last readable byte | entry (parse) |
| 5 | `%proto` | IP protocol (`6` TCP, `17` UDP) | entry |
| 6 | `%sport` | source port | entry |
| 7 | `%dport` | destination port | entry |
| 8–11 | `%s0`–`%s3` | scratch / `let` locals | program |
| 12 | `%m` | match mask (scan results) | `scan` |
| 13 | `%cur` | **the cursor / accumulator** | most ops |
| 14 | `%ifindex` | ingress interface index | entry |
| 15 | `%len` | payload byte count (`end − payload`) | entry |
| 16–19 | `%s4`–`%s7` | more scratch / `let` locals | program |
| 20 | `%saddr` (`%src`) | IPv4 source, **host byte order** (0 for IPv6) | entry |
| 21 | `%shadow` | the host shadow-mode flag (read-only intent) | entry |
| 22 | `%sp` | data-stack pointer | `push`/`pop`/`call`/`ret`, writable |
| 23 | `%bp` | data-stack base pointer (frame marker) | program, writable |
| 24–30 | `%a0`–`%a6` | subroutine argument registers | caller |
| 31 | `%rv` | subroutine return-value register | callee |

Notes:

- `%src` is purely an assembler/host alias for `%saddr` (same index 20).
- At entry, `%cur` is initialised to `%payload`. In reassembly mode `%payload`,
  `%cur` are 0 and `%end`/`%len` span the reassembled prefix.
- Every register is physically writable via `MOV_CR` (except `%cur`, which takes
  op results); by convention a program writes only `%s0`–`%s7`, `%sp`/`%bp`,
  `%a0`–`%a6`, `%rv`. `%m` is written by `scan`.

---

## 3. Memory model

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

## 4. Instruction set

All 62 opcodes. Encoding fields are `code`, `reg` (u32), `imm` (u64) — see §5.
"Flags" lists what each op writes; blank means it touches none. `cur` = `%cur`.

### Moves and arithmetic

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 1 | `mov_rc` | `reg` | `cur = r[reg]` | |
| 2 | `mov_cr` | `reg` | `r[reg] = cur` (no-op if `reg == cur`) | |
| 3 | `add_i` | `imm` | `cur += imm` | |
| 4 | `sub_i` | `imm` | `cur -= imm` | |
| 5 | `add_r` | `reg` | `cur += r[reg]` | |
| 6 | `sub_r` | `reg` | `cur -= r[reg]` | |
| 7 | `and_i` | `imm` | `cur &= imm` | |
| 36 | `or_i` | `imm` | `cur |= imm` | |
| 37 | `shl_i` | `imm` | `cur <<= (imm & 63)` | |
| 38 | `shr_i` | `imm` | `cur >>= (imm & 63)` | |

### Load

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 8 | `load` | `reg`, `imm` | `cur = load(cur + imm, size = reg & 15, big-endian if reg & 16)` | `FF` on OOB |

`reg` packs the access: low 4 bits = byte size (1/2/4/8), bit 4 (`LOAD_BE = 16`) =
big-endian. On an out-of-bounds read `cur` is unchanged and `FF` is set.

### Compare and branch

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 9 | `cmp_i` | `imm` | `ZF = cur == imm`; `CF = cur < imm` | `ZF`,`CF` |
| 10 | `cmp_r` | `reg` | `ZF = cur == r[reg]`; `CF = cur < r[reg]` | `ZF`,`CF` |
| 11 | `test` | `imm` | `ZF = (m & imm) == 0` | `ZF` |
| 12 | `jmp` | `imm` | `pc = imm` (forward) | |
| 13 | `je` | `imm` | jump if `ZF` | |
| 14 | `jne` | `imm` | jump if `!ZF` | |
| 15 | `jb` | `imm` | jump if `CF` (unsigned `<`) | |
| 16 | `jae` | `imm` | jump if `!CF` (unsigned `>=`) | |
| 17 | `ja` | `imm` | jump if `!CF && !ZF` (unsigned `>`) | |
| 18 | `jbe` | `imm` | jump if `CF || ZF` (unsigned `<=`) | |
| 19 | `jf` | `imm` | jump if `FF`; **clears `FF`** when taken | `FF` cleared |

A taken jump to a non-forward/out-of-range target fails closed (`V_PASS`,
`faults++`).

### Scan and match

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 20 | `scan` | `imm` | run the automaton (+ regex DFA) over `imm` bytes at `cur`; OR match bits into `%m`, record match end positions | sets `%m` |
| 21 | `mpos` | `reg` | `cur = end offset of the first match of pattern reg`; `FF` if none | `FF` if none |
| 22 | `cmpstr` | `reg` | `ZF = bytes at cur equal pattern reg` | `ZF` |
| 23 | `findb` | `reg`, `imm` | `cur = offset of byte (reg & 0xff) within imm bytes`; `FF` if not found | `FF`/`!FF` |
| 24 | `skipb` | `reg`, `imm` | advance `cur` past a run of byte `(reg & 0xff)`, at most `imm` (clamped to `PFW_PAT_CAP`) | |

`scan`'s window is clamped to `SCAN_CAP = 2048`; it resets the regex DFA state and
walks both automata in one pass. `cmpstr`/`mpos` take a pattern index in `reg`.

### Verdicts, flow state, and events

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 0 | `end` | — | `verdict = PASS`, stop | |
| 25 | `pass` | — | `verdict = PASS` | |
| 26 | `drop` | `reg` | `verdict = DROP`, `rule = reg` | |
| 27 | `count` | `reg` | `counters[reg]++` (non-terminating) | |
| 28 | `log` | `imm` | snapshot `imm` bytes at `cur` (≤ `LOG_CAP = 256`) onto the next event | |
| 29 | `ban` | `reg`, `imm` | `verdict = BAN`, `rule = reg`, mark flow `MARK_DROP` for `imm` s | |
| 30 | `rst` | `reg`, `imm` | `verdict = RST`, `rule = reg`, mark flow `MARK_RST` for `imm` s | |
| 31 | `flow` | — | `cur = the flow's current mark` | |
| 32 | `mark` | `reg`, `imm` | set flow mark `= reg` for `imm` s | |
| 33 | `sload` | — | `cur = flow.user_state` | |
| 34 | `sstore` | `reg`, `imm` | `flow.user_state = imm` for `reg` seconds (0 = forever) | |
| 35 | `bump` | — | `cur = ++flow.hits` | |
| 39 | `cidr` | `imm` | `ZF = cur (IPv4, host order) ∈ net/prefix`; `imm = net(low32) | prefix<<32` | `ZF` |
| 40 | `rpush` | — | push `cur` onto the flow ring (newest at head) | |
| 41 | `rget` | — | `cur = ring entry at index cur` (0 = newest); `cur = 0` + `FF` if out of range | `FF` if OOR |
| 42 | `rlen` | — | `cur = flow.ring_count` | |

`count` and `log` do **not** stop the program (both fall through); every other
verdict op is terminal.

### Membership

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 46 | `lpm` | — | `ZF = cur (IPv4, host order) ∈ lpm trie` (longest-prefix) | `ZF` |
| 47 | `hash` | — | `ZF = (cur & 0xffffffff) ∈ hashset` (exact) | `ZF` |
| 48 | `bloom` | — | `ZF = (cur & 0xffffffff)` probably ∈ bloom (no false negatives) | `ZF` |
| 49 | `lpm6` | — | `ZF = IPv6 source (read from the packet at l3+8) ∈ lpm6 trie`; IPv6 only | `ZF` |

### Rewrite and steer (kernel-only effects)

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 43 | `redact` | `reg`, `imm` | overwrite every match of pattern `reg` in `[payload, end)` with fill byte `(imm & 0xff)` | |
| 44 | `replace` | `reg`, `imm` | overwrite every match of pattern `reg` with pattern `(imm & 0x3f)` (same length) | |
| 45 | `dnat` | `imm` | rewrite dst IPv4+port to `imm = ip(low32) | port<<32`; fix IP + L4 csums | |
| 50 | `redirect` | `imm` | forward the packet out `ifindex = imm` (`bpf_redirect` → `XDP_REDIRECT`); terminal, overrides the verdict | |

`redact`/`replace` only **record** a request (up to `RW_MAX = 4`); the
`pfw_rewrite` tail-call stage applies them after matching. `reg` bit 15 marks a
regex pattern (then `imm` bits 8–14 carry the fixed match length). These are
host no-ops in the reference model (payload rewrite / forwarding aren't part of
the host frame model); `rate`, membership, etc. are modelled via `exec` opts.

### Rate limit

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 51 | `rate` | `imm` | per-flow token bucket; `ZF = 1` when **over** the limit. `imm = rate/sec(low32) | burst<<32` | `ZF` |

Tokens are fixed-point (`× RL_SCALE = 1e6`); refill is `elapsed_ns × rate / 1000`,
capped at `burst`. A fresh flow starts with a full bucket.

### Runtime args, console, printk

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 52 | `arg` | `imm` | `cur = args[idx]` if `idx < argc` else default. `imm = default(low32) | idx(bits 32..47)` | |
| 53 | `argc` | — | `cur = argc` (number of runtime args the host set) | |
| 54 | `farg` | — | push `cur` as the next **numeric** format arg (≤ `FARGS_MAX = 4`) | |
| 55 | `fargs` | `imm` | capture a `%s` string: copy up to `imm` bytes (≤ `STRARG_CAP = 256`) from the packet at `cur` (≤ `FSTR_MAX = 2`) | |
| 56 | `console` | `imm` | emit a console event (format id `imm`) with the gathered args to `console_ring`; resets the arg buffers | |
| 57 | `printk` | `imm` | `bpf_trace_printk` the in-kernel format `fmts[imm]` with up to 3 numeric fargs | |

`console` is modelled on the host (messages collected and returned from `exec`);
`printk` is a host no-op.

### Data stack and subroutines

| # | mnemonic | operands | semantics | flags |
|---|---|---|---|---|
| 58 | `push` | — | `stack[sp++] = cur` (no-op if full) | |
| 59 | `pop` | — | `cur = stack[--sp]` (no-op if empty) | |
| 60 | `call` | `imm` | `stack[sp++] = pc + 1`; `pc = imm` (may be backward) | |
| 61 | `ret` | — | `pc = stack[--sp]` (no-op if empty) | |

---

## 5. Bytecode encoding

### `struct pfw_op`

```c
struct pfw_op { __u32 code; __u32 reg; __u64 imm; };
```

`reg` is masked `& (NREGS - 1)` for register ops, `& (PFW_MAX_PATS - 1)` for
pattern ops, `& (PFW_NRULES - 1)` for rule ops. Multi-field operands pack into
`reg`/`imm`:

| op | encoding |
|---|---|
| `load` | `reg` = size `(0..15)` \| big-endian bit `16` |
| `cidr` | `imm` = net (low 32, host order) \| prefix `<< 32` |
| `dnat` | `imm` = ip (low 32, net order on the wire) \| port `<< 32` |
| `rate` | `imm` = rate/sec (low 32) \| burst `<< 32` |
| `arg` | `imm` = default (low 32) \| index `<< 32` (bits 32–47) |
| `redact` | `reg` = pat id \| regex bit `<< 15`; `imm` = fill byte (low 8) \| rlen `<< 8` |
| `replace` | `reg` = pat id \| regex bit `<< 15`; `imm` = repl pat id (low 6) \| rlen `<< 8` |
| `sstore` | `reg` = TTL seconds; `imm` = new state value |
| `ban`/`rst`/`mark` | `reg` = rule / mark; `imm` = TTL seconds |
| `findb`/`skipb` | `reg` = byte (low 8); `imm` = window / max run |

### `struct pfw_prog`

The `programs[gen]` map value:

```c
struct pfw_prog {
    __u32 nops, npats, nocase, gen;
    __u32 reasm, reasm_dport, decode, transform_table;
    __u32 argc;  __u64 args[PFW_ARGC];
    __u8  fmts[PFW_FMTS][PFW_FMT_CAP];
    struct pfw_op  ops[PFW_MAX_OPS];     // 8192
    struct pfw_pat pats[PFW_MAX_PATS];   // 64 × {u32 len; u8 bytes[64]}
};
```

`serializeProgram(program, gen)` (host) produces this value; `build(patterns,
nocase)` produces the Aho-Corasick tables (`ac_goto`/`ac_fail`/`ac_accept`), and
the regex compiler produces the DFA tables (`re_goto`/`re_accept`). The loader
writes the program into `programs[gen]`, the automaton/DFA/transform tables and
the membership sets into their maps, patches the `active`/`shadow` globals, then
attaches `pfw_xdp`. Two generations (`PFW_GENS = 2`) let an update write the idle
generation and flip `active` atomically.

---

## 6. Maps and globals

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

## 7. Verdicts and actions

`enum pfw_verdict { V_NONE, V_PASS, V_DROP, V_BAN, V_RST }`. `finish()`
(`match_half`) turns the final verdict into an XDP action:

| verdict | XDP action | side effects |
|---|---|---|
| `PASS` (or none) | `XDP_PASS` (or tail-call the rewrite stage if `rw_n`) | — |
| `DROP` | `XDP_DROP` | `count_rule`, `dropped++` |
| `BAN` | `XDP_DROP` | flow marked `MARK_DROP` for the TTL; later packets dropped at the entry fast path |
| `RST` | `XDP_TX` (IPv4 TCP: a crafted RST) else `XDP_DROP` | flow marked `MARK_RST` for the TTL |

Overrides and fast paths:

- **`redirect`** takes precedence over any verdict: `maybe_redirect` issues
  `bpf_redirect(ifindex)` and returns `XDP_REDIRECT`.
- **Shadow mode**: when `shadow` is set, a `DROP`/`BAN`/`RST` is still counted,
  logged, and its flow mark written, but the packet is returned `XDP_PASS`
  (`shadowed++`). `%shadow` also exposes the flag to the program.
- **Entry fast path**: before running the program, an established flow already
  carrying `MARK_DROP`/`MARK_RST` (and not expired) is enforced immediately
  (dropped or RST), honouring shadow mode. A fresh TCP SYN clears a stale mark in
  reassembly mode so a reused ephemeral port is judged on its own bytes.
- **Flow write-back** (marks, user state, hits, rate tokens, automaton state) is
  applied after the run, visible on the next packet.

`enum pfw_mark { MARK_NONE, MARK_DROP = 1, MARK_RST = 2 }` (user marks via `mark`
use values from 16 up).

---

## 8. Decode front-ends and the rewrite stage

A program may normalise the reassembled stream before matching
(`pfw_prog.decode`): `DECODE_NONE (0)`, `DECODE_H2 (1)` (HPACK, HTTP/2 HEADERS),
`DECODE_HUFFMAN (2)` (HPACK-Huffman via a baked table), `DECODE_TRANSFORM (3)` (a
host-loaded `tt_cells` table chosen by `transform_table`). Decoding and matching
are **separate eBPF programs** so each stays within the verifier's per-program
budget; they are wired through the `decode_jmp` PROG_ARRAY:

| slot | program |
|---|---|
| `SLOT_DECODE (0)` | HPACK/h2 decode |
| `SLOT_MATCH (1)` | the matcher (`pfw_match`) |
| `SLOT_RESOLVE (2)` | HPACK index resolution |
| `SLOT_HUFF (3)` | Huffman decode |
| `SLOT_TRANSFORM (4)` | loadable-table decode |
| `SLOT_REWRITE (5)` | apply recorded `redact`/`replace` + fix the L4 checksum |

The entry (`pfw_xdp`) parses L2–L4, does TCP reassembly when enabled, initialises
the per-CPU state, and either tail-calls a decode stage or runs the matcher
inline. On the pass path, if the program recorded any rewrites, the matcher
tail-calls `SLOT_REWRITE` before the packet continues.

---

## 9. Budgets

From `LIMITS` (`src/isa.js`) / `pfw.h`:

| limit | value | |
|---|---|---|
| instructions (`MAX_OPS`) | 8192 | per program; also the step ceiling |
| patterns (`MAX_PATS`) | 64 | one bit each in `%m` |
| pattern length (`PAT_CAP`) | 64 B | |
| scan window (`SCAN_CAP`) | 2048 B | and the `findb` window |
| AC states (`AC_STATES`) | 4096 | per generation |
| regex DFA states (`RE_STATES`) | 1024 | |
| scratch registers | 8 | `%s0`–`%s7`, reused by live range |
| subroutine args | 7 | `%a0`–`%a6`; return in `%rv` |
| data-stack depth (`STACK_CAP`) | 64 | `push`/`pop`, `call`/`ret` |
| rules (`NRULES`) | 64 | named verdicts / counters |
| runtime args (`ARGC`) | 16 | `argv[i]` |
| console numeric args (`FARGS`) | 4 | per `console`/`printk` call |
| console `%s` args (`FSTR`) | 2 | ≤ `STRARG = 256` B each |
| printk formats (`FMTS`) | 8 | ≤ `FMT_CAP = 64` B each, in-kernel |
| per-flow ring (`RING_CAP`) | 16 | newest-wins |
| rewrites per packet (`RW_MAX`) | 4 | recorded, applied by the rewrite stage |
| log snapshot (`LOG_CAP`) | 256 B | into the event |
| reassembly buffer (`REASM_CAP`) | 2048 B | per flow |
| flows (`MAX_FLOWS`) | 16384 | LRU |
| generations (`GENS`) | 2 | atomic program swap |

---

*Companion documents: [`lang.md`](lang.md) — the pfw-C language and how each
construct lowers to this ISA; [`primitives.md`](primitives.md) — the design note
on building higher-level features from the base primitives.*
