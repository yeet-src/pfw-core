# 4. Instruction set

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
