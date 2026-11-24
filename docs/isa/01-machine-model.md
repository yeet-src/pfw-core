# 1. Machine model

### Execution

A program is an array of `struct pfw_op` in the `programs` map. The interpreter
(`pfw_step`) executes **one instruction per step**, driven by
`bpf_loop(PFW_MAX_OPS, pfw_step, …)` — so a run is **at most 65536 steps**. A step
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
possible at run time, but it is still bounded by the overall 65536-step
`bpf_loop` budget, so termination holds regardless. Repetition that isn't a
subroutine is a **compile-time unroll** (`repeat`, `frame … up to N`) with a
fixed ceiling.

### Host vs. kernel

`src/interp.js` is the executable spec; `bpf/include/match/interp.h` is the
kernel. They implement identical semantics for matching, arithmetic, flow state,
and the ring. A few ops are **kernel-only side effects** the payload-only host
model represents differently (noted per-op in §4): `dnat`/`redirect` are host
no-ops; `rate`, the membership tests, `console`, `shadow`, and the data stack are
modelled through `exec` options, as is per-source state (the `source` option,
threaded across calls like `flow`). The host model does **not** model TCP
reassembly or the decode front-ends — `exec` runs over exactly the bytes it is
given — so those are covered by the kernel tests (`test:reasm`, `test:h2`,
`test:examples-kernel`).

---
