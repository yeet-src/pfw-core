# Rewrite, steering, arguments, observability, and the stack

The side-effecting tail of the instruction set: ops that modify the packet,
forward it elsewhere, rate-limit a flow, read host-set parameters, emit
observability, and drive the data stack / subroutine calls. Opcode numbers are
from `src/isa.js`; kernel semantics from `bpf/include/match/interp.h` (and
`action/rewrite.h`, `action/event.h`, `core/match.h`); host modelling from
`src/interp.js`.

Common encoding note: every op is `{ code (u32), reg (u32), imm (u64) }`. Ops
below that leave a result do so in `%cur`; flow-state fields (`rl_*`, `rw[]`,
`redirect_if`, `fargs`, `fsn`) live in the per-CPU `pfw_state` and, where noted,
are written back to the flow in `finish()`.

---

## Packet rewrite

### 43 — `OP_REDACT` (`redact $PAT, $FILL`)
### 44 — `OP_REPLACE` (`replace $PAT, $REPL`)

- **Assembler:** `redact $pat, $fill` (fill is a byte, 0–255); `replace $pat, $repl`
  (both pattern names). The assembler forms are **literal-only** — the regex form
  is produced by the pfw-C compiler, not written by hand.
- **Encoding:** `code = 43/44`.
  - `reg` — bit 15 (`0x8000`) is the **regex flag**; the low 14 bits are the
    literal pattern id *or*, when the regex flag is set, the regex accept-bit
    (its pattern id in the shared `%m` bit space).
  - `imm` — low 8 bits = the fill byte (`redact`); low 6 bits = the replacement
    pattern id (`replace`); bits 8–14 = the **fixed match length** `rlen`, used
    only for the regex form.
  - Builder: `redact(pat, fill, isRe, rlen)` → `reg = (pat & 0x3fff) | (isRe?0x8000:0)`,
    `imm = (fill & 0xff) | ((rlen & 0x7f) << 8)`. `replace(pat, repl, isRe, rlen)`
    → `imm = (repl & 0x3f) | ((rlen & 0x7f) << 8)`.
- **Operation (kernel):** these do **not** rewrite in `pfw_step`; they *record a
  request* into `st->rw[st->rw_n++]` (`pat`, `is_re`, `rlen`, `mode = (code ==
  OP_REPLACE)`, `repl`, `fill`, `woff = st->r[R_PAYLOAD]`), capped at `RW_MAX = 4`
  and **only when not in reassembly mode** (`!c->reasm`). After matching, if any
  request was recorded, `finish()` tail-calls the `pfw_rewrite` stage
  (`SLOT_REWRITE`), which runs `do_rewrite` in its own verifier budget:
  1. copy the window `[woff, end)` into `st->buf` (`window()`);
  2. walk it one byte per `bpf_loop` step — `rw_ac_step` (Aho-Corasick, literal)
     or `rw_re_step` (regex DFA, `re_goto`/`re_accept`);
  3. on each accept of the target pattern/bit, overwrite the matched span **in
     place, same length** — the fill byte (`redact`) or the replacement pattern's
     bytes (`replace`) — via `fill_step`, accumulating the old/new 16-bit sums;
  4. write the window back (`bpf_xdp_store_bytes`) and fold the L4 checksum
     delta (RFC 1624) at `l4+16` (TCP) / `l4+6` (UDP).

  The span length is `p->pats[pat].len` for a literal, or the compiler-supplied
  fixed `rlen` for a regex (which is why only **fixed-length** regexes may be
  rewritten — see below).
- **Operation (host):** fully modelled — `src/interp.js` rewrites the `frame`
  buffer in place over `[payload, end)`. Literal: a same-length, case-folded
  compare at each offset, overwriting on a hit. Regex (`reg & 0x8000`): walk the
  DFA and, on accept of the bit, overwrite `[i+1-len, i]`.
- **Flags:** none.
- **Maps:** `ac_goto`/`ac_fail`/`ac_accept` (literal) or `re_goto`/`re_accept`
  (regex) at the active generation; the packet itself is written.
- **Compile-time rules (`src/clang/`, `src/regex.js`):** `redact`/`replace`
  take a literal `pattern` **or** a **fixed-length** `regex` (every match the same
  byte count — e.g. `\d{3}-\d{2}-\d{4}` is 11, `AKIA[A-Z0-9]{16}` is 20). A
  variable-length regex is rejected for rewrite (use it in `scan`/`any` to detect
  and then `decide` instead). `replace`'s replacement must equal the match length.
- **Example:** `redact(ssn);` · `redact(card, 'X');` · `replace(bot, "NOTBOT");`
- **Notes:** per-packet only (recorded only when `!reasm`, since reassembly mode
  matches over a reconstructed buffer, not the wire). Up to `RW_MAX = 4` requests
  per packet. Applied on the forward (PASS) path.

---

## Destination steering

### 45 — `OP_DNAT` (`dnat A.B.C.D:PORT`)

- **Assembler:** `dnat 10.0.0.2:8080` (IPv4 literal + port), or `dnat %cur`.
- **Encoding:** `code = 45`. With `reg = 0`, `imm` = destination IPv4 in the
  **low 32 bits** (host order) `|` destination port in **bits 32–47**. Builder:
  `(ip & 0xffffffff) | (port & 0xffff) << 32`. With `reg` bit 0 set, the target
  is **`%cur`**, packed the same way, and `imm` is unused; a `%cur` whose low 32
  bits are 0 steers nothing.
- **Operation (kernel):** `do_dnat` (a `__noinline` helper). IPv4 TCP/UDP only
  (checks the version nibble at `l3`): rewrites the destination address at
  `l3+16` and the destination port at `l4+2`, then fixes the **IP header
  checksum** (`l3+10`) and the **L4 checksum** (TCP `l4+16`, UDP `l4+6`)
  incrementally with `bpf_csum_diff`. Runs only when `!c->reasm`. The program
  then forwards (a PASS verdict) and the stack routes the rewritten packet.
  It also records the **reply tuple** in the `nat` map (from the new destination,
  to this packet's source → the original destination). At the entry,
  `nat_reverse` matches every IPv4 TCP/UDP packet against that map and, on a hit,
  restores the reply's source address and port (fixing both checksums) and
  passes it without running the program — so the client sees replies from the
  address it dialled, and a TCP connection diverted from its SYN completes.
- **Operation (host):** the host frame model is payload-only and has no L3/L4
  headers to rewrite; `interp.js` records the target instead, and a run returns
  it as `dnat: { ip, port }` (or `null`).
- **Flags:** none. **Maps:** `nat` (writes the packet too).
- **Example:** `dnat("10.0.0.2", 8080);`
- **Notes:** pfw-C emits the immediate form when both the address and the port
  are written out, and otherwise computes the target into `%cur`. Pairs with `redirect` to steer a rewritten packet out another interface.

### 50 — `OP_REDIRECT` (`redirect IFINDEX`)

- **Assembler:** `redirect 5`.
- **Encoding:** `code = 50`, `reg = 0`, `imm` = the target interface index (u32).
- **Operation (kernel):** records `st->redirect_if = imm`. The actual
  `bpf_redirect(ifindex, 0)` is issued in `finish()` by `maybe_redirect()` — its
  return value (`XDP_REDIRECT`) must be the program's return value, so the check
  runs **before the verdict switch** and **overrides the verdict** (a redirect
  wins even over a `decide drop`). The (possibly DNAT-rewritten) packet is sent
  out `ifindex`.
- **Operation (host):** kernel-only — no-op in `interp.js`.
- **Flags:** none. **Maps:** none.
- **Example:** `redirect(5);` (often after `dnat(...)` — steer flagged traffic to
  a sandbox/honeypot).
- **Notes:** terminal on the forward path. `ifindex` is a compile-time constant
  (`argv` cannot feed `redirect`).

---

## Rate limiting

### 51 — `OP_RATE` (`rate $PER_SECOND, $BURST`)

- **Assembler:** `rate $5, $20` (both positive u32), or `rate %cur`; `srcrate`
  for the source scope — **pfw-C:** `rate(5, 20)` / `src.rate(5, 20)`.
- **Encoding:** `code = 51`. `reg` bit 0 = scope (0 = one bucket per connection,
  1 = one bucket per source address, shared by all its connections). With `reg`
  bit 1 clear, `imm` = tokens/second in the **low 32 bits** `|` burst (bucket
  capacity) in the **high 32 bits**; with it set, **`%cur`** holds the same
  pair and `imm` is unused.
- **Operation (kernel):** `do_rate` (a `__noinline` helper) — a token bucket kept
  per flow in `st->rl_tokens` / `st->rl_ts` (loaded from the flow at entry,
  written back in `finish()` when `set_rl`). Tokens are fixed-point, scaled by
  `RL_SCALE = 1e6`. On each call: `refill = elapsed_ns * rate / 1000` (`= ns ×
  tok/s × 1e6 / 1e9`), `tokens = min(cap, tokens + refill)` where `cap = burst ×
  RL_SCALE`; first sight (`rl_ts == 0`) seeds a full bucket. If `tokens ≥
  RL_SCALE` one token is spent and the op returns **allowed (0)**; otherwise
  **over-limit (1)**. The return drives the flag:
- **Operation (host):** modelled via `opts.bucket = { tokens, ts }` + `opts.now`
  (thread them across packets to simulate the bucket); with no `bucket` the op is
  treated as allowed.
- **Flags:** sets **ZF = over-limit** (`fl = (fl & FL_FF) | (over ? FL_ZF : 0)`);
  preserves FF; clears CF.
- **Maps:** `flows` (the bucket is per-flow state).
- **Example:** `if (rate(5, 20)) decide drop("rl");` — `rate(...)` is a condition
  that is **true when over the limit**.
- **Notes:** pfw-C emits the immediate form when both arguments are written out
  (and checks they are positive), and otherwise computes the pair into `%cur`.
  A computed burst of 0 has no tokens to give: every packet is over the limit.

---

## Arguments and runtime parameters

### 52 — `OP_ARG` (`arg $IDX[, $DEFAULT]`)

- **Assembler:** `arg $0, $80` (index 0–`ARGC-1`, optional default).
- **Encoding:** `code = 52`, `reg = 0`. `imm` = index in **bits 32–47** `|`
  default in the **low 32 bits**. Builder: `(idx & 0xffff) << 32 | (def &
  0xffffffff)`.
- **Operation:** `cur = (idx < prog->argc) ? prog->args[idx & (PFW_ARGC-1)] :
  default`. The host reads `opts.argv` (`idx < argv.length ? argv[idx] :
  default`). This is the lowering of `argv[idx] ?? default`.
- **Flags:** none (writes `%cur`). **Maps:** none (reads `prog->args`, set by the
  host loader without recompiling).
- **Example:** `if (dport != argv[0] ?? 80) decide pass;`
- **Notes:** up to `PFW_ARGC = 16` args. `argv` yields a plain value usable in
  comparisons/arithmetic/thresholds — it is **not** accepted as an argument to
  `rate`/`dnat`/`redirect`, which require compile-time literals.

### 53 — `OP_ARGC` (`argc`)

- **Assembler:** `argc`. **Encoding:** `code = 53`, no operands.
- **Operation:** `cur = prog->argc` (host: `argv.length`) — how many runtime args
  the host actually set.
- **Flags:** none (writes `%cur`). **Maps:** none.
- **Example:** `if (argc > 3) ...`

---

## Observability

Format arguments are gathered first (`farg` numeric, `fargs` string), then flushed
by `console`/`printk`.

### 54 — `OP_FARG` (`farg`)

- **Assembler:** `farg`. **Encoding:** `code = 54`, no operands.
- **Operation:** push `%cur` as the next numeric format argument —
  `st->fargs[st->fargn++] = cur` while `fargn < FARGS_MAX = 8`.
- **Flags/Maps:** none. **Example:** emitted by the compiler for each numeric
  conversion in a `console`/`printk` format.

### 55 — `OP_FARGS` (`fargs $CAP`)

- **Assembler:** `fargs $256`. **Encoding:** `code = 55`, `reg = 0`, `imm = cap`.
- **Operation:** `%cur` is a **packet offset**; copy up to `min(cap, STRARG_CAP =
  256, end - off)` bytes from the packet into `st->fstr[st->fsn]`, record the
  length in `st->fslen[fsn]`, and bump `fsn` while `fsn < FSTR_MAX = 2`. Kernel
  reads the packet (`bpf_xdp_load_bytes`) and is a no-op in reassembly mode; host
  copies from the `frame`.
- **Flags/Maps:** none (writes `st->fstr`). **Example:** emitted for each `%s`
  conversion (the compiler does `loadPtr(arg); fargs(256)`).
- **Notes:** `%s` is **console-only**; `printk` has no string path.

### 56 — `OP_CONSOLE` (`console $FMTID`)

- **Assembler:** `console $0`. **Encoding:** `code = 56`, `reg = 0`, `imm =
  format id`.
- **Operation (kernel):** `console_emit` reserves a `pfw_console` record on the
  `console_ring` and fills `ts`, `ifindex`, `fmtid`, `nnum = min(fargn, 4)`,
  `nstr = min(fsn, 2)`, the numeric args `nums[FARGS_MAX]`, and the captured
  strings (`slen[FSTR_MAX]`, `strs[FSTR_MAX][STRARG_CAP]`), then submits it and
  resets `st->fargn = 0`. The host maps `fmtid → format string`
  (`program.consoleFormats`) and renders it.
- **Operation (host):** records `{ fmtid, nums, strs }`; `Program.exec` formats
  each via `formatMsg` and returns them in `r.console` (and calls
  `opts.onConsole`).
- **Flags:** none. **Maps:** `console_ring` (a dedicated ringbuf, `pfw_console`).
- **Example:** `console("req to :%d says %s", dport, payload);`
- **Limits:** ≤ 8 numeric conversions (`%d %u %x %X %o %c`, `%%`), ≤ 2 `%s`.
- **Notes:** the format strings never enter the kernel — only the id and the
  args cross the ring. Host/kernel divergence: the host resets **both** the
  numeric and string buffers after each `console()`; the kernel resets the
  numeric count and relies on the per-packet reset of `fsn`, so a single
  `console()` per packet (the common case) matches exactly, while multiple
  `%s`-bearing `console()` calls in one packet can differ.

### 57 — `OP_PRINTK` (`printk $FMTID`)

- **Assembler:** `printk $0`. **Encoding:** `code = 57`, `reg = 0`, `imm =
  printk format id`.
- **Operation (kernel):** `bpf_trace_printk(prog->fmts[id & (PFW_FMTS-1)],
  PFW_FMT_CAP, …)` with up to **3** numeric args from `st->fargs`, then resets
  `fargn = 0`. The format lives **in the program** (`prog->fmts`, NUL-terminated,
  `PFW_FMT_CAP = 64` bytes, `PFW_FMTS = 8` slots) so the helper can read it at
  run time. Output goes to the kernel trace pipe.
- **Operation (host):** no-op (clears the numeric args); nothing to render
  host-side.
- **Flags:** none. **Maps:** none (format in `prog->fmts`; writes the trace pipe).
- **Example:** `printk("reset sport %d", sport);`
- **Limits:** ≤ 3 numeric args; **no `%s`** (use `console` for strings).
- **Notes:** reading the output needs root — `sudo cat
  /sys/kernel/debug/tracing/trace_pipe`.

### 70 — `OP_TLOAD` (`tload $BASE, $SIZE`)

- **Assembler:** `tload $0, $65537`. **Encoding:** `code = 70`, `reg = 0`, `imm` =
  the table's base cell in the **low 32 bits** `|` its size in the **high 32**.
- **Operation:** with `i = %cur`: if `i < size`, `cur ← tables[gen * TABLE_CELLS
  + base + i]`, a 64-bit host-loaded cell (0 if never set); otherwise `cur ← 0`
  and `FF` is set.
- **Flags:** `FF` on an index at or past `size`; `ZF`/`CF` untouched.
- **Maps:** `tables`. The cell space is per generation: the loader lays a
  program's tables out in the idle half before the flip, so a program never
  reads cells placed for another.
- **Example:** `table backends[251]; … dnat(backends[flow.hash % 251]);` →
  `fhash; mod 251; tload 0 251; dnat %cur`.
- **Notes:** the bound is the table's own size, not the cell space's: a bad
  index cannot read the table declared after it.

### 69 — `OP_EMIT` (`emit $EVENTID`)

- **Assembler:** `emit $0`. **Encoding:** `code = 69`, `reg = 0`, `imm = event id`.
- **Operation (kernel):** reserves a `struct pfw_emit { ts, ifindex, id, n,
  vals[FARGS_MAX] }` on the `emits` ring, copies the numeric args queued by
  `farg` into it (`n = min(fargn, 8)`), submits it, then resets `fargn = 0`. A
  full ring counts in `ring_full` and the event is lost; the packet is not.
- **Operation (host):** appends `{ id, nums }` to the run's emitted events; the
  compiler's `emits` list maps an id to the name the program gave it.
- **Flags:** none. **Maps:** `emits`.
- **Example:** `emit("flow", src, sport, dport);`
- **Limits:** ≤ 8 values, numbers only. Strings queued by `fargs` are not
  carried: an event is for values the host will use, `console` for text.

---

## The data stack and subroutines

A single per-CPU data stack (the `stack` map, one `struct vmstack { u64 s[64] }`)
backs both explicit `push`/`pop` and the `call`/`ret` return-address stack.
`%sp` (`R_SP`) is the stack pointer, `%bp` (`R_BP`) a caller-managed frame mark;
depth is `STACK_CAP = 64`.

### 58 — `OP_PUSH` (`push`)

- **Assembler:** `push`. **Encoding:** `code = 58`, no operands.
- **Operation:** `if (sp < STACK_CAP) { stack[sp] = cur; sp++ }` — writes the
  `stack` map at index `%sp` and increments `%sp`.
- **Flags/Maps:** none / `stack`. **Example:** `push(sport);`

### 59 — `OP_POP` (`pop`)

- **Assembler:** `pop`. **Encoding:** `code = 59`, no operands.
- **Operation:** `if (sp > 0) { sp--; cur = stack[sp] }` — decrements `%sp` and
  loads `%cur` from the top. Underflow (`sp == 0`) is a no-op.
- **Flags:** none (writes `%cur`). **Maps:** `stack`. **Example:** `let s = pop();`

### 60 — `OP_CALL` (`call LABEL`)

- **Assembler:** `call label`.
- **Encoding:** `code = 60`, `reg = 0`, `imm = target pc` (resolved from the
  label by the builder). `call` is **exempt** from the forward-only jump check,
  so routines may be defined before or after their call sites.
- **Operation:** push the **return address** (the next pc) onto the data stack
  (`sp++`) and set the program counter to `imm`.
- **Flags/Maps:** none / `stack`. **Example:** a `fn name(...)` call lowers to
  argument moves then `call name`.

### 61 — `OP_RET` (`ret`)

- **Assembler:** `ret`. **Encoding:** `code = 61`, no operands.
- **Operation:** pop the data stack into the program counter (`sp--; pc =
  stack[sp]`). This is the **one place control flows backward at run time** — to
  the return address — and it stays safe only because the interpreter's overall
  step budget (the `bpf_loop` cap, 8192) bounds total execution; there is no
  backward *label* jump.
- **Flags/Maps:** none / `stack`.
- **Calling convention:** arguments are passed in registers `%a0..%a6` (up to 7),
  the return value in `%rv` (`return <expr>` sets `%rv` then `ret`); the compiler
  loads args before `call` and reads `%rv` after. Routines are **caller-saved**
  over `%a0..%a6`/`%rv`, and must keep the data stack **balanced** across a call
  (the return address sits on it, so a net push before `ret` would pop as the
  return address). A `decide <verdict>` inside a routine is terminal — it ends the
  whole program, it does not return to the caller.
- **Example:** `fn add(a, b) { return a + b; }` → `let r = add(3, 4);`

---

## Live control knobs

*Knobs* are a named control plane the host rewrites **while the program runs** —
unlike `argv` (positional and fixed at load), a knob is read fresh from a map on
every packet, so the host can retune or re-target a running program with no
reload and no recompile. The compiler assigns each name a slot; the loader writes
the slot. Two kinds: numeric knobs (`OP_KNOB`, the `knobs` map) and string knobs
(`OP_KNOBHAS`, the `knob_strs` map).

### 62 — `OP_KNOB` (`knob $SLOT`)

- **Assembler:** `knob $0` (slot 0–`PFW_KNOBS-1`).
- **Encoding:** `code = 62`, `reg = 0`, `imm` = slot.
- **Operation:** `cur = knobs[imm & (PFW_KNOBS-1)]` — the current value at that
  slot of the `knobs` array map. The host reads `opts.knobs` (by name → slot).
  Zero-initialized, so an unset knob reads `0`; the loader seeds a declared
  default (`knob("x") ?? d`) into the slot at load time, which the host may later
  overwrite with any value (including `0`).
- **Flags:** none (writes `%cur`). **Maps:** `knobs` (array of `__u64`,
  `PFW_KNOBS = 32` slots, shared — not per-CPU).
- **Operation lowered from:** `knob("name")` / `knob("name") ?? default`, and a
  `knob struct` field read `Name.field` (sugar for consecutive slots).
- **Example:** `if (len > knob("cap")) decide drop("too_big");` — the host raises
  or lowers `cap` live.
- **Notes:** like `argv`, a knob is a plain value (comparisons / arithmetic /
  thresholds); it is **not** accepted where `rate`/`dnat`/`redirect` require a
  compile-time literal.

### 63 — `OP_KNOBHAS` (`knobhas $SLOT`)

- **Assembler:** `knobhas $0` (slot 0–`PFW_KNOBSTRS-1`).
- **Encoding:** `code = 63`, `reg = 0`, `imm` = slot.
- **Operation:** `ZF = knob_strs[imm]` occurs in the payload — a bounded
  substring search of the host-set needle over the first `KNOB_SCAN = 256` bytes
  of the payload (loaded into `st->kbuf` once per use). An empty/unset string
  knob never matches. `ZF = 1` when the needle is found (same sense as
  `OP_HASH`/`OP_LPM` membership).
- **Flags:** sets `ZF` (preserves `FF`). **Maps:** `knob_strs` (array of
  `struct knob_str { __u32 len; __u8 b[KNOBSTR_CAP]; }`, `PFW_KNOBSTRS = 16`
  slots, `KNOBSTR_CAP = 64` bytes per needle).
- **Operation lowered from:** `kstr("name")` used as a condition.
- **Example:** `if (kstr("bad_host")) decide rst("blocked", 0);` — push the
  current bad host/token and block it without a reload.
- **Notes:** the search window is fixed (`KNOB_SCAN`, a power of two for the
  verifier); needles are capped at `KNOBSTR_CAP` bytes. Unlike compile-time
  `pattern`s (baked into the Aho-Corasick automaton), a string knob is set and
  changed live.

---

### Flag summary for this group

Only `OP_RATE` and `OP_KNOBHAS` touch a flag (`OP_RATE` sets `ZF` = over-limit,
`OP_KNOBHAS` sets `ZF` = needle found; both preserve `FF`). `OP_ARG`, `OP_ARGC`,
`OP_POP`, and `OP_KNOB` write `%cur`. Everything else here is a pure side effect
(packet write, ring emit, stack/pc change) and leaves `%cur` and the flags as
they were.
