# Compare, branch, and scan

The comparison, control-flow, and content-matching opcodes — the part of the ISA
that turns bytes into decisions. Semantics below are taken from the kernel
interpreter (`bpf/include/match/interp.h`, `bpf/include/match/scan.h`); the host
reference (`src/interp.js`) mirrors them, and any divergence is called out.

## The flag model

Three one-bit flags live in `st->flags` (`pfw.h`): `FL_ZF = 1` (zero/equal),
`FL_CF = 2` (carry / unsigned *below*), `FL_FF = 4` (fault). They are the only
state the branches read.

- **`CMP_I` / `CMP_R`** recompute `ZF` and `CF` from an unsigned compare and
  **preserve `FF`**; they touch nothing else (`fl = (fl & FL_FF) | ZF | CF`).
- **`TEST`** sets `ZF` from a mask test against `%m`, preserves `FF`, clears `CF`.
- **`CIDR` and the membership ops** set `ZF` and preserve `FF`.
- **A faulting read** (a load past `%end`, a missing match) sets `FF`; `MPOS`,
  `LOAD`, and `FINDB`-miss raise it.
- **The branches consume** flags; only `JF` *clears* one (`FF`, on taken).

Comparisons are **unsigned** over 64-bit registers: `CF` means `cur < operand`.
There is no signed compare — operands that must be ordered are values in
`[0, 2⁶⁴)`.

## Forward-only branching

Every label jump targets a **later** instruction. The assembler rejects a
backward or out-of-range target at build time (`builder.js` resolves a label to
its pc and requires `target > pc`), and the kernel enforces it again at run time:
a taken branch whose `imm ≤ pc` or `imm > PFW_MAX_OPS` aborts the program with a
fault and a `pass` verdict. This is what makes termination provable — a program
is a DAG of forward edges, walked under a hard `bpf_loop(PFW_MAX_OPS, …)` step
budget. (The one controlled backward transfer in the ISA is `RET`, documented
with the stack ops; it is bounded by that same step budget, not by a label.)

The matcher opcodes (`SCAN`, `CMPSTR`, `FINDB`, `SKIPB`) read a **window**: up to
`n` bytes starting at the cursor, copied into `st->buf` by `window()`, bounded by
`%end` and by `SCAN_CAP = 4096`. In reassembly mode the window is served from the
flow's reassembled stream instead of the packet. The matcher never reads past the
window.

---

## Compare and test

### 9 — `OP_CMP_I` (`cmp $imm, %cur`)
- **Assembler:** `cmp $N, %cur` — the immediate is the left operand, `%cur` must
  be the right.
- **Encoding:** `code = 9`, `reg = 0`, `imm = N` (the 64-bit comparand).
- **Operation:** `ZF ← (cur == imm)`, `CF ← (cur < imm)` (unsigned). `FF`
  preserved; no register written.
- **Flags:** sets `ZF`, `CF`; preserves `FF`.
- **Example:** `cmp $80, %cur` after `mov %dport, %cur` — pfw-C `dport == 80`.

### 10 — `OP_CMP_R` (`cmp %reg, %cur`)
- **Assembler:** `cmp %reg, %cur`.
- **Encoding:** `code = 10`, `reg = register index` (an allocatable slot), `imm =
  0`.
- **Operation:** `v = st->r[reg]`; `ZF ← (cur == v)`, `CF ← (cur < v)` (unsigned).
- **Flags:** sets `ZF`, `CF`; preserves `FF`.
- **Example:** compare two scanned values held in scratch registers.

### 11 — `OP_TEST` (`test $mask, %m`)
- **Assembler:** `test $MASK, %m` — the right operand is always the match mask
  register `%m`.
- **Encoding:** `code = 11`, `reg = 0`, `imm = mask`. The mask is a bitset of
  pattern ids: bit *k* = pattern *k* (the same bit `SCAN` sets).
- **Operation:** `ZF ← ((%m & mask) == 0)`. So after a `scan`, `test $bits, %m;
  jne hit` branches to `hit` when **any** pattern in `bits` matched; `je`
  branches when **none** did. `all(...)` is lowered as one `test`+`je` per bit.
- **Flags:** sets `ZF`; preserves `FF`; clears `CF`.
- **Example:** pfw-C `scan(payload, 256) & bot` → `scan $256; test $bot, %m; je …`.

---

## Branches

All eight take a single label operand; `imm` holds the resolved **target pc**
(filled when the Builder finalises labels). `jz`/`jnz` are assembler aliases for
`je`/`jne`. A taken branch sets the next pc to `imm`; a not-taken branch falls
through to `pc + 1`. Forward-only (see above).

### 12 — `OP_JMP` (`jmp label`)
- **Encoding:** `code = 12`, `imm = target`. **Operation:** unconditional —
  `pc ← imm`. **Flags:** none read or written.

### 13 — `OP_JE` (`je` / `jz`)
- Taken when `ZF == 1` (operands were equal). **Consumes** `ZF`.

### 14 — `OP_JNE` (`jne` / `jnz`)
- Taken when `ZF == 0` (not equal). **Consumes** `ZF`.

### 15 — `OP_JB` (`jb`)
- Taken when `CF == 1` (unsigned *below*: the earlier `cmp` had `cur < operand`).
  **Consumes** `CF`.

### 16 — `OP_JAE` (`jae`)
- Taken when `CF == 0` (unsigned *above-or-equal*). **Consumes** `CF`.

### 17 — `OP_JA` (`ja`)
- Taken when `CF == 0 && ZF == 0` (unsigned *above*). **Consumes** `CF`, `ZF`.

### 18 — `OP_JBE` (`jbe`)
- Taken when `CF == 1 || ZF == 1` (unsigned *below-or-equal*). **Consumes** `CF`,
  `ZF`.

### 19 — `OP_JF` (`jf label`)
- Taken when `FF == 1` (the previous read faulted), and **clears `FF`** on the
  taken path. Lets a program recover from a read past `%end` (e.g. a truncated
  packet) instead of silently mis-deciding.
- **Encoding:** `code = 19`, `imm = target`. **Example:** `mov %end, %cur; movb
  0(%cur), %cur; jf short` — jump away when the load ran off the end.

> **Comparison → branch mapping.** `==`→`je`, `!=`→`jne`, `<`→`jb`, `>=`→`jae`,
> `>`→`ja`, `<=`→`jbe` (all unsigned). The front-ends emit the *inverted* branch
> to skip a `then`-block, e.g. `if (dport == 80) {…}` lowers to `cmp $80,%cur; jne
> END; …; END:`.

---

## Scan and match

### 20 — `OP_SCAN` (`scan $len[, (%cur)]`)
- **Assembler:** `scan $LEN` or `scan $LEN, (%cur)` — the window always begins at
  the cursor; `LEN` is `1 … SCAN_CAP (4096)`. `fscan` is the fresh form —
  **pfw-C:** `scan(ptr, N)` / `within(ptr, N)`.
- **Encoding:** `code = 20`, `reg` bit 0 = fresh, `imm = window length` (clamped to
  `SCAN_CAP`). The length is a **compile-time constant** (the assembler and pfw-C
  both reject a variable).
- **Operation:** when the fresh bit is set, first clear `%m` and the automaton
  state, so the result is exactly the patterns inside this window — a plain
  `scan` ORs into a mask that still holds every earlier scan's hits (and, per
  packet, earlier segments of the connection), and continues the automaton from
  where the last scan stopped. Then copy up to `n = min(imm, SCAN_CAP, %end −
  cur)` bytes from the cursor into `st->buf`, then run **one `bpf_loop(n, …)`** that advances, per
  byte:
  - the **Aho-Corasick** automaton over *all literal patterns at once*
    (`ac_goto`/`ac_fail`/`ac_accept`): on an accepting state it ORs the accepting
    patterns' bits into `%m` and, for each *newly* matched pattern *k*, records
    `mpos[k] = (byte offset of the match end)`;
  - the **regex DFA** (`re_goto`/`re_accept`) over the same byte, ORing matched
    regex bits into `%m` too (a no-op when the program has no regexes).

  Bytes are folded to lower-case first when `nocase` is set. One pass answers
  every `any`/`all`/`seq`/regex question via `%m` and `mpos[]`.
- **Flags:** sets `%m` (not a flag) and `mpos[]`; leaves `ZF`/`CF`/`FF`
  untouched — follow it with `test`/`mpos` to branch.
- **Notes:** a match-mask **bit index == the pattern's id**; `SCAN_CAP` caps the
  window; up to `PFW_MAX_PATS = 64` patterns share the scan. The literal and
  regex automata are built host-side (`src/ac.js`, `src/regex.js`) into the `ac_*`
  / `re_*` maps.
- **Example:** `mask m = scan(payload, 1460);` then `any(m, a, b)` / `seq(m, a,
  b)`.

### 21 — `OP_MPOS` (`mpos $pat, %cur`)
- **Assembler:** `mpos $PAT, %cur` — `PAT` is a pattern name/id.
- **Encoding:** `code = 21`, `reg = pattern id (& 63)`, `imm = 0`.
- **Operation:** `cur ← mpos[pat]`, the byte offset **one past** where that
  pattern last matched in the preceding `scan` (0 if it never matched). On 0 the
  cursor is left unchanged and `FF` is set.
- **Flags:** may set `FF` (no match). **Faults:** a never-matched pattern faults —
  guard with the `test` that proved it matched, or `jf`.
- **Example:** jump the cursor to just after a matched marker, then parse the
  bytes that follow (`after(pat)` lowers to `mpos`).

### 22 — `OP_CMPSTR` (`cmpstr $pat, (%cur)`)
- **Assembler:** `cmpstr $PAT, (%cur)` — anchored; move the cursor first (disp
  must be 0).
- **Encoding:** `code = 22`, `reg = pattern id (& 63)`, `imm = 0`.
- **Operation:** compare the `len`-byte pattern against the window **at the
  cursor** (not a search — an anchored equality). `ZF ← (the first `len` bytes
  equal the pattern)`, honoring `nocase` folding on both sides. A zero-length or
  over-long pattern just clears the flags.
- **Flags:** sets `ZF`; preserves `FF`.
- **Example:** `starts(payload, get)` → `mov %payload,%cur; cmpstr $get,(%cur);
  jne …`.

### 23 — `OP_FINDB` (`findb $byte, $len`)
- **Assembler:** `findb $BYTE, $LEN`.
- **Encoding:** `code = 23`, `reg = byte (& 0xff)`, `imm = window length`
  (clamped to `SCAN_CAP`).
- **Operation:** set `FF`, then scan the window for the first occurrence of
  `byte`; on a hit, set `cur ←` that byte's **absolute offset** and **clear
  `FF`**; on no hit, leave the cursor and keep `FF` set. (The op writes the
  cursor and flags from inside its `bpf_loop` and advances the pc itself.)
- **Flags:** clears `FF` on hit, leaves it set on miss. **Faults:** a miss is a
  fault — follow with `jf`, or rely on the cursor being unchanged.
- **Example:** `ptr p = find(payload, ' ', 16);` — walk to the first space within
  16 bytes.

### 24 — `OP_SKIPB` (`skipb $byte[, $max]`)
- **Assembler:** `skipb $BYTE` or `skipb $BYTE, $MAX`.
- **Encoding:** `code = 24`, `reg = byte (& 0xff)`, `imm = max run`
  (`0` or `> PFW_PAT_CAP` ⇒ `PFW_PAT_CAP = 64`).
- **Operation:** count the leading run of `byte` in the window (up to `max`) and
  advance the cursor past it: `cur ← cur + run`. Never faults — a zero-length run
  just leaves the cursor where it was.
- **Flags:** none.
- **Example:** `skip(p, ' ')` after a `find` — eat the run of spaces so the
  cursor rests on the next field.

---

Covered: `OP_CMP_I (9)`, `OP_CMP_R (10)`, `OP_TEST (11)`, `OP_JMP (12)`,
`OP_JE (13)`, `OP_JNE (14)`, `OP_JB (15)`, `OP_JAE (16)`, `OP_JA (17)`,
`OP_JBE (18)`, `OP_JF (19)`, `OP_SCAN (20)`, `OP_MPOS (21)`, `OP_CMPSTR (22)`,
`OP_FINDB (23)`, `OP_SKIPB (24)`.
