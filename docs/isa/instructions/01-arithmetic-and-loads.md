# Arithmetic, moves, and loads

The data-movement core of the ISA: the halt sentinel, moves between the `%cur`
accumulator and the register file, integer arithmetic/bitwise ops on `%cur`, and
the packet/stream load. All arithmetic is on unsigned 64-bit words and wraps mod
2⁶⁴ (the kernel uses native `__u64`; the host interpreter masks with
`U64 = 2⁶⁴−1`). These ops operate purely on `%cur` and the registers — **none of
them touch `ZF`/`CF`**, and only `LOAD` touches `FF` (it *sets* it on a
fault). After every op the interpreter commits `%cur`, the flags, and
`pc ← pc+1`.

Each `pfw_op` is `{ code, reg, imm }` (`reg` is `u32`, `imm` is `u64`); `reg` is
masked `& (NREGS−1)` before use. See [bytecode encoding](../05-bytecode-encoding.md).

---

### 0 — `OP_END` (no mnemonic)

- **Assembler:** none. `END` is the implicit program terminator — the Builder
  does not expose it as a statement, and running off the end of the op array
  behaves identically.
- **Encoding:** code = 0; `reg`, `imm` unused.
- **Operation:** sets `verdict ← V_PASS` and halts the interpreter (the
  `bpf_loop`/host loop returns). Equivalent to `decide pass`.
- **Flags:** none.
- **Faults:** none.
- **Example:** reaching the end of `filter { … }` with no explicit verdict falls
  through here → `pass`.
- **Notes:** the one opcode with no textual form; it exists so a truncated or
  fully-executed program has a defined terminal verdict.

### 1 — `OP_MOV_RC` (`mov %REG, %cur`)

- **Assembler:** `mov %REG, %cur`.
- **Encoding:** code = 1; `reg` = source register index (0–31); `imm` unused.
  Emitted via `Builder.movToCur(reg)` (a register-slot op — `reg` is allocatable
  for virtual registers).
- **Operation:** `cur ← r[reg]`. Reads any register — packet fields (`%payload`,
  `%dport`, `%saddr`, …), scratch (`%s0…%s39`), `%m`, `%sp`/`%bp`, `%a0…%a6`,
  `%rv`, `%shadow`. Host and kernel identical.
- **Flags:** none.
- **Faults:** none.
- **Example:** `mov %saddr, %cur` — load the source IPv4 before a `cidr`/`lpm` test.
- **Notes:** the only way to get a register value into `%cur`; every expression
  that reads a register lowers to this.

### 2 — `OP_MOV_CR` (`mov %cur, %REG`)

- **Assembler:** `mov %cur, %REG` (a *writable* register: `%s0…%s39`, `%m`,
  `%end`, `%sp`, `%bp`, `%a0…%a6`, `%rv`; the other packet fields are read-only).
- **Encoding:** code = 2; `reg` = destination register index; `imm` unused.
  Emitted via `Builder.movFromCur(reg)`.
- **Operation:** `r[reg] ← cur`, **except** when `reg == R_CUR` (index 13), which
  is a no-op — writing `%cur` to itself is suppressed in both kernel
  (`if (reg != R_CUR)`) and host (`if (reg !== REG.cur)`).
- **Flags:** none.
- **Faults:** none.
- **Example:** `mov %cur, %s0` — spill the accumulator into a scratch register
  (how `let` locals are stored).
- **Notes:** writing to a read-only register index is not expressible from the
  front-ends; the assembler rejects it (`isWritable`).

### 3 — `OP_ADD_I` (`add $N, %cur`)

- **Assembler:** `add $N, %cur` (a negative `$N` is assembled as `OP_SUB_I`).
- **Encoding:** code = 3; `reg` unused; `imm` = the 64-bit addend.
- **Operation:** `cur ← (cur + imm) mod 2⁶⁴`.
- **Flags:** none.
- **Faults:** none.
- **Example:** `add $9, %cur` — step the cursor past a 9-byte header.
- **Notes:** arithmetic is modular; there is no overflow trap.

### 4 — `OP_SUB_I` (`sub $N, %cur`)

- **Assembler:** `sub $N, %cur`.
- **Encoding:** code = 4; `reg` unused; `imm` = the 64-bit subtrahend.
- **Operation:** `cur ← (cur − imm) mod 2⁶⁴`.
- **Flags:** none.
- **Faults:** none.
- **Example:** `sub $4, %cur`. Also emitted implicitly for a negative load
  displacement (see `LOAD`).
- **Notes:** wraps mod 2⁶⁴ (underflow is defined, not trapped).

### 5 — `OP_ADD_R` (`add %REG, %cur`)

- **Assembler:** `add %REG, %cur`.
- **Encoding:** code = 5; `reg` = addend register; `imm` unused. Register-slot op.
- **Operation:** `cur ← (cur + r[reg]) mod 2⁶⁴`.
- **Flags:** none.
- **Faults:** none.
- **Example:** `add %s0, %cur` — add a previously computed length.
- **Notes:** the register form of `ADD_I`; used by the compiler when the RHS of a
  `+` is a register rather than a constant.

### 6 — `OP_SUB_R` (`sub %REG, %cur`)

- **Assembler:** `sub %REG, %cur`.
- **Encoding:** code = 6; `reg` = subtrahend register; `imm` unused. Register-slot op.
- **Operation:** `cur ← (cur − r[reg]) mod 2⁶⁴`.
- **Flags:** none.
- **Faults:** none.
- **Example:** `sub %s0, %cur` — e.g. `%end − %payload` style length math.
- **Notes:** wraps mod 2⁶⁴.

### 7 — `OP_AND_I` (`and $MASK, %cur`)

- **Assembler:** `and $MASK, %cur`.
- **Encoding:** code = 7; `reg` unused; `imm` = the 64-bit mask.
- **Operation:** `cur ← cur & imm`.
- **Flags:** none.
- **Faults:** none.
- **Example:** `and $0, %cur` — the idiomatic "zero the accumulator" (then `add`
  a constant to load an immediate).
- **Notes:** there is no dedicated load-immediate op; `and $0` + `add $N` is the
  canonical constant-materialisation sequence (`loadConst` in the compiler).

### 8 — `OP_LOAD` (`movb`/`movw`/`movl`/`movq`, `movbew`/`movbel`/`movbeq`)

- **Assembler:** `mov{b,w,l,q} D(%REG), %cur` for little-endian, `movbe{w,l,q}
  D(%REG), %cur` for big-endian. Size suffix: `b`=1, `w`=2, `l`=4, `q`=8 bytes.
  A non-`%cur` base emits a `MOV_RC` first; a negative displacement `D` emits a
  `SUB_I -D` first and loads at displacement 0.
- **Encoding:** code = 8; `reg` packs the access: low 4 bits = `size` (1/2/4/8),
  bit 4 (`LOAD_BE = 16`) = big-endian flag; `imm` = the displacement added to the
  cursor. Emitted via `Builder.load(size, be, disp)`.
- **Operation:** effective address `off = cur + imm`; reads `size` bytes.
  On success `cur ← value` (little-endian by default; byte-swapped when the BE bit
  is set and `size > 1`). In normal mode the bytes come from the packet; in
  reassembly mode (`decode`/`reassemble`) from the flow's reassembled stream
  (`flow->reasm`, index masked to `REASM_CAP`). The host interpreter reads from
  the frame buffer, little-endian, swapping for BE.
- **Flags:** sets `FF` on a bounds failure; leaves `ZF`/`CF` untouched; does **not**
  clear `FF` on success.
- **Faults:** `FF` is raised and `%cur` is left unchanged when `off > 0xffff`,
  `off + size > %end`, or `size` is not 1, 2, 4 or 8 (the assembler only emits
  those; other bytecode faults rather than reading). `off` is computed mod 2⁶⁴,
  like all arithmetic, so `%cur = 2⁶⁴ − 1` with displacement 1 addresses
  offset 0. A subsequent `jf` branches on it (and clears it). This is
  how out-of-bounds reads are made safe for the verifier — the read is bounded,
  never trapping.
- **Example:** `movbew 0(%cur), %cur` — read a big-endian 16-bit field at the
  cursor (e.g. an HTTP/2 frame length high bytes); `movl 4(%cur), %cur` — a
  little-endian 32-bit field 4 bytes in.
- **Notes:** `off` is capped at `0xffff` regardless of `%end` — offsets beyond
  64 KiB always fault. Endianness only matters for `size > 1`.

### 36 — `OP_OR_I` (`or $N, %cur`)

- **Assembler:** `or $N, %cur`.
- **Encoding:** code = 36; `reg` unused; `imm` = the 64-bit mask.
- **Operation:** `cur ← cur | imm`.
- **Flags:** none.
- **Faults:** none.
- **Example:** `or $0x20, %cur` — set a bit (e.g. ASCII-lowercase a byte).
- **Notes:** the bitwise-OR counterpart to `AND_I`.

### 37 — `OP_SHL_I` (`shl $N, %cur`)

- **Assembler:** `shl $N, %cur`.
- **Encoding:** code = 37; `reg` unused; `imm` = the shift count.
- **Operation:** `cur ← (cur << (imm & 63)) mod 2⁶⁴`. The shift count is masked to
  6 bits in both kernel (`imm & 63`) and host (`imm & 63n`).
- **Flags:** none.
- **Faults:** none.
- **Example:** `shl $4, %cur` — build a nibble-shifted value.
- **Notes:** shifting by ≥ 64 is defined via the `& 63` mask (no UB), matching the
  x86/BPF shift semantics the kernel relies on.

### 38 — `OP_SHR_I` (`shr $N, %cur`)

- **Assembler:** `shr $N, %cur`.
- **Encoding:** code = 38; `reg` unused; `imm` = the shift count.
- **Operation:** `cur ← cur >> (imm & 63)` (logical/unsigned right shift).
- **Flags:** none.
- **Faults:** none.
- **Example:** `shr $8, %cur` — drop the low byte (e.g. after a `movbel` to take
  the top 3 bytes of a 4-byte big-endian read: `load 4be; shr $8`).
- **Notes:** unsigned — there is no arithmetic (sign-extending) shift; `%cur` has
  no sign.

### 64 — `OP_MUL_I` (`mul $N, %cur`)

- **Assembler:** `mul $N, %cur`. `N` is unsigned.
- **Encoding:** code = 64; `reg` unused; `imm` = the multiplier.
- **Operation:** `cur ← (cur × imm) mod 2⁶⁴`.
- **Flags:** none.
- **Faults:** none.
- **Example:** `mul $157, %cur` — spread neighbouring values before reducing them
  to a table index.

### 65 — `OP_MUL_R` (`mul %REG, %cur`)

- **Assembler:** `mul %REG, %cur`.
- **Encoding:** code = 65; `reg` = the register (masked like every register
  operand); `imm` unused.
- **Operation:** `cur ← (cur × r[reg]) mod 2⁶⁴`.
- **Flags:** none.
- **Faults:** none.

### 66 — `OP_MOD_I` (`mod $N, %cur`)

- **Assembler:** `mod $N, %cur`. The assembler refuses `$0`.
- **Encoding:** code = 66; `reg` unused; `imm` = the divisor.
- **Operation:** `cur ← cur mod imm`, unsigned, over all 64 bits.
- **Flags:** `FF` is set when `imm` is 0; `ZF`/`CF` are untouched.
- **Faults:** a zero divisor (only reachable in hand-built bytecode) leaves
  `cur = 0` and sets `FF`. There is no trap.
- **Example:** `fhash %cur; mod $65537, %cur` — a slot in a prime-sized table.

### 67 — `OP_MOD_R` (`mod %REG, %cur`)

- **Assembler:** `mod %REG, %cur`.
- **Encoding:** code = 67; `reg` = the register; `imm` unused.
- **Operation:** `cur ← cur mod r[reg]`, unsigned.
- **Flags:** `FF` is set when the register holds 0; `ZF`/`CF` are untouched.
- **Faults:** a zero divisor leaves `cur = 0` and sets `FF`; test it with `jf` if 0
  is not a safe answer.

### 68 — `OP_FHASH` (`fhash %cur`)

- **Assembler:** `fhash %cur`.
- **Encoding:** code = 68; `reg` and `imm` unused.
- **Operation:** `cur ←` a 32-bit hash of the packet's source address,
  destination address, source port, destination port and protocol. Each address
  is first folded to 32 bits (its four big-endian words XORed, so an IPv4 address
  folds to itself in host order); then, with `mix` the murmur3 finaliser:
  `h = mix(src); h = mix(h ^ dst); h = mix(h ^ (sport << 16 | dport)); h = mix(h ^ proto)`.
- **Flags:** none.
- **Faults:** none.
- **Host:** `flowHash({ saddr, daddr, sport, dport, proto })`, exported by the
  package root, is the same function, so a table built on the host is indexed the
  same way in the kernel. The conformance vectors pin its values.
- **Notes:** every packet of a connection in one direction hashes the same; the
  reply direction (addresses and ports swapped) does not. It is not keyed: it
  spreads flows, it does not resist someone choosing their source port.

---

**Covered:** `OP_END` (0), `OP_MOV_RC` (1), `OP_MOV_CR` (2), `OP_ADD_I` (3),
`OP_SUB_I` (4), `OP_ADD_R` (5), `OP_SUB_R` (6), `OP_AND_I` (7), `OP_LOAD` (8),
`OP_OR_I` (36), `OP_SHL_I` (37), `OP_SHR_I` (38), `OP_MUL_I` (64), `OP_MUL_R` (65),
`OP_MOD_I` (66), `OP_MOD_R` (67), `OP_FHASH` (68) — 17 opcodes.
