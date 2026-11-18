# The pfw ISA — architecture reference

This is the authoritative reference for the pfw virtual machine: the register
file, the memory model, every instruction, the bytecode encoding, and the maps
the program runs against. It is the contract shared by the host
(`src/isa.js`, `src/interp.js`) and the kernel (`bpf/include/pfw.h`,
`bpf/include/match/interp.h`); a test (`test/node/check-isa.mjs`) asserts the two
enums agree.

Counts, verified against `src/isa.js`:

- **69 opcodes** (`OP_END = 0` … `OP_FHASH = 68`; `OP_COUNT_OPCODES = 69`).
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

## Contents

- [1. Machine model](isa/01-machine-model.md)
- [2. Registers](isa/02-registers.md)
- [3. Memory model](isa/03-memory-model.md)
- [4. Instruction set](isa/04-instruction-set.md)
- [5. Bytecode encoding](isa/05-bytecode-encoding.md)
- [6. Maps and globals](isa/06-maps-and-globals.md)
- [7. Verdicts and actions](isa/07-verdicts-and-actions.md)
- [8. Decode front-ends and the rewrite stage](isa/08-decode-front-ends-and-the-rewrite-stage.md)
- [9. Budgets](isa/09-budgets.md)
