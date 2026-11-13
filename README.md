# pfw-core

The **programmable-firewall VM**: a small, forward-only instruction set for
packet/stream matching, a C-style language (`pfw-C`) that compiles to it, the
bytecode other code loads, a reference interpreter, and an eBPF/XDP backend that
runs the same bytecode in the kernel.

Other projects import this to *lower programs onto the VM* — compile a rule to
bytecode + automaton tables, then run it either in the reference interpreter
(host, for tests and simulation) or on the kernel interpreter (XDP).

```js
import { compile, serializeProgram, build, machine } from "pfw-core";

const c = compile(`
  pattern bot = "GPTBot";
  filter {
    if (dport != 80) return pass;
    if (scan(payload, 1460) & bot) return rst("crawler", 60);
    return pass;
  }
`);

const programBytes = serializeProgram(c.program);   // the `programs` map value
const tables = build(c.patterns, c.nocase);          // the ac_goto/ac_fail/ac_accept tables
// ...load those into the kernel maps, or run them on the host:
const run = machine({ asm: c, tables });
const { verdict } = run(packetBytes, /*payloadOffset*/ 0, { ac: 0, mask: 0n }, { dport: 80 });
```

## What's in the VM

- **ISA** — `src/isa.js` (host view) mirrored by `bpf/include/pfw.h` (the C
  contract). A forward-only, straight-line machine (termination is guaranteed):
  a cursor, scratch registers, a match mask, flags, and an Aho-Corasick `scan`.
- **Assembler** — `src/asm.js`, AT&T-style text → program.
- **pfw-C compiler** — `src/clang.js`, source → assembly → program.
- **Bytecode** — `src/bytes.js`, the `programs` map value (`serializeProgram`).
- **Table builders** — `src/ac.js` (Aho-Corasick) and `src/huffman.js` (the
  HPACK Huffman decode table, built from RFC 7541 and baked into
  `bpf/include/huff_table.h`).
- **Reference interpreter** — `src/interp.js`, `pfw_step` modelled line-for-line,
  the executable spec the tests assert against.
- **eBPF backend** — `bpf/pfw.bpf.c`, the once-verified kernel interpreter that
  reads exactly the bytes `serializeProgram`/`build` produce. `make bpf`.

## Primitives

Built on top of the base matching ISA (see `docs/primitives.md`):

| | |
|---|---|
| **P2** `decode huffman` | HPACK-Huffman-decode the stream before matching — "a decoding is data" |
| **P3** `ring` | per-flow newest-wins ring (`ring.push/get/len`) — the HPACK dynamic-table / rate-limit shape |
| **P4** `frame` | bounded walk over length-prefixed records (`frame (...) up to N { ... }`) |
| **P5** `cidr` | source-address membership (`src in "10.0.0.0/8"`) |

`docs/isa.md` is the full instruction reference.

## Build & test

```sh
make bpf              # compile the eBPF backend to bin/app.bpf.o
npm test              # yeet test — the behavioral conformance suite
npm run check         # the above + the isa.js <-> pfw.h static guard
npm run gen:huff      # regenerate bpf/include/huff_table.h from src/huffman.js
```

The conformance suite (`test/*.test.mjs`) runs under `yeet test`: it runs real
programs through the reference interpreter and asserts on the verdict. The
`isa.js <-> pfw.h` sync is a separate node guard (`test/check-isa.mjs`) because it
reads the C header, which the test sandbox cannot.

## Internal imports

Modules reference each other through the `#/` subpath map (package.json
`imports`), the same convention the yeet daemon uses: `#/src/isa.js`,
`#/examples/index.js`, etc.
