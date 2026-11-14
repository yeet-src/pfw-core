# pfw-C — the language reference

pfw-C is the C-style source language of `pfw-core`. A program inspects one packet
(or the reassembled stream) and reaches a verdict. The compiler (`src/clang.js`)
lexes and parses the source to an AST, then lowers it through the shared op
`Builder` to **pfw ISA** bytecode — the same bytecode the reference interpreter
and the eBPF/XDP backend execute. For the machine itself (opcodes, registers,
memory model, map layout, encoding) see [`isa.md`](isa.md); this document is the
*language*.

Three front-ends produce the identical AST and bytecode:

- **pfw-C source** — this language (`compile(src)` / `load(src)`).
- **the value builder** — `pfw-core/dsl.js`, the same constructs as composed JS
  values (`C.program(C.filter(...))`). It covers the expression/statement core but
  **not** the source-only constructs `fn` / `match` / `switch` / `push` / `pop`.
- **combinators** — `pfw-core/fp.js`, higher-order composition over the DSL.

Because they share one codegen, everything below describes the semantics of all
three; the pfw-C spelling is given first, the DSL constructor in passing.

---

## Contents

- [1. Lexical structure](lang/01-lexical-structure.md)
- [2. Program structure](lang/02-program-structure.md)
- [3. Types and values](lang/03-types-and-values.md)
- [4. Expressions](lang/04-expressions.md)
- [5. Statements](lang/05-statements.md)
- [6. Per-connection state, rings, frames (recap)](lang/06-per-connection-state-rings-frames-recap.md)
- [7. Subroutines — the calling convention](lang/07-subroutines-the-calling-convention.md)
- [8. Lowering to the ISA](lang/08-lowering-to-the-isa.md)
- [9. Grammar (summary)](lang/09-grammar-summary.md)
- [10. The regex dialect](lang/10-the-regex-dialect.md)
- [11. Gotchas and limits](lang/11-gotchas-and-limits.md)
