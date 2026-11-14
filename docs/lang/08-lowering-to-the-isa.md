# 8. Lowering to the ISA

Each construct lowers to ISA ops through the `Builder`; op names below are the
`OP.*` enum in [`isa.md`](isa.md).

| construct | emits |
|---|---|
| register/local read, literal | `MOV_RC`, `AND_I`/`ADD_I` (materialize a constant) |
| `name = expr`, `let` | compute into `%cur`, `MOV_CR` to the register/local |
| `a + b`, `& | << >>` | `ADD_I/SUB_I/AND_I/OR_I/SHL_I/SHR_I` or `ADD_R/SUB_R` |
| comparison | `CMP_I`/`CMP_R` + a conditional jump (`JE/JNE/JB/JAE/JA/JBE`) |
| `scan` | `SCAN`; `& pat`/`any`/`all` → `TEST`; `seq` → `MPOS` + `CMP_R` |
| `starts` / `find` / `after` / `skip` | `CMPSTR` / `FINDB` / `MPOS` / `SKIPB` |
| `load` (frame field) | `LOAD` (size + byte order packed in the operand) |
| `a in "cidr"` / `set` / `hash` / `bloom` / `set6` | `CIDR` / `LPM` / `HASH` / `BLOOM` / `LPM6` |
| `rate` | `RATE` |
| `flow.state` / `= N for` | `SLOAD` / `SSTORE`; `flow.count` → `BUMP` |
| `within(ptr, N)` | `SCAN` with the fresh bit (clears `%m` and the automaton first) |
| `src.state` / `src.count` / `src.rate(r, b)` | the same ops (`SLOAD`/`SSTORE`/`BUMP`/`RATE`) with the source scope set |
| `ring.push/get/len` | `RPUSH` / `RGET` / `RLEN` |
| `decide pass/drop/count/ban/rst`, `log` | `PASS` / `DROP` / `COUNT` / `BAN` / `RST`, `LOG` |
| `redact` / `replace` / `dnat` / `redirect` | `REDACT` / `REPLACE` / `DNAT` / `REDIRECT` |
| `argv[i]` / `argc` | `ARG` / `ARGC` |
| `knob("n")` / `knob("n") ?? d` / `cfg.field` | `KNOB $slot` (default seeded into the slot at load) |
| `kstr("n")` | `KNOBHAS $slot` (`ZF` = needle found) |
| `console` / `printk` | `FARG`/`FARGS` + `CONSOLE` / `PRINTK` |
| `push` / `pop` / call / `return` | `PUSH` / `POP` / `CALL` / `RET` (value return: `MOV_CR %rv` + `RET`) |
| `if` / `match` / `switch` | compare + forward jumps (`JE/JNE/JMP`), one scrutinee eval into a temp |
| `repeat` / `frame` | the body emitted inline, N / up-to-MAX times |

**Forward-only.** Every *label* jump goes forward; there are no backward loops.
Repetition is the compile-time unroll above. The one controlled exception is
`ret`, which resumes at a return address popped at run time — bounded by the
interpreter's overall step budget, not a backward label. This is what lets a
program pass the eBPF verifier.

---
