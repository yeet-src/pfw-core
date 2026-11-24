# 9. Budgets

From `LIMITS` (`src/isa.js`) / `pfw.h`:

| limit | value | |
|---|---|---|
| instructions (`MAX_OPS`) | 65536 | per program; also the step ceiling |
| patterns (`MAX_PATS`) | 64 | one bit each in `%m` |
| pattern length (`PAT_CAP`) | 256 B | |
| skip run (`SKIP_CAP`) | 64 B | what one `skipb` passes over |
| scan window (`SCAN_CAP`) | 4096 B | and the `findb` window |
| AC states (`AC_STATES`) | 16384 | per generation |
| regex DFA states (`RE_STATES`) | 8192 | |
| scratch registers | 40 | `%s0`–`%s39`, reused by live range |
| subroutine args | 7 | `%a0`–`%a6`; return in `%rv` |
| data-stack depth (`STACK_CAP`) | 256 | `push`/`pop`, `call`/`ret` |
| rules (`NRULES`) | 1024 | named verdicts / counters |
| runtime args (`ARGC`) | 64 | `argv[i]` |
| numeric knobs (`KNOBS`) | 256 | `knob("name")` live control slots |
| string knobs (`KNOBSTRS`) | 64 | `kstr("name")`, ≤ `KNOBSTR_CAP = 64` B each |
| string-knob scan window (`KNOB_SCAN`) | 256 | payload bytes `kstr` searches |
| numeric args (`FARGS`) | 8 | per `console` or `emit` (`printk` takes 3) |
| console `%s` args (`FSTR`) | 2 | ≤ `STRARG = 256` B each |
| printk formats (`FMTS`) | 16 | ≤ `FMT_CAP = 64` B each, in-kernel |
| per-flow ring (`RING_CAP`) | 16 | newest-wins |
| rewrites per packet (`RW_MAX`) | 16 | recorded, applied by the rewrite stage |
| log snapshot (`LOG_CAP`) | 256 B | into the event |
| reassembly window (`REASM_CAP`) | 4096 B | per flow; slides, keeping `REASM_KEEP = 256` B |
| sources (`SRC_MAX`) | 262144 | LRU; per-source state and bans |
| NAT connections (`NAT_MAX`) | 65536 | LRU; `dnat` reply path |
| h2 dynamic table (`H2_DYN_SLOTS` × `H2_ENT_CAP`) | 64 × 256 B | per h2 connection, newest entries |
| h2 connections (`H2_CONNS`) | 1024 | LRU |
| flows (`MAX_FLOWS`) | 16384 | LRU |
| generations (`GENS`) | 2 | atomic program swap |

---

*Companion documents: [`lang.md`](lang.md) — the pfw-C language and how each
construct lowers to this ISA; [`primitives.md`](primitives.md) — the design note
on building higher-level features from the base primitives.*
