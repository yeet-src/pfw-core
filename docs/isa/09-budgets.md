# 9. Budgets

From `LIMITS` (`src/isa.js`) / `pfw.h`:

| limit | value | |
|---|---|---|
| instructions (`MAX_OPS`) | 8192 | per program; also the step ceiling |
| patterns (`MAX_PATS`) | 64 | one bit each in `%m` |
| pattern length (`PAT_CAP`) | 64 B | |
| scan window (`SCAN_CAP`) | 2048 B | and the `findb` window |
| AC states (`AC_STATES`) | 4096 | per generation |
| regex DFA states (`RE_STATES`) | 1024 | |
| scratch registers | 8 | `%s0`–`%s7`, reused by live range |
| subroutine args | 7 | `%a0`–`%a6`; return in `%rv` |
| data-stack depth (`STACK_CAP`) | 64 | `push`/`pop`, `call`/`ret` |
| rules (`NRULES`) | 64 | named verdicts / counters |
| runtime args (`ARGC`) | 16 | `argv[i]` |
| console numeric args (`FARGS`) | 4 | per `console`/`printk` call |
| console `%s` args (`FSTR`) | 2 | ≤ `STRARG = 256` B each |
| printk formats (`FMTS`) | 8 | ≤ `FMT_CAP = 64` B each, in-kernel |
| per-flow ring (`RING_CAP`) | 16 | newest-wins |
| rewrites per packet (`RW_MAX`) | 4 | recorded, applied by the rewrite stage |
| log snapshot (`LOG_CAP`) | 256 B | into the event |
| reassembly buffer (`REASM_CAP`) | 2048 B | per flow |
| flows (`MAX_FLOWS`) | 16384 | LRU |
| generations (`GENS`) | 2 | atomic program swap |

---

*Companion documents: [`lang.md`](lang.md) — the pfw-C language and how each
construct lowers to this ISA; [`primitives.md`](primitives.md) — the design note
on building higher-level features from the base primitives.*
