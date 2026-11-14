# 11. Gotchas and limits

**Compile-time rules**

- `scan(ptr, N)` — `N` is a constant, never a variable or `argv`.
- `redact`/`replace` — literal pattern or **fixed-length** regex only; `replace`
  replacement must equal the match length.
- Verdicts use **`decide`**; `return` is a subroutine value. `return <verdict>`
  is a compile error that points you at `decide`.
- `any`/`all`/`seq`/`rate`/membership are **conditions**, not values — use them in
  `if`, don't store or `return` them.
- Subroutines: ≤ 7 params; `fn`/`match`/`switch`/`push`/`pop` are source-only
  (not in the DSL); keep the data stack balanced across a call; a0..a6/rv are
  caller-saved.
- `console`: ≤ 4 numeric args + ≤ 2 `%s` (packet pointer). `printk`: ≤ 3 numeric
  args, no `%s`.
- `argv` is not a `rate`/`dnat`/`redirect` argument (those need constants).

**Budgets** (`LIMITS` in `src/isa.js`, mirrored in `bpf/include/pfw.h`)

| limit | value |
|---|---|
| instructions / program | 8192 |
| patterns (`scan` matches all at once) | 64 |
| pattern length | 64 B |
| scan window | 2048 B |
| AC automaton states | 4096 |
| regex DFA states | 1024 |
| scratch registers (locals, by live range) | 8 |
| subroutine args | 7 (`%a0..%a6`) |
| data-stack depth | 64 |
| rules (named verdicts) | 64 |
| runtime args (`argv`) | 16 |
| per-flow ring | 16 |
| `console` %s capture | 256 B |
| `printk` formats / length | 8 / 64 B |

See [`isa.md`](isa.md) for the machine these compile to, and the README for the
public JS interface and loading a program into the kernel.
