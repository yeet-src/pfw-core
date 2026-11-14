# 7. Subroutines — the calling convention

```c
fn is_scanner(ptr) {                 // up to 7 params
  if (any(scan(ptr, 1024), sqlmap, nikto)) return 1;
  return 0;                          // value return -> %rv
}
filter {
  if (is_scanner(payload)) decide ban("scanner", 3600);   // call as a condition
  let s = is_scanner(after(host));                         // call as a value
  decide pass;
}
```

- **Definition.** `fn name(p0, …, p6) { ... }` — up to **7 params**. Each param
  name aliases its argument register `%a0..%a6` for the body (a param is a
  readable/writable register). Subroutines are a **pfw-C source** construct (the
  DSL has no `fn`).
- **Arguments.** The caller evaluates each argument and loads `%a0..%a6` (args are
  staged through temporaries first, so a call-valued argument can't clobber an
  already-placed register). Arguments are untyped — pass integers, ports, IPs,
  lengths, flags, or **packet pointers** (`payload`, `after(pat)`, `find(...)`),
  so a routine can `scan`/`starts` from a pointer it is handed.
- **Return value.** `return <expr>;` sets `%rv` and returns to the caller. A call
  used as a value yields `%rv`; used as a bare condition it tests `%rv != 0`.
- **Verdicts inside a routine.** `decide drop(...)` / `decide pass` inside a `fn`
  is still a **terminal verdict** — it ends the whole program, it does not return
  to the caller. Use `return <expr>;` to return a value; `decide` to decide the
  packet.
- **Registers are caller-saved** across `%a0..%a6` and `%rv`: a nested call
  overwrites them, so save anything you still need (in a scratch local or on the
  stack) before calling again.
- **The data stack.** `call` pushes the return address onto the same stack that
  `push`/`pop` use, and `ret` pops it. So a routine must keep the stack
  **balanced** across a `ret` (equal pushes and pops) — otherwise `ret` would pop
  a data value as the return address. Pass data in registers; use `push`/`pop`
  for scratch within a balanced span. `%sp`/`%bp` are the stack and base pointers
  (set `bp = sp;` to mark a frame, `sp = bp;` to unwind it). Depth is 64.

```c
push(sport); push(dport); bp = sp;   // save a frame
push(len); sp = bp;                  // scratch, then unwind
let d = pop(); let s = pop();        // LIFO
```

---
