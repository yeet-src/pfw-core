# 10. The regex dialect

`regex NAME = "...";` compiles to a DFA matched one byte per step (no
backtracking), sharing the `scan` match mask with literal patterns. Matching is
**unanchored** (matches anywhere in the window).

**Supported:** literals; `.` (any byte); classes `\d \w \s` and negations
`\D \W \S`; character sets `[a-z]`, `[^...]`, ranges; groups `( )`; alternation
`|`; quantifiers `? * + {n} {n,m} {n,}` (`*` and open-ended `{n,}` are capped at a
bounded repeat). Escapes `\n \r \t \0`.

**Not supported:** backreferences, lookaround (they need backtracking).

**Rewrite requires fixed length.** `redact`/`replace` overwrite a span in place,
so a regex used with them must match a **constant** number of bytes: literals and
classes are 1, concatenation sums, alternation arms must agree, `{n}` is `n×`;
`* + ? {n,m}` (with `n≠m`) and `{n,}` are variable and **rejected for rewrite**
(they are fine for detection with `scan`/`any`). `replace`'s replacement must
equal that fixed length.

```c
regex card = "\d{4}-\d{4}-\d{4}-\d{4}";   // fixed 19 -> redact/replace OK
regex email = "[a-z0-9._]+@[a-z0-9.]+";   // variable -> detect only
filter {
  if (any(scan(payload, 1460), email)) decide rst("pii", 0);  // detect
  replace(card, "XXXX-XXXX-XXXX-XXXX");                         // rewrite (same length)
  decide pass;
}
```

---
