# 4. Expressions

Two expression grammars, by context:

- **Conditions** — used in `if (...)`, and as the first argument of the boolean
  grammar. Precedence, lowest to highest: `||` → `&&` → (`in` / `&` mask-test /
  comparison) → `|` (pattern-or) → primary. `!` negates a primary.
- **Value arithmetic** — used in `let`, assignment, `return <expr>`, and the
  `match`/`switch` scrutinee. A left-associative chain of `+ - & | << >>` over
  primaries. It has **no** comparisons or `in`; it is pure integer math.

Note `|` is overloaded by context: inside a condition's mask operand it is
**pattern-or** (grouping patterns for a mask test, e.g. `scan(...) & (a | b)`);
inside value arithmetic it is **bitwise-or**.

### Primaries

- literals (number, char, string), register reads, local reads;
- `(expr)`, `!primary`;
- `flow.state`, `flow.count` (§6), `ring.len`, `ring.get(i)` (§6),
  `frame.len`, `frame.type`, `frame.data` (valid only inside a `frame` body, §6);
- `argv[i] ?? default`, `argc` (§5);
- calls: `scan(...)`, `after(...)`, `find(...)`, `starts(...)`, `any/all/seq(...)`,
  `rate(...)`, `pop()`, and subroutine calls.

### Comparisons

`== != < > <= >=`. Ordered comparisons (`< > <= >=`) are **unsigned**.

```c
if (dport != 80) decide pass;
if (len > 1400) decide drop("too_big");
```

### Content matching

`scan(ptr, N)` runs the Aho-Corasick automaton over `N` bytes from `ptr`,
producing a mask. **`N` must be a compile-time constant.** Query the mask:

- `scan(...) & pat` or `mask & (p1 | p2)` — true if any listed pattern matched;
- `any(scan|mask, p1, p2, …)` — at least one matched;
- `all(scan|mask, p1, p2, …)` — every one matched (anywhere);
- `seq(scan|mask, p1, p2, …)` — matched in strictly increasing position order.

`any`/`all`/`seq` are **conditions, not values** — use them in `if (...)`, not as
something to store or return. Reuse one scan across several questions with a
`mask` local:

```c
mask m = scan(payload, 1460);
if (seq(m, kw_union, kw_select) && any(m, kw_comment)) decide drop("sqli");
if (any(m, passwd, cmd_exe)) decide rst("rce_probe", 0);
```

`regex` patterns participate in the same `scan`/`any`/… (they share the match
mask). The regex dialect is in §10.

### Cursor / field parsing

| form | result | notes |
|---|---|---|
| `after(pat)` | pointer one past where `pat` matched | |
| `find(ptr, 'c', N)` | pointer at the first `'c'` within `N` bytes | `N` constant |
| `starts(ptr, pat\|"lit")` | condition: does `ptr` begin with the pattern | |
| `skip(ptr, 'c');` | statement: advance the `ptr` local past a run of `'c'` | mutates the local |

```c
ptr path = find(payload, ' ', 16);   // to the first space
skip(path, ' ');                     // past the space(s)
if (starts(path, admin)) decide rst("admin_probe", 0);
```

### Source / set membership

| form | tests |
|---|---|
| `a in "10.0.0.0/8"` | `a` (an IPv4, host order — usually `src`) is in the inline CIDR |
| `a in set` | `a` is in the host-loaded LPM CIDR trie (`lpm`) |
| `src6 in set6` | the packet's IPv6 source is in the host-loaded v6 trie (`lpm6`) |
| `a in hash` | `a`'s low 32 bits are a key in the host-loaded exact set (`hash`) |
| `a in bloom` | `a`'s low 32 bits are (probably) in the host-loaded Bloom filter |

The host populates `set`/`set6`/`hash`/`bloom` out of band (see the README's
probe section). `src6 in set6` reads the v6 source from the packet itself — the
left operand is conventional (`src6`) and otherwise ignored.

```c
if (src in "10.0.0.0/8") decide pass;      // internal
if (src in set) decide drop("blocklist");  // host-loaded trie
if (dport in hash) decide rst("blocked_port", 0);
```

### Runtime parameters

`argv[i]` reads the *i*-th host-set runtime argument (`i` a literal `0..15`);
`argv[i] ?? default` supplies a literal fallback when the host set fewer than
`i+1` args; `argc` is how many were set. One compiled program, many deployments —
no recompile.

```c
if (dport != argv[0] ?? 80) decide pass;   // port tunable per deploy
if (len > argv[1] ?? 8192) decide drop("oversize");
```

`argv` reads anywhere a value is expected (comparisons, arithmetic, thresholds).
It is **not** usable as an argument to `rate` / `dnat` / `redirect` (those take
compile-time constants).

### `rate`

`rate(per_sec, burst)` is a per-flow token-bucket **condition**, true when the
flow is over its limit. Both arguments are compile-time constants.

```c
if (rate(5, 20)) decide drop("too_fast");  // 5/s steady, burst 20
```

### Calls as values and conditions

A subroutine call (`f(x)`) is usable as a value (its `%rv`), as a bare condition
(true when `%rv != 0`), or as a statement (§7). `pop()` is a value (§7).

---
