# 4. Expressions

Two expression grammars, by context:

- **Conditions** — used in `if (...)`, and as the first argument of the boolean
  grammar. Precedence, lowest to highest: `||` → `&&` → (`in` / `&` mask-test /
  comparison) → `|` (pattern-or) → primary. `!` negates a primary.
- **Value arithmetic** — used in `let`, assignment, `return <expr>`, the
  `match`/`switch` scrutinee and a read's pointer. `*` and `%` bind tightest;
  `+ - & | << >>` are one level below them, left to right (so `a + b << 1` is
  `(a + b) << 1`: parenthesise when mixing them). `( … )` groups. It has **no**
  comparisons or `in`; it is pure unsigned 64-bit integer math, wrapping.

  `+ - * %` take a constant, a register/local, or a parenthesised expression on
  the right; `& | << >>` take a constant. `x % 0` is a compile error when the 0
  is written out, and yields 0 at run time when it is not.

Note `|` is overloaded by context: inside a condition's mask operand it is
**pattern-or** (grouping patterns for a mask test, e.g. `scan(...) & (a | b)`);
inside value arithmetic it is **bitwise-or**.

### Primaries

- literals (number, char, string), register reads, local reads;
- `(expr)`, `!primary`;
- `flow.state`, `flow.count`, `flow.hash`, `src.state`, `src.count` (§6), `ring.len`, `ring.get(i)` (§6),
  `frame.len`, `frame.type`, `frame.data` (valid only inside a `frame` body, §6);
- `argv[i] ?? default`, `argc` (§5);
- direct reads: `u8(p)`, `be16(p + 2)`, … (below);
- calls: `scan(...)`, `after(...)`, `find(...)`, `starts(...)`, `any/all/seq(...)`,
  `rate(...)`, `pop()`, and subroutine calls.

### Reading the packet

`TYPE(ptr)` reads one field at a pointer and is a value like any other. The
argument is value arithmetic, so the offset is written where it is used.

| type | bytes | order |
|---|---|---|
| `u8` | 1 | — |
| `u16` `u32` `u64` | 2, 4, 8 | little-endian |
| `be16` `be24` `be32` `be64` | 2, 3, 4, 8 | big-endian (network order) |

```c
let opening = u8(l4 + 13) & 18;         // TCP flags: SYN set, ACK clear
if (opening == 2) count("connections");
let qtype = be16(name_end);              // a field wherever a pointer has got to
let p = payload + u8(payload);           // a length byte, used as an offset
```

A read that runs past the end of the data — the packet's, or the current
record's inside a `frame` body — yields **0**. It does not fault, so test the
length first if 0 is a value the field can really hold.

`frame` (§5) is still the tool for *walking* records; a read is for the one
field at a known offset, which used to take a one-record `frame`.

### The flow hash

`flow.hash` is a 32-bit hash of the packet's source and destination address,
ports and protocol — the same for every packet of a connection in one
direction. It is what a balancer reduces to a slot:

```c
let slot = flow.hash % 65537;            // a prime-sized table
```

The host has the same function (`flowHash`, exported by `pfw-core`), so a
table built there is indexed identically in the kernel.

### Comparisons

`== != < > <= >=`. Ordered comparisons (`< > <= >=`) are **unsigned**.

```c
if (dport != 80) decide pass;
if (len > 1400) decide drop("too_big");
```

### Content matching

`scan(ptr, N)` runs the Aho-Corasick automaton over `N` bytes from `ptr`,
producing a mask. **`N` must be a compile-time constant.** Query the mask:

`within(ptr, N)` is the same scan started fresh: the match mask and the
automaton are cleared first, so the result is exactly the patterns inside
`[ptr, ptr+N)`. Use it to anchor a test to a region you located with the cursor
(`after`, `find`, `frame.data`) — a second `scan` would still report whatever an
earlier scan saw elsewhere.

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

### Live control knobs

Where `argv` is positional and fixed at load, a **knob** is a *named* control the
host rewrites while the program runs — read fresh on every packet, so the host
retunes or re-targets a running rule with no reload. The compiler assigns each
name a slot; `compile()` exposes the `name → slot` bindings so a loader knows what
to write.

- `knob("name")` — reads the current numeric value (unset reads `0`). Usable
  anywhere a value is (comparisons, arithmetic, thresholds), but **not** as a
  `rate`/`dnat`/`redirect` argument.
- `knob("name") ?? default` — the loader seeds `default` into the slot at load
  time. It is a seeded initial value, **not** a run-time if-zero, so the host can
  still override it to any value, `0` included.
- `kstr("name")` — a **condition**, true when the host-set string for that name
  occurs in the payload (a bounded substring search over the first 256 bytes).
  Change the needle and the match changes — block a bad host/token with no reload.

```c
if (knob("block") == 1) decide drop("kill_switch");  // flip live
if (len > knob("cap") ?? 8192) decide drop("oversize");
if (kstr("bad_host")) decide rst("blocked", 0);      // live blocklist entry
```

Related names are grouped with a `knob struct` declaration and read as fields
(`cfg.rate`) — see [§2 Program structure](02-program-structure.md). Up to 32
numeric knobs and 16 string knobs per program.

### `rate`

`rate(per_sec, burst)` is a per-flow token-bucket **condition**, true when the
flow is over its limit. Both arguments are compile-time constants.
`src.rate(per_sec, burst)` is the same with one bucket per **source address**,
shared by every connection that source opens (§6).

```c
if (rate(5, 20)) decide drop("too_fast");  // 5/s steady, burst 20
```

### Calls as values and conditions

A subroutine call (`f(x)`) is usable as a value (its `%rv`), as a bare condition
(true when `%rv != 0`), or as a statement (§7). `pop()` is a value (§7).

---
