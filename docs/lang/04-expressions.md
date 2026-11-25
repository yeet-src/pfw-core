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
- `flow.state`, `flow.count`, `flow.hash`, `flow.r0`–`flow.r3`, `flow.bytes`, `flow.packets`, `src.state`, `src.count` (§6), `ring.len`, `ring.get(i)` (§6),
  `frame.len`, `frame.type`, `frame.data` (valid only inside a `frame` body, §6);
- `argv[i] ?? default`, `argc`, `now` (§5);
- direct reads: `u8(p)`, `be16(p + 2)`, … (below);
- table cells: `NAME[index]`, and `lookup(key) ?? default` (below);
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

`== != < > <= >=`. Ordered comparisons (`< > <= >=`) are **unsigned**. Either
side may be value arithmetic, so a computed value is tested where it is
computed:

```c
if (flow.hash % 16 == 0) sample(64);          // one flow in sixteen
if (flow.bytes < flow.packets * 8) decide rst("slow_sender", 0);
if (u8(l4 + 13) & 18 == 2) count("syn");      // (flags & 18) == 2
```

Arithmetic binds tighter than the comparison, `&` included — unlike C, where
`x & 18 == 2` is `x & (18 == 2)`. After a `scan` or a mask variable `&` is still
the mask test, not the bitwise and. A sum on its own is not a condition: compare
it with something.

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

### Lookup tables

`table NAME[SIZE];` declares a table of `SIZE` 64-bit cells; `NAME[index]` reads
one. The host fills it — at load, and whenever it likes afterwards — so what a
program decides can be data rather than code:

```c
table backends[65537];                     // one backend per slot
filter {
  if (dport != 8181) decide pass;
  dnat(backends[flow.hash % 65537]);       // the cell is a whole dnat target
  decide pass;
}
```

That is a balancer whose backends change with no new program: the host
recomputes the table (Maglev, or any other assignment) and rewrites the slots.
`flow.hash` is the same function on the host, so its table lines up.

- A cell nobody set reads **0**. An index at or past `SIZE` reads 0 too, and
  never another table's cell.
- The index is value arithmetic. A cell is a value like any other: compare it,
  do arithmetic on it, pass it to `dnat` or `rate`.
- Tables share one space of 131072 cells (so a 65537-slot Maglev table fits,
  with room beside it); up to 16 tables.
- Contents follow the table's **name**: a new program that declares the same
  table starts with what the host last put in it. A new program's tables come
  into force together with the program, never half of one.

Where `x in hash` answers yes or no for a set of keys, a table answers *what*
for a dense range of indices.

### The key → value map

`lookup(key)` reads the value the host stored under a 64-bit key, for keys that
are sparse — an API key's hash, an address, a port worth naming — where a table
would be mostly empty:

```c
let tenant = lookup(key_hash);                 // 0 if the key is unknown
if (tenant == 0) decide rst("unknown_key", 0);
if (rate(lookup(tenant) ?? 5, 20)) decide drop("over_quota");
```

- A key that is not in the map yields **0**, or the literal after `??`. A key
  stored *with* the value 0 yields 0 either way: `??` is for absence.
- There is one map, shared by every program and kept across `apply`, like the
  sets. Programs that want separate namespaces put one in the key's high bits
  (`lookup(tenant + 0x100000000)`).
- Up to 262144 entries; keys and values are 64-bit.

### Source / set membership

| form | tests |
|---|---|
| `a in "10.0.0.0/8"` | `a` (an IPv4, host order — usually `src`) is in the inline CIDR |
| `a in set` | `a` is in the host-loaded LPM CIDR trie (`lpm`) |
| `src6 in set6` | the packet's IPv6 source is in the host-loaded v6 trie (`lpm6`) |
| `a in hash` | `a`'s low 32 bits are a key in the host-loaded exact set (`hash`) |
| `a in bloom` | `a`'s low 32 bits are (probably) in the host-loaded Bloom filter |

(For *what goes with* a key rather than whether it is known, see `lookup` above.)

The host populates `set`/`set6`/`hash`/`bloom` out of band (see the README's
probe section). `src6 in set6` reads the v6 source from the packet itself — the
left operand is conventional (`src6`) and otherwise ignored.

```c
if (src in "10.0.0.0/8") decide pass;      // internal
if (src in set) decide drop("blocklist");  // host-loaded trie
if (dport in hash) decide rst("blocked_port", 0);
```

### Runtime parameters

`argv[i]` reads the *i*-th host-set runtime argument (`i` a literal `0..63`);
`argv[i] ?? default` supplies a literal fallback when the host set fewer than
`i+1` args; `argc` is how many were set. One compiled program, many deployments —
no recompile.

```c
if (dport != argv[0] ?? 80) decide pass;   // port tunable per deploy
if (len > argv[1] ?? 8192) decide drop("oversize");
```

`argv` reads anywhere a value is expected: comparisons, arithmetic, thresholds,
and the arguments of `rate` and `dnat`. `redirect` and `scan`'s length still
want constants.

### Packet time

`now` reads the packet's arrival time in kernel-monotonic nanoseconds — one
reading taken as the packet enters, so every read of `now` in a program sees the
same value. It is a plain value, read anywhere a value is expected. The
reference interpreter has no clock, so it reads whatever time the host supplies
(0 by default); a program's use of `now` is checked against the kernel, not the
model.

An inter-packet gap on a flow comes from the per-flow ring. The ring holds
**32-bit** entries, so push `now`'s low 32 bits and take the difference mod
2³² — exact for any gap under ~4.3 seconds:

```c
let t = now & 0xffffffff;
ring.push(t);
if (ring.len >= 2) {
  let prev = ring.get(1);                     // the previous packet's time
  let gap = (t - prev) & 0xffffffff;          // nanoseconds since it
  if (gap < 1000000) decide drop("too_fast"); // < 1 ms apart
}
```

### Live control knobs

Where `argv` is positional and fixed at load, a **knob** is a *named* control the
host rewrites while the program runs — read fresh on every packet, so the host
retunes or re-targets a running rule with no reload. The compiler assigns each
name a slot; `compile()` exposes the `name → slot` bindings so a loader knows what
to write.

- `knob("name")` — reads the current numeric value (unset reads `0`). Usable
  anywhere a value is: comparisons, arithmetic, thresholds, and the arguments of
  `rate` and `dnat` — a limit or a backend the host changes with no reload.
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
(`cfg.rate`) — see [§2 Program structure](02-program-structure.md). Up to 256
numeric knobs and 64 string knobs per program.

### `rate`

`rate(per_sec, burst)` is a per-flow token-bucket **condition**, true when the
flow is over its limit. Written-out numbers are checked at compile time and
cost one instruction; either argument may instead be any value — a knob, a
local — so the host can retune a limit while the program runs. A computed
burst of 0 lets nothing through, which is what an unset knob reads as: seed it
(`knob("burst") ?? 20`).
`src.rate(per_sec, burst)` is the same with one bucket per **source address**,
shared by every connection that source opens (§6).

```c
if (rate(5, 20)) decide drop("too_fast");  // 5/s steady, burst 20
```

### Calls as values and conditions

A subroutine call (`f(x)`) is usable as a value (its `%rv`), as a bare condition
(true when `%rv != 0`), or as a statement (§7). `pop()` is a value (§7).

---
