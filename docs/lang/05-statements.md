# 5. Statements

### Blocks and conditionals

```c
if (cond) stmt [else stmt]
{ stmt; stmt; }
```

### `match` — one arm, no fall-through

Dispatch on a value; exactly one arm runs. Arms are block-delimited; `case` takes
one or more constant labels; `default` is optional.

```c
match (flow.state) {
  case 0      { if (starts(payload, helo)) { flow.state = 1 for 60; decide pass; } decide drop("no_greeting"); }
  case 1, 2   { decide pass; }     // shared arm
  default     { decide drop("bad_state"); }
}
```

### `switch` — C-style fall-through

Colon labels and statement lists; control falls through to the next case until a
`break;`. `default:` may appear anywhere.

```c
switch (dport) {
  case 80:
    log(1);
    // falls through
  case 443:
    count("web");
    break;
  default:
    decide drop("other");
}
```

`break;` exits the nearest enclosing `switch`/`match`.

### Verdicts — `decide`

`decide` is the **terminal action** (verdicts use `decide`; `return` is for
subroutine values, §7):

| verdict | effect |
|---|---|
| `decide pass;` | allow the packet |
| `decide drop("rule");` | drop it (`XDP_DROP`) |
| `decide rst("rule", ttl);` | send a TCP reset (IPv4 TCP; else drop) |
| `decide ban("rule", ttl);` | ban the **source address** for `ttl` seconds — every later packet from it, on any port or connection, is dropped before the program runs — and drop this one |
| `decide count("rule");` | tally the rule — **non-terminal**, execution continues |

`drop`/`ban`/`rst`/`count` take a rule name (bareword or `"string"`) that labels
the event and per-rule counter; `ban`/`rst` also take a TTL in seconds.
`count` is a measurement, not a stop — it (and the bare `count("r");` statement)
tally and fall through.

### Non-blocking observation

- `count("rule");` — tally (same as `decide count`, non-terminal).
- `log(n);` — attach up to `n` payload bytes to the emitted event for userspace.
- `console("fmt", args…);` — printf-style message to the host (a JS callback
  receives it). Conversions `%d %i %u %o %x %X %c %%` take numeric args (≤ 4) and
  `%s` captures up to 256 bytes from a **packet pointer** (≤ 2). The format
  strings live host-side; only ids + args cross the ring.
- `printk("fmt", args…);` — `bpf_trace_printk` to the kernel trace pipe. Numeric
  conversions only (≤ 3 args); **`%s` is not supported** — use `console`.

```c
console("req to :%d says %s", dport, payload);
printk("pfw: scanner from sport %d", sport);
```

### Packet rewrite

Overwrite a match in place; the L4 checksum is fixed up. The target is a literal
`pattern` or a **fixed-length** `regex` (§10).

- `redact(pat);` / `redact(pat, 'c');` — fill every match with `'c'` (default `*`).
- `replace(pat, "repl");` — overwrite with a **same-length** replacement.

```c
regex ssn = "\d{3}-\d{2}-\d{4}";   // fixed length 11 -> rewritable
redact(ssn);                        // 123-45-6789 -> ***********
replace(key, "AKIAXXXXXXXXXXXXXXXX"); // same length as the match
```

### Packet steering

- `dnat("a.b.c.d", port);` — rewrite the destination IPv4 + port and forward.
  Two-way: the kernel records the connection and translates the replies back, so
  TCP works. It cannot move an established connection — call it on every packet
  of the connections to divert, from the first one (typically gated on
  `src.state`).
- `redirect(ifindex);` — forward the packet out another interface
  (`XDP_REDIRECT`); terminal on the forward path.

Both take compile-time constants.

### Per-connection state

- `flow.state = N;` or `flow.state = N for SECONDS;` — set the connection's user
  state (optionally with a TTL after which it decays). Read with `flow.state`.
- `flow.count` — a per-connection hit counter (an expression). Every read
  increments it first and yields the new value, so the first read is 1; read it
  once into a `let` if you need the value twice.
- `src.state = N;` / `src.state = N for SECONDS;`, `src.count`, and the condition
  `src.rate(per_second, burst)` — the same three, keyed on the **source address**
  instead of the connection, so they hold across every connection a source opens.
- `ring.push(v);` / `ring.get(i)` / `ring.len` — a 16-slot newest-wins per-flow
  ring (push is a statement; get/len are expressions).

Writes are applied by the kernel on the **next** packet (deferred); the reference
interpreter models this exactly.

```c
if (len == 0) decide pass;
ring.push(len);
let recent = ring.get(0) + ring.get(1) + ring.get(2);
if (recent > 3000) { if (flow.state == 1) decide rst("bulk_exfil", 0); flow.state = 1 for 60; }
```

### Locals and assignment

- `let name = expr;` — a named integer local (held in a scratch register; locals
  reuse the 16 scratch registers by live range). `expr` is value arithmetic.
- `name = expr;` — reassign an existing local, or write a **writable register**
  (`sp`/`bp`/`rv`/`a0`…`a6`).
- `mask name = scan(...);` — name a scan result (§4).
- `ptr name = expr;` — name a pointer: `payload`, `after(...)`, `find(...)`, or
  arithmetic on one (`ptr q = payload + 5;`). A pointer is an offset, so the
  same value arithmetic as `let` applies; `ptr` is what `skip` asks for.

### Bounded repetition

Repetition is a **compile-time unroll** (there are no runtime loops):

- `repeat (N) { ... }` — emit the body `N` times (`N` a literal `0..1024`).
- `frame (len = TYPE @ OFF, type = TYPE @ OFF, head = N) [at PTR] up to MAX { ... }`
  — walk up to `MAX` length-prefixed records. Each record is a `head`-byte header
  (fields read by name + byte offset) followed by `len` payload bytes; the cursor
  advances `head + len` each iteration and `end` is narrowed to the record so a
  body `scan`/`load` stays inside it. A walk holds three registers while its
  body runs (four with a `type` field), so walks nest: `frame at (frame.data)`
  inside a body walks the records within a record. In the body, `frame.len` / `frame.type` are
  the parsed header fields and `frame.data` points at this record's payload.
  Field types: `u8 u16 u32 be16 be24 be32`; `len` required, `type` optional,
  `head` is `1..255`, `MAX` is `1..64`.

```c
frame (len = be24 @ 0, type = u8 @ 3, head = 9) up to 8 {
  if (frame.type == 1) {                      // HTTP/2 HEADERS
    if (scan(frame.data, 1024) & bot) decide rst("h2_bot", 0);
  }
}
```

### Macros and calls

- `NAME;` — expand the `macro NAME { ... }` block here (compile-time, non-recursive).
- `NAME(args);` — call the subroutine `fn NAME` (§7).
- `push(v);` / `pop()` — the data stack (§7).

---
