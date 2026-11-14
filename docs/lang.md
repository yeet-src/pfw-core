# pfw-C — the language reference

pfw-C is the C-style source language of `pfw-core`. A program inspects one packet
(or the reassembled stream) and reaches a verdict. The compiler (`src/clang.js`)
lexes and parses the source to an AST, then lowers it through the shared op
`Builder` to **pfw ISA** bytecode — the same bytecode the reference interpreter
and the eBPF/XDP backend execute. For the machine itself (opcodes, registers,
memory model, map layout, encoding) see [`isa.md`](isa.md); this document is the
*language*.

Three front-ends produce the identical AST and bytecode:

- **pfw-C source** — this language (`compile(src)` / `load(src)`).
- **the value builder** — `pfw-core/dsl.js`, the same constructs as composed JS
  values (`C.program(C.filter(...))`). It covers the expression/statement core but
  **not** the source-only constructs `fn` / `match` / `switch` / `push` / `pop`.
- **combinators** — `pfw-core/fp.js`, higher-order composition over the DSL.

Because they share one codegen, everything below describes the semantics of all
three; the pfw-C spelling is given first, the DSL constructor in passing.

---

## 1. Lexical structure

**Comments.** `// line` to end of line, and `/* block */` (non-nested).

**Identifiers.** `[A-Za-z_][A-Za-z0-9_]*`. Keywords (`if`, `filter`, `decide`, …)
are identifiers matched positionally — there is no separate reserved-word class,
but using a keyword as a name will not parse where the keyword is expected.

**Number literals.** Decimal (`80`, `1460`) or hex (`0x1f`, `0X80`). Integers
only; every value is a 64-bit unsigned quantity.

**Character literals.** `'c'` — one byte. Escapes: `\n` `\r` `\t` `\0` `\\` `\'`
`\"` and `\xHH` (two hex digits). A char literal is just its byte value.

**String literals.** `"..."`, used for patterns, CIDRs, rule names, and
format/IP arguments. In a *pattern* the bytes are unescaped with `\n \r \t \0 \\
\' \"` and `\xHH`; any other `\c` becomes the literal `c`.

**Byte-list patterns.** `{ 0xac, 0xed, 0x00, 0x05 }` — a comma-separated list of
number or char literals, for binary signatures.

```c
pattern java = { 0xac, 0xed, 0x00, 0x05 };   // Java serialization magic
```

**Punctuation / operators** (longest match first):

```
??  ==  !=  <=  >=  &&  ||  <<  >>
<   >   !   &   |   +   -   (   )   {   }   [   ]   ;   ,   =   .   @   :
```

---

## 2. Program structure

A program is a sequence of top-level items in **any order**, exactly one of which
is the required `filter` block:

```
nocase;                         // case-fold all matching
reassemble [PORT];              // match the coalesced TCP stream (optional dport filter)
decode h2|huffman|<table> [PORT];  // normalize the stream before matching (implies reassembly)
pattern NAME = "lit" | { bytes } [, NAME = ...];
regex NAME = "regex";
macro NAME { statements }       // a reusable statement block, expanded by `NAME;`
fn NAME(p0, …) { statements }   // a subroutine (§7)
filter { statements }           // REQUIRED — the program body
```

Pattern/`regex` references resolve regardless of declaration order. `decode`
takes a built-in front-end (`h2` HPACK headers, `huffman` HPACK-Huffman) or the
name of a loadable byte-transform table; it implies `reassemble`. The optional
`PORT` on `reassemble`/`decode` restricts reassembly to that TCP destination port
(`0`/omitted = every TCP flow).

```c
nocase;
reassemble 8080;
pattern gptbot = "GPTBot", claudebot = "ClaudeBot";
filter {
  if (dport != 80) decide pass;
  if (scan(payload, 1460) & (gptbot | claudebot)) decide rst("crawler", 60);
  decide pass;
}
```

---

## 3. Types and values

The machine is **untyped**: every register, local, literal, and argument is a
64-bit unsigned integer. What a value *means* is contextual — a byte, a port, a
host-order IPv4 address, a length, a flag, or a **pointer** (a byte offset into
the frame).

**Readable registers** (use the bare name in an expression):

| register | meaning |
|---|---|
| `payload` | offset of the L7 payload (the usual scan/parse cursor start) |
| `sport`, `dport` | TCP/UDP ports |
| `proto` | IP protocol (`6` TCP, `17` UDP) |
| `len` | payload length in bytes |
| `l3`, `l4` | offsets of the IP and transport headers |
| `end` | one past the last readable byte |
| `ifindex` | ingress interface index |
| `src` | source IPv4 address, host byte order |
| `frame` | offset 0 of the frame |
| `shadow` | the host-set dry-run flag (`%shadow`; see [`isa.md`](isa.md)) |
| `sp`, `bp` | data-stack pointer / base pointer (§7) |
| `a0`…`a6` | subroutine argument registers (§7) |
| `rv` | subroutine return-value register (§7) |

**Writable registers** (assignable with `name = expr;`): `sp`, `bp`, `rv`,
`a0`…`a6`. The rest are read-only inputs.

**Masks** — the result of a `scan`: the set of pattern bits matched in that pass,
queried with `any`/`all`/`seq` or `& pattern` (§5).

**Pointers** — byte offsets produced by `payload`, `after(pat)`, `find(ptr,'c',N)`
and consumed by `scan`/`starts`/`find`/`skip`.

**Patterns and regexes** — named byte signatures (`pattern`) or restricted
regexes (`regex`), both matched by `scan` (§5, §10).

---

## 4. Expressions

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

## 5. Statements

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
| `decide ban("rule", ttl);` | blocklist the source for `ttl` seconds (future packets dropped before the program runs), and drop this one |
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
- `redirect(ifindex);` — forward the packet out another interface
  (`XDP_REDIRECT`); terminal on the forward path.

Both take compile-time constants.

### Per-connection state

- `flow.state = N;` or `flow.state = N for SECONDS;` — set the connection's user
  state (optionally with a TTL after which it decays). Read with `flow.state`.
- `flow.count` — a read-then-increment per-connection hit counter (an expression).
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
  reuse the 8 scratch registers by live range). `expr` is value arithmetic.
- `name = expr;` — reassign an existing local, or write a **writable register**
  (`sp`/`bp`/`rv`/`a0`…`a6`).
- `mask name = scan(...);` — name a scan result (§4).
- `ptr name = payload | after(...) | find(...);` — name a pointer.

### Bounded repetition

Repetition is a **compile-time unroll** (there are no runtime loops):

- `repeat (N) { ... }` — emit the body `N` times (`N` a literal `0..1024`).
- `frame (len = TYPE @ OFF, type = TYPE @ OFF, head = N) [at PTR] up to MAX { ... }`
  — walk up to `MAX` length-prefixed records. Each record is a `head`-byte header
  (fields read by name + byte offset) followed by `len` payload bytes; the cursor
  advances `head + len` each iteration and `end` is narrowed to the record so a
  body `scan`/`load` stays inside it. In the body, `frame.len` / `frame.type` are
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

## 6. Per-connection state, rings, frames (recap)

`flow.state` (a small user state machine, with optional TTL), `flow.count` (a hit
counter), the per-flow `ring` (push/get/len), and the `frame` walker above are the
stateful/structural features. They persist across packets of the same connection
(state/count/ring) or structure one packet (`frame`). See [`isa.md`](isa.md) for
the backing map layout and the deferred-write model.

---

## 7. Subroutines — the calling convention

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

## 8. Lowering to the ISA

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
| `ring.push/get/len` | `RPUSH` / `RGET` / `RLEN` |
| `decide pass/drop/count/ban/rst`, `log` | `PASS` / `DROP` / `COUNT` / `BAN` / `RST`, `LOG` |
| `redact` / `replace` / `dnat` / `redirect` | `REDACT` / `REPLACE` / `DNAT` / `REDIRECT` |
| `argv[i]` / `argc` | `ARG` / `ARGC` |
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

## 9. Grammar (summary)

```ebnf
program     = { item } ;
item        = "nocase" ";"
            | "reassemble" [ number ] ";"
            | "decode" ident [ number ] ";"
            | "pattern" patdecl { "," patdecl } ";"
            | "regex" ident "=" string ";"
            | "macro" ident "{" { stmt } "}"
            | "fn" ident "(" [ ident { "," ident } ] ")" "{" { stmt } "}"
            | "filter" "{" { stmt } "}" ;      (* required, once *)
patdecl     = ident "=" ( string | "{" bytelist "}" ) ;

stmt        = block | if | match | switch | "break" ";"
            | "decide" verdict ";" | "return" arith ";"
            | ( "mask" | "ptr" ) ident "=" expr ";"
            | "let" ident "=" arith ";"
            | "repeat" "(" number ")" stmt
            | "frame" [ "at" primary ] "(" framefields ")" "up" "to" number stmt
            | "ring" "." "push" "(" expr ")" ";"
            | "flow" "." "state" "=" expr [ "for" expr ] ";"
            | ident "=" arith ";"          (* assign local / writable register *)
            | ident ";"                     (* macro expansion *)
            | ident "(" [ args ] ")" ";" ;  (* call / builtin statement *)
if          = "if" "(" expr ")" stmt [ "else" stmt ] ;
match       = "match" "(" arith ")" "{" { "case" prims block | "default" block } "}" ;
switch      = "switch" "(" arith ")" "{" { ("case" prims | "default") ":" { stmt } } "}" ;
verdict     = "pass" | "drop" "(" args ")" | "count" "(" args ")"
            | "ban" "(" args ")" | "rst" "(" args ")" ;

expr        = and { "||" and } ;                (* condition grammar *)
and         = compare { "&&" compare } ;
compare     = maskop [ "in" cidr-or-set ]
                     [ "&" maskop ] [ cmpop maskop ] ;
maskop      = primary { "|" primary } ;
arith       = primary { ("+"|"-"|"&"|"|"|"<<"|">>") primary } ;  (* value grammar *)
primary     = number | char | string | ident | "(" expr ")" | "!" primary
            | "flow" "." ("state"|"count") | "ring" "." ("len"|"get" "(" expr ")")
            | "frame" "." ("len"|"type"|"data")
            | "argv" "[" number "]" [ "??" (number|char) ] | "argc"
            | ident "(" [ args ] ")" ;         (* call *)
```

---

## 10. The regex dialect

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

## 11. Gotchas and limits

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
