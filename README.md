# pfw-core

The **programmable-firewall VM**: a small, forward-only instruction set for
packet/stream matching, three front-ends that compile to it (a C-style language,
a JS value builder, and functional combinators), a runnable reference
interpreter, and an eBPF/XDP backend that runs the *same* bytecode in the Linux
kernel — before a packet reaches the IP stack.

You write a rule once. `pfw-core` lowers it to bytecode + automaton tables that
either run on the host (the reference interpreter, for tests and simulation) or
load into the kernel (XDP, for line-rate enforcement). Both execute the same
program and are checked against each other.

```js
import { load } from "pfw-core";

const p = load(`
  nocase;
  pattern bot = "GPTBot", claudebot = "ClaudeBot";
  filter {
    if (dport != 80) decide pass;
    if (scan(payload, 1460) & (bot | claudebot)) decide rst("crawler", 60);
    decide pass;
  }
`);

p.exec(new TextEncoder().encode("GET / ... User-Agent: GPTBot"), { dport: 80 });
// -> { verdict: "rst", ruleName: "crawler", rule, code, flow, console }
```

`pfw-core` is a **library other yeet code imports** — a probe compiles a rule,
writes the resulting bytes into BPF maps, attaches the shipped XDP object, and
reads verdicts back. The public JS interface and that end-to-end flow are the
subject of this document; the exhaustive instruction and language references live
in [`docs/isa.md`](docs/isa.md) and [`docs/lang.md`](docs/lang.md).

## What a program can do

A program inspects one packet (or the reassembled stream) and reaches a verdict.
It can:

- **Match L7 content** — multi-pattern Aho-Corasick `scan` in a single pass:
  `any` / `all` / ordered-`seq` of signatures, case-insensitive, over a bounded
  window; plus **regex** patterns (a restricted, backtrack-free dialect compiled
  to a DFA) matched in the same scan.
- **Parse protocol fields without copying** — walk the cursor to a delimiter
  (`find`/`skip`), anchor a compare (`starts`), jump past a marker (`after`),
  read big/little-endian integers (`load`), and unroll a bounded loop over
  length-prefixed records (`frame ... up to N`).
- **Decode before matching** — normalize the stream through a front-end
  (`decode h2` HPACK, `decode huffman`, or a loadable byte-transform table) so
  signatures match the decoded bytes.
- **Keep per-connection state** — a user state machine (`flow.state`, with TTL),
  a hit counter (`flow.count`), and a 16-slot ring (`ring.push/get/len`).
- **Match the source** — inline CIDR (`src in "10.0.0.0/8"`), a host-loaded v4/v6
  CIDR trie (`src in set`, `src6 in set6`), an exact set (`x in hash`), or a
  Bloom filter (`x in bloom`).
- **Rate-limit** — a per-flow token bucket (`rate(per_sec, burst)`).
- **Rewrite the packet** — overwrite a match in place: `redact(pat[, 'c'])` fills
  it, `replace(pat, "same-length")` swaps it (literal patterns, or fixed-length
  regex); the L4 checksum is fixed up.
- **Steer the packet** — `dnat("a.b.c.d", port)` rewrites the destination,
  `redirect(ifindex)` forwards it out another interface (`XDP_REDIRECT`).
- **Factor logic into subroutines** — `fn name(a, b) { ... return <expr>; }`,
  called as a value/condition/statement; args in `%a0..%a6`, result in `%rv`;
  backed by a `call`/`ret` data stack (`push`/`pop`, `%sp`/`%bp`).
- **Branch on a value** — `match` (no fall-through) and C-style `switch`
  (fall-through + `break`) over `flow.state`, a port, a param, etc.
- **Be tuned at load time** — `argv[i] ?? default` reads host-set runtime
  parameters (one bytecode, many deployments); `%shadow` is a dry-run flag that
  turns enforcement into logged-but-passed.
- **Observe** — `console("fmt", args...)` ships a printf-style message to the
  host (with a JS callback), `printk(...)` writes to the kernel trace pipe, and
  `log(n)` snapshots payload bytes onto a verdict event.
- **Act** — `decide pass | drop | rst | ban | count` (`rst` sends a TCP reset,
  `ban` blocklists the source for a TTL, `count` is a non-blocking tally).

## What to expect

It is a **forward-only cursor machine**: one accumulator walks the bytes front to
back and never rewinds, and every *label* jump is forward. This is deliberate —
the compiled program must pass the **eBPF verifier** to run at XDP, so
termination is provable by construction. (The one controlled exception is
`call`/`ret`: a `ret` resumes at a return address popped at run time, bounded by
the interpreter's overall step budget, not by a backward label jump.)

Consequences to design around:

- No backward loops or unbounded iteration. Repetition is a compile-time unroll
  (`repeat`, `frame ... up to N`) with a fixed ceiling.
- Everything is bounded — a program is a fixed budget, not a general computer:

  | Limit | Value | |
  |---|---|---|
  | instructions | 8192 | per program |
  | patterns | 64 | `scan` matches all at once |
  | pattern length | 64 B | |
  | scan window | 2048 B | the matcher never reads past it |
  | automaton states | 4096 | across all literal patterns |
  | regex DFA states | 1024 | across all regex patterns |
  | scratch registers | 8 | locals reuse them by live range |
  | subroutine args | 7 | `%a0..%a6`, result in `%rv` |
  | data stack depth | 64 | `push`/`pop`, `call`/`ret` |
  | rules | 64 | named verdicts, per program |
  | runtime args | 16 | `argv[i]` |
  | per-flow ring | 16 | newest-wins |

- Packet **reads** are unrestricted; **writes** are the deliberate rewrite ops
  (`redact`/`replace`/`dnat`) with checksum fixup. Decode front-ends normalize a
  copy, not the wire.

## Public interface

ESM only (`"type": "module"`). The barrel is the package root; the authoring
front-ends are submodules so their short constructor names don't collide.

```js
import { load, compile, Program, serializeProgram, build, machine } from "pfw-core";
import * as C from "pfw-core/dsl.js";                 // the value builder
import { when, guard, allOf, each, rules } from "pfw-core/fp.js";  // combinators
```

### Compiling

| export | signature | returns |
|---|---|---|
| `load(src)` | `(string) -> Program` | a runnable `Program`; **throws** on a compile error |
| `compile(src)` | `(string) -> result` | `{ ok, errors, program, patterns, rules, listing, nocase, regex, consoleFormats, printkFormats }` — never throws |
| `compileAst(ast)` | `(ast) -> result` | lower an AST (what `pfw-core/dsl.js` builds) directly |
| `compileToAsm(src)` | `(string) -> string` | the disassembly, for inspection |
| `assemble(text)` | `(string) -> result` | the AT&T-style assembler (same `result` shape, minus source-only fields) |

On failure `compile` returns `{ ok: false, errors: [{ line, text }] }`. On
success, `program` is the op/pattern record the kernel runs, `regex` is the
compiled DFA (or `null`), and `consoleFormats`/`printkFormats` map a format id
back to its string (see *Observability*).

### The `Program` object

`load()` and the DSL's `C.program(...)` both return a `Program`:

| member | what it is |
|---|---|
| `p.exec(frame, opts)` | run through the reference interpreter → verdict (see *Running on the host*) |
| `p.bytes(gen = 0)` | the `programs` map value as a `Uint8Array` (`serializeProgram` under the hood) |
| `p.tables()` | the Aho-Corasick automaton `{ edges, fails, accepts }` for the `ac_*` maps |
| `p.program` | the op/pattern record (`{ ops, pats, nops, npats, nocase, reasm, decode, args, argc, fmts, … }`) |
| `p.patterns`, `p.rules` | the interned pattern list and rule-name table |
| `p.regex` | the regex DFA (`{ nstates, trans, accept }`) or `null` |
| `p.consoleFormats`, `p.printkFormats` | format strings by id |
| `p.asm` | the disassembly |

### Low-level building blocks

For driving the maps yourself (the `Program` methods wrap these):

| export | purpose |
|---|---|
| `serializeProgram(program, gen=0)` | program record → `programs` map value (`Uint8Array`) |
| `build(patterns, nocase)` | patterns → `{ edges, fails, accepts }` (the `ac_goto`/`ac_fail`/`ac_accept` tables) |
| `machine({ asm, tables, regex })` | the raw reference interpreter → `run(frame, payload, flow, opts)` |
| `mapModel`, `mapDump` | colored map dumps, for debugging |
| `buildHuffman`, `huffDecode`, `codes`, `headerText`, `TT_CELL` | the HPACK-Huffman decode table (RFC 7541) |
| `buildByteMap`, `TRANSFORM_TABLES`, `transformCells`, `TT_CELLS` | loadable byte-transform tables for `decode <table>` |
| `Builder`, `opText` | the op constructor every front-end targets; single-op disassembly |

### The ISA contract

Mirrors `bpf/include/pfw.h` (a test asserts they agree):

```js
import { OP, OP_NAME, REG, REG_NAME, LIMITS, VERDICT, DECODE, LOAD_BE, V } from "pfw-core";
```

`OP`/`REG` are the opcode and register enums, `LIMITS` the budgets in the table
above, `VERDICT`/`V` the verdict codes (`pass`/`drop`/`ban`/`rst`).

## Three ways to author a program

All three lower to the **same** AST and the same bytecode — pick by taste.

**1. pfw-C source** — the C-style language. `load(src)` returns a `Program`
(throws on error); `compile(src)` returns the full result without throwing.

```js
const p = load(`pattern bot="GPTBot"; filter { if (scan(payload,256)&bot) decide rst("x",0); decide pass; }`);
```

**2. JS value builder (DSL)** — the same constructs as composable JS values. Good
when the rule is generated from data.

```js
import * as C from "pfw-core/dsl.js";
const p = C.program(
  C.nocase(),
  C.pattern("bot", "GPTBot"),
  C.filter(
    C.iff(C.ne(C.dport, 80), C.pass()),
    C.iff(C.band(C.scan(C.payload, 1460), "bot"), C.rst("crawler", 60)),
    C.pass(),
  ),
); // -> a Program
```

**3. Functional combinators** — higher-order composition over the DSL: `guard`,
`when`/`unless`, `allOf`/`anyOf`/`none`, and fragments generated from a list.

```js
import * as C from "pfw-core/dsl.js";
import { guard, rules, each } from "pfw-core/fp.js";

const BOTS = ["gptbot", "claudebot", "bytespider"];
const p = C.program(
  C.nocase(), ...BOTS.map((b) => C.pattern(b, b)),
  rules(
    guard(C.ne(C.dport, 80), C.pass()),
    each(BOTS, (b) => guard(C.band(C.scan(C.payload, 1460), b), C.rst("crawler", 60))),
    C.pass(),
  ),
);
```

## Running on the host

`Program.exec(frame, opts)` runs the bytes through the reference interpreter —
the executable spec the kernel is checked against. Use it for tests and
simulation.

```js
const r = p.exec(frameBytes, {
  payload: 0,          // offset of the L7 payload within frame (default 0)
  proto: 6,            // IP protocol (6 = TCP, 17 = UDP)
  dport: 80, sport: 0, // ports
  src: "203.0.113.9",  // source IPv4 (string) or saddr as a u32
  src6: "2001:db8::1", // source IPv6 (for `src6 in set6`)
  set: ["10.0.0.0/8"], hashset: [80, 443], bloom: [1, 2], set6: ["2001:db8::/32"],
  bucket: {}, now: 0n, // token-bucket state + clock for rate()
  argv: [8080, 50],    // runtime args for argv[i]
  shadow: false,       // dry-run flag (%shadow)
  flow: {},            // carried per-connection state
  onConsole: (line) => {}, // called per console() message
});
// r = { verdict, code, would, rule, ruleName, flow, console }
```

`r.verdict` is the decision string; `r.would` is the would-be verdict when
`shadow` turned an enforcement into a pass; `r.console` is the array of formatted
`console()` messages.

Thread `r.flow` back as `opts.flow` to **simulate a multi-packet connection**:

```js
let { flow } = p.exec(pkt1, { dport: 80 });
const r2 = p.exec(pkt2, { dport: 80, flow });  // sees state set by pkt1
```

The kernel applies state *writes* on the next packet (deferred), and the
interpreter models that exactly: a `flow.state = N` write is visible on the
following `exec`, not the one that made it.

## Using it from a yeet probe (XDP)

The host and kernel run identical bytes. A probe compiles the rule, binds the
shipped XDP object's maps, writes the artifacts, attaches, and reads events. The
kernel object is `bin/vm.bpf.o` (built by `make bpf`).

```js
import { compile, build } from "pfw-core";
import { BpfObject, ArrayMap, LpmTrie, HashMap, BloomFilter, RingBuf } from "yeet:bpf";

const c = compile(ruleSource);
if (!c.ok) throw new Error(JSON.stringify(c.errors));

const control = await new BpfObject({ exe: "bin/vm.bpf.o", base: root })
  .bind("programs", { kind: "array" })
  .bind("ac_goto", { kind: "array" }).bind("ac_fail", { kind: "array" }).bind("ac_accept", { kind: "array" })
  .bind("re_goto", { kind: "array" }).bind("re_accept", { kind: "array" })  // regex DFA
  .bind("lpm", { kind: "lpm_trie" }).bind("lpm6", { kind: "lpm_trie" })      // src in set / set6
  .bind("hashset", { kind: "hash" }).bind("bloom", { kind: "bloom_filter" })
  .bind("flows", { kind: "lru_hash" }).bind("stack", { kind: "percpu_array" })
  .bind("events", { kind: "ringbuf", btf_struct: "pfw_event" })
  .bind("console_ring", { kind: "ringbuf", btf_struct: "pfw_console" })
  .bind("vm.bss", { kind: "data" })
  .attach("pfw_xdp", { kind: "xdp", ifindex: [ifindex] })
  .start();

// write the program into programs[0] (the typed `pfw_prog` value — field order
// per pfw.h; apply-and-hold's progValue() builds it), then the automaton tables:
const t = build(c.patterns, c.nocase);
// ... programs[0] = { nops, npats, ops, pats, args, argc, fmts, … } ...
// ... write t.edges -> ac_goto, t.fails -> ac_fail, t.accepts -> ac_accept ...
// ... if (c.regex) write c.regex.trans -> re_goto, c.regex.accept -> re_accept ...
// ... populate lpm/hashset/bloom from your source/port sets ...

await new RingBuf(control, "events").subscribe((e) => {/* verdict events */});
```

`scripts/apply-and-hold.mjs` is the **complete, working reference** for this: it
binds every map, writes the program + AC tables + regex DFA + the membership sets
+ the printk formats, patches `vm.bss` globals (`active`, `shadow`), and streams
verdict and `console()` events back. `test/kernel/*.mjs` drive it. The full map
list and the `pfw_prog` / `pfw_event` / `pfw_console` layouts are in
[`docs/isa.md`](docs/isa.md).

## Examples

133 complete pfw-C programs live in [`examples/`](examples); every one is compiled
by `npm run test:node`. A few, as you'd actually write them:

**Reset AI crawlers by user-agent** ([`crawlers.pfc`](examples/crawlers.pfc)):

```c
nocase;
pattern gptbot = "GPTBot", claudebot = "ClaudeBot", bytespider = "Bytespider";
filter {
  if (dport != 80) decide pass;
  if (scan(payload, 1460) & (gptbot | claudebot | bytespider)) decide rst("crawler", 60);
  decide pass;
}
```

**A protocol state machine with `match`** ([`fsm.pfc`](examples/fsm.pfc)) — one
arm per connection phase, no fall-through:

```c
reassemble 7000;
pattern helo = "HELO", auth = "AUTH ", admin = "CONFIG";
filter {
  if (len == 0) decide pass;
  match (flow.state) {
    case 0 { if (starts(payload, helo)) { flow.state = 1 for 60; decide pass; } decide drop("no_greeting"); }
    case 1 { if (starts(payload, auth)) { flow.state = 2 for 300; decide pass; } decide drop("not_authed"); }
    case 2 { if (starts(payload, admin)) decide rst("admin_blocked", 0); decide pass; }
    default { decide drop("bad_state"); }
  }
}
```

**Subroutines with args + a return value** ([`args.pfc`](examples/args.pfc)):

```c
nocase;
pattern sqlmap = "sqlmap", nikto = "nikto";
fn has_scanner(ptr) {                       // ptr is a packet pointer
  if (any(scan(ptr, 1024), sqlmap, nikto)) return 1;
  return 0;
}
filter {
  if (dport != 80) decide pass;
  if (has_scanner(payload)) decide ban("scanner", 3600);
  decide pass;
}
```

Highlights across the set — web attacks (`log4shell`, `sqli`, `xss`, `ssrf_metadata`,
`path_traversal`, `jwt_none`, `xxe`), bots/DoS (`scanner_ban`, `http_flood`,
`rapid_reset`, `slowloris`, `honeypot`, `dns_ratelimit`), protocols/services
(`tls_sni`, `grpc_gate`, `redis_guard`, `smtp_filter`, `ssh_bruteforce`), DLP
(`card_leak`, `ssn_leak`, `secret_scan`, `canary`, `banner_hide`), and network
(`anti_spoof`, `geoblock`, `tor_block`, `conn_limit`), capped by
[`waf_suite.pfc`](examples/waf_suite.pfc), a full scored WAF built from subroutines.

## What's in the VM

- **ISA** — `src/isa.js` (host view) mirrored by `bpf/include/pfw.h` (the C
  contract). Change both or neither; a test asserts they agree.
- **Builder** — `src/builder.js`, an LLVM-IRBuilder-style op constructor (emit
  methods, label resolution, scratch-register allocation, pattern/rule
  interning). Every front-end targets it — one definition of how an op is built.
- **Front-ends** — `src/clang.js` (pfw-C), `src/dsl.js` (value builder),
  `src/fp.js` (combinators), `src/asm.js` (AT&T-style assembler).
- **Program** — `src/program.js`, the runnable object `load()`/the DSL return.
- **Bytecode** — `src/bytes.js` (`serializeProgram`, map dumps).
- **Table builders** — `src/ac.js` (Aho-Corasick), `src/regex.js` (regex→DFA),
  `src/huffman.js` (HPACK Huffman), `src/transform.js` (byte-transform tables).
- **Reference interpreter** — `src/interp.js`, `pfw_step` modelled
  line-for-line: the executable spec the tests assert against.
- **eBPF backend** — `bpf/vm/` (entry + decode/rewrite stages + `core/*.h`), the
  once-verified kernel interpreter that reads exactly the bytes
  `serializeProgram`/`build` produce. `make bpf` → `bin/vm.bpf.o`.

## Build & test

```sh
make bpf              # compile the eBPF backend to bin/vm.bpf.o
npm test              # the full host suite: test:node then test:unit
npm run test:unit     # yeet test test/unit — behavioral conformance
npm run test:node     # file-reading guards (isa<->header sync, every example compiles)
npm run test:verify   # load through yeetd so this kernel's verifier judges it
npm run test:kernel   # kernel differential: reference vs real kernel on loopback
```

Per-feature kernel tests (`test:rewrite`, `test:dnat`, `test:lpm`, `test:regex`,
`test:hash`, `test:bloom`, `test:lpm6`, `test:redirect`, `test:rate`, `test:argv`,
`test:shadow`, `test:console`, `test:printk`, `test:stack`, `test:call`,
`test:args`, `test:regex-rewrite`) each load a program through `yeetd` and assert
on real loopback traffic; they need `yeetd` + loopback.

- **`test/unit/*.test.mjs`** (under `yeet test`): real programs through the
  reference interpreter, one file per feature, plus `ops.test.mjs` (every opcode,
  with a coverage gate), the front-end differentials (`dsl`/`fp` == source), and
  `fuzz.test.mjs`.
- **`test/node/*.mjs`**: `check-isa.mjs` (the `isa.js` ↔ `pfw.h` enums agree) and
  `examples.mjs` (every `examples/*.pfc` compiles).
- **`test/kernel/*.mjs`**: the differential and per-feature kernel tests — load,
  apply, send loopback traffic, read the verdict from the event stream, assert it
  matches the reference.

## Reference

- [`docs/isa.md`](docs/isa.md) — the complete instruction set, registers, memory
  model, map layout, and bytecode encoding.
- [`docs/lang.md`](docs/lang.md) — the pfw-C language: grammar, every statement
  and expression, the calling convention, and how each construct lowers.
- [`docs/primitives.md`](docs/primitives.md) — the design note on building higher
  features from the base primitives.
