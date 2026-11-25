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
- **Follow a TCP stream** — `reassemble` matches the stream, not the packet,
  through a sliding window: a connection is followed for its whole life, and a
  signature split across segments (or across the window's edge) is seen whole.
- **Decode before matching** — normalize the stream through a front-end so
  signatures match the decoded bytes. `decode h2` parses cleartext HTTP/2 frames
  and HPACK (Huffman strings, the per-connection dynamic table, CONTINUATION) into
  `name: value` lines; also `decode huffman`, or a loadable byte-transform table.
- **Anchor a match** — `within(ptr, N)` reports only the patterns inside that
  window (a header value, a frame), where `scan` accumulates.
- **Keep per-connection state** — a user state machine (`flow.state`, with TTL),
  a hit counter (`flow.count`), and a 16-slot ring (`ring.push/get/len`).
- **Keep per-source state** — the same, keyed on the source address so it
  survives a reconnect: `src.state`, `src.count`, `src.rate(per_sec, burst)`.
- **Match the source** — inline CIDR (`src in "10.0.0.0/8"`), a host-loaded v4/v6
  CIDR trie (`src in set`, `src6 in set6`), an exact set (`x in hash`), or a
  Bloom filter (`x in bloom`).
- **Rate-limit** — a token bucket per connection (`rate(per_sec, burst)`) or per
  source address (`src.rate(per_sec, burst)`).
- **Rewrite the packet** — overwrite a match in place: `redact(pat[, 'c'])` fills
  it, `replace(pat, "same-length")` swaps it (literal patterns, or fixed-length
  regex); the L4 checksum is fixed up.
- **Steer the packet** — `dnat("a.b.c.d", port)` rewrites the destination (two-way:
  replies are translated back, so a TCP connection diverted from its SYN works),
  `redirect(ifindex)` forwards it out another interface (`XDP_REDIRECT`).
- **Factor logic into subroutines** — `fn name(a, b) { ... return <expr>; }`,
  called as a value/condition/statement; args in `%a0..%a6`, result in `%rv`;
  backed by a `call`/`ret` data stack (`push`/`pop`, `%sp`/`%bp`).
- **Branch on a value** — `match` (no fall-through) and C-style `switch`
  (fall-through + `break`) over `flow.state`, a port, a param, etc.
- **Be tuned at load time** — `argv[i] ?? default` reads host-set runtime
  parameters (one bytecode, many deployments); `%shadow` is a dry-run flag that
  turns enforcement into logged-but-passed.
- **Be driven live** — *knobs* are a named control plane the host rewrites while
  the program runs: `knob("name") ?? default` reads a numeric control value,
  `kstr("name")` is true when a host-set string occurs in the payload (change the
  bad host/token and block it with no reload), and `knob struct Name { … }` groups
  related knobs read as `Name.field`.
- **Observe** — `console("fmt", args...)` ships a printf-style message to the
  host (with a JS callback), `printk(...)` writes to the kernel trace pipe, and
  `log(n)` snapshots payload bytes onto a verdict event.
- **Act** — `decide pass | drop | rst | ban | count` (`rst` sends a TCP reset,
  `ban` bans the source address — every port, every connection — for a TTL,
  `count` is a non-blocking tally).

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
  | instructions | 65536 | per program |
  | patterns | 64 | `scan` matches all at once |
  | pattern length | 256 B | |
  | scan window | 4096 B | the matcher never reads past it |
  | automaton states | 16384 | across all literal patterns |
  | regex DFA states | 32768 | across all regex patterns, in up to 4 DFAs |
  | scratch registers | 40 | locals reuse them by live range |
  | subroutine args | 7 | `%a0..%a6`, result in `%rv` |
  | data stack depth | 256 | `push`/`pop`, `call`/`ret` |
  | rules | 1024 | named verdicts, per program |
  | runtime args | 64 | `argv[i]` |
  | knobs | 256 | `knob("name")` live control slots |
  | string knobs | 64 | `kstr("name")`, 64 B each |
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
import { PfwVm } from "pfw-core/loader";               // run it in the kernel (yeet runtime only)
```

### Compiling

| export | signature | returns |
|---|---|---|
| `load(src)` | `(string) -> Program` | a runnable `Program`; **throws** on a compile error |
| `compile(src)` | `(string) -> result` | `{ ok, errors, program, patterns, rules, listing, nocase, regex, consoleFormats, printkFormats, knobs, knobDefaults, knobStrs, structKnobs }` — never throws |
| `compileAst(ast)` | `(ast) -> result` | lower an AST (what `pfw-core/dsl.js` builds) directly |
| `compileToAsm(src)` | `(string) -> string` | the disassembly, for inspection |
| `assemble(text)` | `(string) -> result` | the AT&T-style assembler (same `result` shape, minus source-only fields) |

On failure `compile` returns `{ ok: false, errors: [{ line, text }] }`. On
success, `warnings` (`[{ line, text }]`) lists what compiled but probably is not
what was meant (a scan shorter than the reassembly window, for one), `program`
is the op/pattern record the kernel runs, `regex` is the compiled DFA
(or `null`), and `consoleFormats`/`printkFormats` map a format id
back to its string. The knob bindings tell a loader what live control values the
program expects: `knobs[slot]` is the knob name at that `knobs`-map slot,
`knobDefaults[slot]` its seeded initial value, `knobStrs[slot]` the string-knob
name at that `knob_strs`-map slot, and `structKnobs` the `{ name, base }` groups
declared with `knob struct`.

### The `Program` object

`load()` and the DSL's `C.program(...)` both return a `Program`:

| member | what it is |
|---|---|
| `p.exec(frame, opts)` | run through the reference interpreter → verdict (see *Running on the host*) |
| `p.bytes(gen = 0)` | the `programs` map value as a `Uint8Array` (`serializeProgram` under the hood) |
| `p.tables()` | the Aho-Corasick automaton `{ edges, fails, accepts }` for the `ac_*` maps |
| `p.program` | the op/pattern record (`{ ops, pats, nops, npats, nocase, reasm, decode, args, argc, fmts, … }`) |
| `p.patterns`, `p.rules` | the interned pattern list and rule-name table |
| `p.regex` | the regex DFAs (`{ nstates, trans, accept, starts, startOf }`) or `null` |
| `p.consoleFormats`, `p.printkFormats` | format strings by id |
| `p.knobs`, `p.knobDefaults`, `p.knobStrs` | live-control bindings: knob name / seeded default / string-knob name, by slot |
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
  source: {},          // per-source state (src.state / src.count / src.rate, bans): thread r.source back in
  argv: [8080, 50],    // runtime args for argv[i]
  shadow: false,       // dry-run flag (%shadow)
  knobs: { block: 1 }, // live numeric knobs by name (unset -> knobDefaults, else 0)
  knobStrs: { bad: "evil.example.com" }, // live string knobs by name (kstr)
  flow: {},            // carried per-connection state
  onConsole: (line) => {}, // called per console() message
});
// r = { verdict, code, would, rule, ruleName, flow, source, console }
```

`r.verdict` is the decision string; `r.would` is the would-be verdict when
`shadow` turned an enforcement into a pass; `r.console` is the array of formatted
`console()` messages. `r.source` is the source address's state after the packet
(`banned` once a `ban` landed): pass it back as `opts.source` and the next packet
from that source — on any connection — sees it, and is dropped unseen if banned.

`exec` runs over exactly the bytes you give it: it does not model TCP reassembly
or the `decode` front-ends. Those are covered against the real kernel
(`test:reasm`, `test:h2`, `test:examples-kernel`).

Thread `r.flow` back as `opts.flow` to **simulate a multi-packet connection**:

```js
let { flow } = p.exec(pkt1, { dport: 80 });
const r2 = p.exec(pkt2, { dport: 80, flow });  // sees state set by pkt1
```

The kernel applies state *writes* on the next packet (deferred), and the
interpreter models that exactly: a `flow.state = N` write is visible on the
following `exec`, not the one that made it.

## Embedding it in a yeet program (XDP)

`pfw-core/loader` is the kernel side as one object. `PfwVm` loads the XDP
interpreter, wires its stages, and gives the embedding program a lifecycle —
**start**, apply, steer, read, **stop** — instead of two dozen map bindings.

```js
import { load } from "pfw-core";
import { PfwVm } from "pfw-core/loader";      // yeet runtime only (it imports yeet:bpf)

const vm = new PfwVm({ iface: 2 });           // an ifindex, or several
await vm.start();                             // attached; no program yet, so everything passes

await vm.apply(load(ruleSource), { knobs: { enforce: 1 }, argv: [8080] });
vm.onVerdict((e) => console.log(e.verdict, e.rule, e.src, e.dport));
vm.onConsole((line) => console.log(line));

await vm.setKnob("enforce", 0);               // steer the running program, no reload
await vm.addCidrs(["203.0.113.0/24"]);        // `src in set`
await vm.apply(load(nextRuleSource));         // atomic swap; flows and bans are kept
await vm.route({ proto: "tcp", dport: 8443 }, load(apiRuleSource));   // that port gets its own program
console.log(await vm.stats());                // { seen, dropped, ..., rules: { name: hits } }

await vm.stop();                              // detached; the hook is free again
```

| method | what it does |
|---|---|
| `new PfwVm({ iface, object, base })` | `iface`: ifindex or array (default 1). `object`: path to `vm.bpf.o` (default: the package's `bin/vm.bpf.o`) |
| `start()` | load the object, attach every stage and the XDP entry. Passes all traffic until `apply`. Throws if already running or the hook is taken |
| `stop()` | detach and release everything in the kernel — maps, flow and source state, bans. Harmless to call twice; `start()` works again after |
| `running`, `program` | whether it is started; the compile result now enforcing |
| `apply(program, opts)` | put a `Program`, a `compile()` result or pfw-C source into effect as the default program: the one every packet runs that no route claims. Installed beside the one it replaces, then one flip. `opts`: `argv`, `knobs`, `knobStrs`, `tables`, `shadow` |
| `route(match, program, opts)`, `unroute(match)` | give some packets a program of their own, in place of the default. `match` names any combination of `iface` (interface index), `proto`, `dport` (with `proto`) and `dst` (an address or CIDR, v4 or v6). The more specific route wins, and the address decides first: the longest prefix the destination is in, a route with no `dst` counting as the shortest. Only between routes with the same prefix does the rest decide: a port, then a protocol, then an interface. Routing the same packets again swaps the program. Up to 64 programs are installed at once. `routes` lists them by name (`"tcp/8443"`, `"10.1.0.0/16"`, `"10.1.0.0/16 if2 udp"`) |
| `first(programs, opts)` | run a program, or an array of up to 8 in order, on every packet before the one it is dispatched to: each decides, or passes the packet on. A stage keeps its own per-connection state (`flow.state`, `flow.count`, the ring, the registers, `rate`, a scan carried across segments), apart from every other program's. It has no reassembled stream, so no `reassemble`, `decode`, `redact` or `replace`. The chain is swapped whole; `first(null)` removes it |
| `clear()` | stop enforcing but stay attached (standing bans still apply) |
| `setKnob(name, v)`, `setKnobStr(name, s)`, `setShadow(on)` | live control of the running program |
| `setTable(name, values, offset)` | fill a declared `table` live (or pass `tables` to `apply`); contents follow the name across programs |
| `setKv(entries)` / `deleteKv(keys)` | the `lookup(key)` map: 64-bit keys to 64-bit values, as a Map, pairs or an object |
| `addCidrs` / `removeCidrs`, `addHash` / `removeHash`, `addBloom` | the host-loaded sets (`src in set`, `src6 in set6`, `x in hash`, `x in bloom`) |
| `onVerdict(cb)`, `onConsole(cb)`, `onEmit(cb)`, `onSample(cb)` | events; each returns an unsubscribe function. A sample is `{ tag, data, wireLen, ts, ifindex }`: the frame's first bytes as a Uint8Array. An emit event is `{ name, values, ts, ifindex }`, the values as BigInt. A verdict event is `{ verdict, rule, src, dst, sport, dport, proto, data, ts, … }` with names, not ids |
| `stats()` | global counters since `start()`; per rule name since the program was applied (`applied` is the apply count, `applied_at` when), `rules` — the times it decided — and `enforced_rules` — the packets its standing marks and bans went on to stop, such as a dropped connection's retransmissions. Decisions and packets are kept apart throughout: `bans` counts `ban` verdicts only (a reset is in `rsts`), `shadowed` counts the verdicts shadow mode let through and `shadow_enforced` the packets a standing mark would then have stopped; `timing[rule] = { runs, ns }`, the decision time of the packets that ended on each rule (`"-"`: the ones that touched none); and `decide_hist`: how long decisions took, as `{ bounds, counts }` (`counts[i]` decisions under `bounds[i]` ns; one more count past the last bound) |

Things to know when embedding:

- **One per interface.** The kernel allows a single XDP program per interface, so
  a `PfwVm` owns the hook of the interfaces it starts on. A second `start()` on
  the same interface — from another `PfwVm` or any other program — fails until
  the first stops.
- **One program at a time.** `apply` replaces the running program; it does not
  add to it. Programs that must coexist have to be merged into one source.
- **Rule counts start at `apply`.** In the kernel a rule counter is a numbered
  slot, and the next program's rules reuse the slots. `stats().rules` subtracts
  what each slot held when the program went in, so a rule reads 0 after `apply`
  whatever the last program did there. `stats().applied` changes on every
  `apply`, for a consumer that keeps its own running totals.
- **`stop()` forgets.** Bans, flow state and counters live in the object's maps
  and go with it. `apply` and `clear` keep them.
- **A route's program is a whole program.** It has its own patterns, rules,
  instruction budget, `reassemble` and `decode`; nothing of the default runs on
  its packets. Knobs and tables are shared by name with every other installed
  program, and so are the sets and the `lookup` map. `stats().routes[name]`
  holds its `rules` and `timing`, and `stats().first` is the same for each stage
  program, in order; an event's `route` says which program raised it
  (`"default"`, `"first"`, `"first.1"`, or the route's name).
- **A knob two programs declare has one value.** What the host set wins. If it
  has set nothing, the knob keeps the default of the program that was installed
  first, for as long as a program declaring it stays installed: installing a
  second program never changes how the first one runs.
- **Standing source bans hold whatever program a packet would run**, and with
  none at all (`clear()`).
- **Knob values follow the name.** A value set with `setKnob` or `apply({ knobs })`
  is remembered and re-applied to any later program that declares that knob.
- **No version check yet** between this JS and the `vm.bpf.o` it loads: ship them
  together. The release package does (`make package` puts the object and the
  bundled JS side by side in `pkg/`); from a checkout, run `make bpf` first.

### Several programs on one interface

The kernel allows one XDP program on an interface. The VM is that program, and
what you install in it are programs it dispatches each packet to: a default,
any number with packets of their own, and optionally a chain every packet runs
first.

```js
const vm = new PfwVm({ iface: 2 });
await vm.start();

await vm.apply(load(defaultSource));                                  // every packet no route claims
await vm.route({ proto: "tcp", dport: 8443 }, load(apiSource));       // one port
await vm.route({ dst: "10.1.0.0/16" }, load(tenantSource));           // one destination prefix
await vm.route({ dst: "10.1.2.3", proto: "tcp", dport: 22 }, load(sshSource));
await vm.first([load(blocklistSource), load(rateLimitSource)]);       // every packet, before its own
```

**Which program a packet runs.** First the stages `first()` installed, in
order: any of them can stop it, and if all pass it goes on. Then one program:
the route with the longest `dst` prefix its destination is in — a route with no
`dst` counting as the shortest — and, between routes with the same prefix, the
one that names a port, then a protocol, then an interface. A packet no route
claims runs the default.

**Changing it while it runs.** `route()` or `apply()` again with the same
match swaps that program: the new one is installed beside the old and one write
switches to it. `unroute(match)` gives the packets back to whatever else claims
them, and `first(null)` removes the stages. `vm.routes` lists what is installed.

**What a program has to itself, and what it shares.** Each has its own
patterns, rules, instruction budget, `reassemble` and `decode`, and its own
state for every connection — two programs on one connection never read each
other's `flow.state`, count, ring or registers. Knobs, lookup tables, the sets
and the `lookup` map are shared by name. A stage has no reassembled stream,
so it may not `reassemble`, `decode`, `redact` or `replace`.

**What each one did.** `stats()` reports the default's rules, each route's
under `routes[name]`, and each stage's in `first`, and every event carries
`route`: `"default"`, `"first"`, `"first.1"`, or the route's name.

For more than one interface, give `iface` an array and name the interface in
the routes. [`examples/host/several-programs.mjs`](examples/host/several-programs.mjs)
is all of this as one script to run; the limits are 64 programs installed at
once and 8 stages.

`scripts/apply-and-hold.mjs` is a 50-line CLI over `PfwVm` that every kernel test
drives, and `scripts/loader-lifecycle.mjs` walks the whole lifecycle. To bind the
maps yourself instead, `src/loader.js` is the reference; the map list and the
`pfw_prog` / `pfw_event` / `pfw_console` layouts are in [`docs/isa.md`](docs/isa.md).

## Examples

[`examples/`](examples) is a small showcase: each program does something
structurally different, and each is **behaviour-tested** — a realistic attack
with the verdict and rule it must produce, realistic benign traffic (stock
`curl`, a browser, a multipart upload, real captured TLS ClientHellos and DNS
queries) that must pass, and a cross-check that runs every benign input through
every program (`test/node/examples-behavior.mjs`, part of `npm run test:node`).

| program | what it shows |
|---|---|
| [`crawlers.pfc`](examples/crawlers.pfc) | the minimal rule: a case-insensitive multi-pattern `scan` |
| [`blocklist.pfc`](examples/blocklist.pfc) | `src in set` — a host-loaded CIDR trie |
| [`sqli.pfc`](examples/sqli.pfc) | a scored WAF rule: regexes + literals in one scan, `after()` positions, per-source strikes |
| [`http_router.pfc`](examples/http_router.pfc) | cursor parse of the request line, a `fn`, method × path × source policy |
| [`json_depth.pfc`](examples/json_depth.pfc) | a pushdown automaton: `push`/`pop` tracking JSON nesting depth |
| [`dns_tunnel.pfc`](examples/dns_tunnel.pfc) | `frame` walking the length-prefixed labels of a DNS name (UDP) |
| [`tls_sni.pfc`](examples/tls_sni.pfc) | parsing a ClientHello down to the `server_name` extension |
| [`heartbleed.pfc`](examples/heartbleed.pfc) | TLS record walk + a length-consistency check, `flow.state` as a latch |
| [`os_fingerprint.pfc`](examples/os_fingerprint.pfc) | IP/TCP header field reads and arithmetic; observe-only |
| [`syn_flood.pfc`](examples/syn_flood.pfc) | per-source rate limit and ban (`src.rate`, `src.count`) |
| [`token_bucket.pfc`](examples/token_bucket.pfc) | per-connection `rate(per_sec, burst)` |
| [`fsm.pfc`](examples/fsm.pfc) | a protocol state machine with `match` on `flow.state` |
| [`port_knock.pfc`](examples/port_knock.pfc) | a multi-step state machine with TTLs |
| [`dlp_redact.pfc`](examples/dlp_redact.pfc) | in-place rewrite: `redact` / `replace` on fixed-length regexes |
| [`shadow_mode.pfc`](examples/shadow_mode.pfc) | dry-run enforcement (`shadow`) |
| [`multi_tenant.pfc`](examples/multi_tenant.pfc) | one bytecode tuned per deployment with `argv` |
| [`live_blocklist.pfc`](examples/live_blocklist.pfc), [`control_plane.pfc`](examples/control_plane.pfc) | live control: needles and dials the host changes at runtime (`kstr`, `knob`) |
| [`h2_guard.pfc`](examples/h2_guard.pfc), [`http2_rbac.pfc`](examples/http2_rbac.pfc), [`rapid_reset.pfc`](examples/rapid_reset.pfc) | `decode h2`: matching HPACK-decoded HTTP/2 |
| [`honeypot.pfc`](examples/honeypot.pfc), [`reroute.pfc`](examples/reroute.pfc) | steering: `dnat` / `redirect` |

The last two rows (`decode h2`, `dnat`/`redirect`) are things the host
interpreter does not model; those five are driven on live loopback by
`test/kernel/examples.mjs` instead.

[`contrib/`](contrib) holds another ~110 programs (web attack signatures, CVE
probes, service guards, DLP, live control with `knob`, …). They **compile** —
that is checked — but they are **not behaviour-tested**; treat them as starting
points, not as rules to deploy. See [`contrib/README.md`](contrib/README.md).

Two of the showcase, as you'd actually write them.

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
pattern helo = "HELO", auth = "AUTH ", admin = "CONFIG";
filter {
  if (proto != 6) decide pass;
  if (dport != 7000) decide pass;
  if (len == 0) decide pass;
  match (flow.state) {
    case 0 { if (starts(payload, helo)) { flow.state = 1 for 60; decide pass; } decide drop("no_greeting"); }
    case 1 { if (starts(payload, auth)) { flow.state = 2 for 300; decide pass; } decide drop("not_authenticated"); }
    case 2 { if (starts(payload, admin)) decide rst("admin_blocked", 0); decide pass; }
    default { decide drop("bad_state"); }
  }
}
```

## What's in the VM

- **ISA** — `src/isa.js` (host view) mirrored by `bpf/include/pfw.h` (the C
  contract). Change both or neither; a test asserts they agree.
- **Builder** — `src/builder/` (`#/builder`), an LLVM-IRBuilder-style op
  constructor (emit methods, label resolution, scratch-register allocation,
  pattern/rule interning) with `optext.js` for single-op disassembly. Every
  front-end targets it — one definition of how an op is built.
- **Front-ends** — `src/clang/` (`#/clang`, pfw-C: lex/parse/codegen),
  `src/dsl.js` (value builder), `src/fp.js` (combinators), `src/asm/` (`#/asm`,
  AT&T-style assembler: lex/operands/assemble).
- **Program** — `src/program/` (`#/program`), the runnable object `load()`/the
  DSL return, with `format.js` for the printf-style `console()`/`printk` formatter.
- **Bytecode** — `src/bytes/` (`#/bytes`): `serializeProgram` and map dumps.
- **Table builders** — `src/ac.js` (Aho-Corasick), `src/regex.js` (regex→DFA),
  `src/huffman/` (`#/huffman`, HPACK Huffman), `src/transform.js` (byte-transform
  tables).
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
npm run test:node     # file-reading guards (isa<->header sync, every program compiles, examples behave)
npm run test:verify   # load through yeetd so this kernel's verifier judges it
npm run test:kernel   # kernel differential: reference vs real kernel on loopback
```

Per-feature kernel tests (`test:rewrite`, `test:dnat`, `test:lpm`, `test:regex`,
`test:hash`, `test:bloom`, `test:lpm6`, `test:redirect`, `test:rate`, `test:argv`,
`test:shadow`, `test:console`, `test:printk`, `test:stack`, `test:call`,
`test:args`, `test:regex-rewrite`, `test:source`, `test:nat`, `test:reasm`,
`test:h2`, `test:mpos`, `test:lang` (the language features that otherwise only run on the host: ring, `flow.count`/`flow.state`, `seq`, `within`, `skip`, the frame walker, `switch`, macros, knob structs, `decode <table>` and `decode huffman`), `test:loader` (the `PfwVm` lifecycle), and `test:examples-kernel`, which drives the shipped example files with
curl and Node HTTP/2 clients) each load a program through `yeetd` and assert
on real loopback traffic; they need `yeetd` + loopback.
`npm run test:kernel:all` runs every one of them in turn (`scripts/kernel-tests.mjs`;
name some to run only those), and is what CI runs, one category to a runner
(`--group <name>`). Among them: `test:route`
(programs routed by port, interface and prefix; stage programs), `test:counts`
(a rule is counted when it decides, not once a packet), `test:midjoin` (a
connection older than the program is followed, not reset), and in `test:reasm`,
a segment many windows long read whole.

- **`test/isa/*.test.mjs`** (under `yeet test`, `npm run test:isa`): the ISA
  conformance vectors — a small program per case, asserting the registers,
  flags or verdict `docs/isa/` says each of the 75 opcodes leaves behind.
- **`test/unit/*.test.mjs`** (under `yeet test`): real programs through the
  reference interpreter, one file per feature, plus `ops.test.mjs` (every opcode,
  with a coverage gate), the front-end differentials (`dsl`/`fp` == source), and
  `fuzz.test.mjs`.
- **`test/node/*.mjs`**: `check-isa.mjs` (the `isa.js` ↔ `pfw.h` enums agree),
  `examples.mjs` (every `.pfc` in `examples/` and `contrib/` compiles) and
  `examples-behavior.mjs` (each `examples/` program does what its header says).
- **`test/kernel/*.mjs`**: the differential and per-feature kernel tests — load,
  apply, send loopback traffic, read the verdict from the event stream, assert it
  matches the reference.

**CI** (`.github/workflows/ci.yml`), on pull requests and pushes to `master`:
`test` runs the host suites — `test:node` under node 24 and 26, and `test:isa`
and `test:unit` with `yeet test`; `kernel-matrix` builds `bin/vm.bpf.o` and
loads it with `veristat` on 6.1, 6.6, 6.12, 6.18 and 7.2, plus bpf-next as a
non-gating column; `package` builds the release tarball, installs it into an empty
project and runs the ISA and unit suites against the installed copy. The live kernel tests are not run in CI.

**Releases**: on `master`, once those three pass, the tarball is published as
`pfw-core.tgz` on the `rolling` GitHub release (a prerelease, replaced on every
merge). It holds the compiled
`bin/vm.bpf.o` and the JavaScript bundled and minified — no sources — so the
consumer needs no BPF toolchain (`make package` builds the same thing into
`pkg/`):

```sh
gh release download rolling -R yeet-src/pfw-core -p pfw-core.tgz --clobber
npm install ./pfw-core.tgz
```

Its version is `<package version>-git<commit date>.g<commit>` (UTC,
`YYYYMMDDHHMMSS`), so builds order as the commits do and every one sorts below
the final `<package version>`; its `package.json` records the full commit as
`gitHead`. The repository is
private, so the download needs GitHub auth (`gh auth login`, or a token).

## Reference

- [`docs/isa.md`](docs/isa.md) — the complete instruction set, registers, memory
  model, map layout, and bytecode encoding.
- [`docs/lang.md`](docs/lang.md) — the pfw-C language: grammar, every statement
  and expression, the calling convention, and how each construct lowers.
- [`docs/primitives.md`](docs/primitives.md) — the design note on building higher
  features from the base primitives.
- [`docs/upgrade-notes.md`](docs/upgrade-notes.md) — what behaves differently for
  a program or a host written against an earlier version.
