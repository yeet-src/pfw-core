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
    if (dport != 80) return pass;
    if (scan(payload, 1460) & (bot | claudebot)) return rst("crawler", 60);
    return pass;
  }
`);

p.exec(new TextEncoder().encode("GET / ... User-Agent: GPTBot"), { dport: 80 });
// -> { verdict: "rst", ruleName: "crawler", rule, code, flow }
```

## What it can do

A program inspects one packet (or the reassembled stream) and returns a verdict.
It can:

- **Match L7 content** — multi-pattern Aho-Corasick `scan` in a single pass:
  any / all / ordered-sequence of signatures, case-insensitive, over a bounded
  window.
- **Parse protocol fields without copying** — walk the cursor to a delimiter
  (`find`/`skip`), anchor a compare (`starts`), jump past a marker (`after`),
  read big/little-endian integers (`load`).
- **Walk framed protocols** — a bounded unrolled loop over length-prefixed
  records (e.g. HTTP/2 HEADERS frames).
- **Decode before matching** — normalize the stream through a front-end
  (HPACK-Huffman, or a loadable byte-transform table) so signatures match the
  decoded bytes.
- **Keep per-connection state across packets** — a user state machine
  (`flow.state`, with TTL), a hit counter (`flow.count`), and a 16-slot ring
  (`ring.push/get/len`): rate limits, protocol gates, sequence tracking.
- **Filter by source** — CIDR membership (`src in "10.0.0.0/8"`).
- **Act** — `pass`, `drop`, `rst` (TCP reset), `ban` (blocklist the source for a
  TTL), and the non-blocking `count` / `log` for passive measurement.

See [`docs/isa.md`](docs/isa.md) for the full instruction reference and
[`docs/primitives.md`](docs/primitives.md) for how the higher-level features are
built from the base ISA.

## What to expect

It is a **forward-only, straight-line cursor machine** — one accumulator walks
the bytes front to back and never rewinds, and every jump is forward. This is
the central constraint, and it is deliberate: the compiled program must pass the
**eBPF verifier** to run at XDP, so termination has to be provable by
construction. What you get in return is a rule that runs safely in the kernel at
line rate.

Consequences to design around:

- No backward loops or unbounded iteration. Repetition is a compile-time unroll
  (`repeat`, `frame ... up to N`) with a fixed ceiling.
- Everything is bounded. A program is a fixed budget, not a general computer:

  | Limit | Value | |
  |---|---|---|
  | instructions | 8192 | per program |
  | patterns | 64 | `scan` matches all at once |
  | pattern length | 64 B | |
  | scan window | 2048 B | the matcher never reads past it |
  | automaton states | 4096 | across all patterns |
  | scratch registers | 8 | locals reuse them by live range |
  | rules | 64 | named verdicts, per program |
  | per-flow ring | 16 | newest-wins |

- It reads packets and carried flow state; it does not modify packet payloads.
- Decode front-ends (`huffman`, `transform`, `h2`) are kernel stages that
  normalize the stream — the host interpreter models the match path, and those
  front-ends are verified at the compile + kernel-differential level.

## Install & import

Published as the `pfw-core` package (ESM only, `"type": "module"`).

```js
import { load, compile, Program, serializeProgram, build, machine } from "pfw-core";
import * as C from "pfw-core/dsl.js";              // the value builder
import { when, guard, allOf, each, rules } from "pfw-core/fp.js"; // combinators
```

Internally, modules reference each other through the `#/` subpath map
(`package.json` `imports` → `./src/`), the same convention the yeet daemon uses
(`#/isa.js`, `#/clang.js`, …). It resolves under both node and the yeet sandbox.

## Three ways to author a program

All three lower to the **same** AST and the same bytecode — pick by taste.

**1. pfw-C source** — the C-style language. `load(src)` returns a runnable
`Program` (throws on a compile error); `compile(src)` returns the full result
object (`{ ok, errors, program, patterns, rules, listing, nocase }`) without
throwing.

```js
import { load } from "pfw-core";
const p = load(`pattern bot="GPTBot"; filter { if (scan(payload,256)&bot) return rst("x",0); return pass; }`);
```

**2. JS value builder (DSL)** — the same constructs as composable JS values.
Good when the rule is generated from data.

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

**3. Functional combinators** — higher-order composition over the DSL: guards,
`when/unless`, `allOf/anyOf/none`, `match(...).has/any/all/seq`, and fragments
generated from a list.

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

## Running a program (host)

`Program.exec(frame, opts)` runs the bytes through the reference interpreter:

```js
const r = p.exec(frameBytes, {
  payload: 0,        // offset of the L7 payload within frame (default 0)
  proto: 6,          // IP protocol (default 6 = TCP)
  dport: 80,         // destination port
  src: "203.0.113.9",// source IP (string); or saddr as a u32
  flow: {},          // carried per-connection state (see below)
});
// r = { verdict: "pass"|"drop"|"ban"|"rst", code, rule, ruleName, flow }
```

The returned `r.flow` carries the connection's updated state (`userState`,
`hits`, `ring`, match mask). Pass it back as `opts.flow` on the next call to
**simulate a multi-packet connection** — this is how per-flow rules are tested:

```js
let { flow } = p.exec(pkt1, { dport: 80 });
const r2 = p.exec(pkt2, { dport: 80, flow });  // sees state set by pkt1
```

Note the kernel applies state *writes* on the next packet (deferred), and the
interpreter models that exactly: a `flow.state = N` write is visible on the
following `exec`, not the one that made it.

## Lowering to the kernel (XDP)

The host and kernel run identical bytes. `Program` carries both artifacts:

```js
const programBytes = p.bytes();     // the `programs` map value (Uint8Array)
const tables = p.tables();          // the ac_goto / ac_fail / ac_accept automaton
```

A loader writes `programBytes` into the `programs` BPF map and `tables` into the
automaton maps, then the XDP interpreter (`bpf/pfw.bpf.c`, built by `make bpf`)
runs it per packet. The low-level equivalents are exported too
(`serializeProgram`, `build`, and `machine` for the raw interpreter) if you are
driving the maps yourself rather than through `Program`.

`scripts/apply-and-hold.mjs` and `test/kernel/diff.mjs` are a working reference
for loading a program and reading its verdicts back from the event ring.

## Examples

Runnable, commented pfw-C programs in [`examples/`](examples) (all compiled by
`npm run test:node`):

| file | shows |
|---|---|
| `crawlers.pfc` | reset AI crawlers by user-agent, case-insensitive |
| `request_line.pfc` | parse the HTTP request line with the cursor (`find`/`skip`/`starts`) |
| `host_filter.pfc` | anchor a scan past `Host:` with `after`, then `ban` |
| `signature.pfc` | one scan, interrogated by `any`/`all`/`seq` |
| `cidr.pfc` | source-address allow / block |
| `frames.pfc` | walk HTTP/2 frames (`frame ... up to N`) |
| `huffman.pfc` | HPACK-Huffman decode, then match |
| `transform.pfc` | loadable byte-transform decode, then match |
| `ring.pfc` | per-flow ring — reset on too many segments |
| `rate_limit.pfc` | per-flow counter + `ban` |
| `handshake.pfc` | per-flow state machine (`flow.state`, TTL) |
| `size_guard.pfc` | `let` locals and arithmetic |
| `observe.pfc` | passive tap — `count` / `log`, no blocking |
| `macro.pfc` | reusable rule block |

## What's in the VM

- **ISA** — `src/isa.js` (host view) mirrored by `bpf/include/pfw.h` (the C
  contract). Change both or neither; a test asserts they agree.
- **Builder** — `src/builder.js`, an LLVM-IRBuilder-style op constructor (emit
  methods, label resolution, scratch-register allocation, pattern/rule
  interning). All front-ends target it — one definition of how an op is built,
  no assembly-text round-trip.
- **Front-ends** — `src/clang.js` (pfw-C), `src/dsl.js` (value builder),
  `src/fp.js` (combinators), `src/asm.js` (AT&T-style assembler).
- **Program** — `src/program.js`, the runnable object `load()`/the DSL return.
- **Bytecode** — `src/bytes.js` (`serializeProgram`, map dumps).
- **Table builders** — `src/ac.js` (Aho-Corasick), `src/huffman.js` (HPACK
  Huffman from RFC 7541), `src/transform.js` (loadable byte-transform tables).
- **Reference interpreter** — `src/interp.js`, `pfw_step` modelled
  line-for-line: the executable spec the tests assert against.
- **eBPF backend** — `bpf/pfw.bpf.c`, the once-verified kernel interpreter that
  reads exactly the bytes `serializeProgram`/`build` produce. `make bpf`.

## Build & test

```sh
make bpf              # compile the eBPF backend to bin/app.bpf.o
npm test              # the full host suite: test:node then test:unit
npm run test:unit     # yeet test test/unit — behavioral conformance
npm run test:node     # node file-reading guards (isa<->header sync, examples)
npm run test:verify   # load through yeetd so this kernel's verifier judges it
npm run test:kernel   # kernel differential: reference vs real kernel on loopback
npm run gen:huff      # regenerate bpf/include/huff_table.h from src/huffman.js
```

- **`test/unit/*.test.mjs`** run under `yeet test`: real programs through the
  reference interpreter, one file per feature (`compare`, `bool`, `match`,
  `arith`, `flow`, `pointer`, `verdict`, `repeat`, `macro`, `cidr`, `frame`,
  `ring`, `nocase`, `huffman`, `transform`), plus `ops.test.mjs` (every opcode,
  with a coverage gate), `dsl.test.mjs` (DSL == source, differential),
  `fp.test.mjs` (combinators == source), `exec.test.mjs` (the `Program` API) and
  `fuzz.test.mjs`. `helpers.mjs` is the shared `fromAsm`/`fromC` harness.
- **`test/node/*.mjs`** cover the two checks the yeet sandbox can't (no file
  I/O): `check-isa.mjs` (the `isa.js` ↔ `pfw.h` enums agree) and `examples.mjs`
  (every `examples/*.pfc` compiles).
- **`test/kernel/diff.mjs`** is the kernel *differential*: for a set of
  (program, payload) cases it runs each through both the reference interpreter
  and the real kernel (load, apply, send loopback traffic, read the verdict from
  the event stream) and asserts they agree. yeet exposes no `BPF_PROG_TEST_RUN`,
  so it uses live traffic; needs `yeetd` + loopback.
