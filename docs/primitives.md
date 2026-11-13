# A general ISA for programmable firewalls (design note)

Status: design, not built. A companion to [isa.md](isa.md), which documents the
ISA as it exists today. This note is about where it goes next, and why.

It was written out of a concrete exercise: turning a one-line upstream patch
(apache/httpd `1b47e95`, CVE-2026-106023, a NULL `r->hostname` in `mod_md`) into
an XDP rule, then pushing the ISA until it could reassemble TCP out of order and
decode HTTP/2 HPACK in the kernel. Everything hard in that exercise turned out
to be the *same* handful of missing primitives, surfacing once per protocol. The
point of a general ISA is to add those primitives once, in the substrate, so a
new protocol is a *program*, not a kernel patch.

## Thesis

**Encodings are data. Decoders are stages. The hard part is the verifier
budget.**

- `scan` is already table-driven — you load an Aho-Corasick automaton built from
  a program's string literals, the kernel just walks it. Every *other* decoding
  (Huffman, base64, percent, a bespoke obfuscation) has that same shape and
  should be data too, not kernel C.
- A real decoder (HPACK, TLS, DNS) does not fit one eBPF program — the verifier's
  instruction and state budgets force it into a tail-call pipeline. We built
  `scan → hpack → resolve → match` by hand, re-deriving packet context and
  threading state through maps at every cut. That plumbing is mechanical and
  identical for every decoder; the toolchain should generate it.
- Per-flow state beyond "one integer" (HPACK's dynamic table, sessions,
  per-identity rate limits) and bounded iteration over length-prefixed
  structures (frames, records, chunks) are the other two things decoders need
  and the ISA doesn't give them.

Get those into the substrate and "add HTTP/2" stops being a C project: you write
an HPACK decoder *in the ISA* from a Huffman table, a per-flow ring, and a
framing loop, and the compiler stages it to fit the verifier. Whether that is
*possible* is the real test of whether the ISA is general.

## What exists today (recap)

From `isa.md`, plus the work this note grew out of:

- L2–L4 prologue filling a register file; straight-line, **forward-jumps-only**
  programs (so a program always terminates).
- `scan` over a loaded Aho-Corasick automaton; cursor loads, `cmp`/`test`/jumps,
  `cmpstr`/`mpos`/`findb`/`skipb`.
- Verdicts: `pass`/`drop`/`rst`/`ban`/`count`/`log`; a per-flow table with a
  carried automaton state, one `user_state` int, and a hit counter.
- **TCP reassembly** (out-of-order, first-wins overlap, fail-closed on
  gap/eviction) — a substrate primitive, because every TCP L7 protocol needs it.
- A **decode front-end**: a stage normalizes the stream to a plaintext view the
  matcher scans (`decode h2` reassembles → frames → HPACK-decodes → the rule
  scans the decoded headers).
- **Tail-call stages** — but hand-wired: a `PROG_ARRAY`, `bpf_tail_call`, and
  per-stage re-derivation written by hand in C.

The last two are the tell. Reassembly got promoted to a primitive once we
noticed every protocol needs it. Staging and decoding are at the stage reassembly
was before: real, load-bearing, and hand-rolled per use. They want to be
primitives too.

## The primitives

In leverage order. (1) is the one nothing else scales without.

### P1 — Compiler-managed staging *(the meta-primitive)* — **stage framework landed**

Reframed by what P2–P4 taught: pfw-C programs are *interpreted* (bytecode the one
fixed, already-verified `pfw_step` runs), so they never hit the verifier — the
"auto-split a heavy program" half below is a problem pfw-C programs don't have.
The verifier pain is entirely in the hand-written C **decode stages**, where we
wrote the same prologue four times. So the landed piece is the **stage
framework**: `flow_lookup()`, `stage_reset()`, and the `PFW_STAGE_ENTER(ctx)`
macro in `bpf/pfw.bpf.c` factor the parse / state / flow prologue and the
fail-closed reset, so `pfw_decode` / `pfw_resolve` / `pfw_huff` are now just their
bodies and a new decode stage is `PFW_STAGE_ENTER(ctx); if (f) { ...; }
bpf_tail_call(ctx, &decode_jmp, SLOT_NEXT); return XDP_PASS;`. Continuations ride
the maps the stages already share (the per-cpu `state`, the per-flow buffer) —
the only state a tail call may carry. Verified end to end by
`scripts/verify-load.mjs`.

The *automatic* half below — liveness analysis, continuation spill, budget-based
auto-splitting of one straight-line program — stays deferred: it needs a pfw-C →
native-eBPF backend that does not exist (and is not needed while pfw-C is
interpreted). The framework is what makes adding real decoders cheap today.



The verifier judges **per program**: ~1M instructions, a 512-byte stack shared
down the call chain, and a state-exploration ceiling that a branchy loop body
blows long before the instruction count. A decoder exceeds all three. The only
escape is to split it into several programs chained by `bpf_tail_call` through a
`PROG_ARRAY`, because tail calls don't nest stack frames and each program is
verified independently.

We did this four times by hand for h2 (`pfw_xdp → pfw_decode → pfw_resolve →
pfw_match`), and each time wrote the same boilerplate: re-parse the packet,
re-look-up the flow and program, reload the state the previous stage left in a
map, and populate the jump table from the host. That is a **compiler pass**, not
a thing authors should write.

Design:

- The author writes one straight-line program. Stage boundaries are either
  explicit (`@stage`) or inserted automatically when a per-stage budget estimate
  (instructions × branch factor, nested-loop count) would exceed a threshold.
- The compiler computes the variables **live across** each boundary and spills
  them to a per-flow / per-CPU *continuation* record, with a resume stage id.
- Each emitted stage is `prologue(parse + reload continuation) → its ops →
  epilogue(spill continuation + tail_call next | verdict)`. Pointers and stack
  values never cross a boundary — only map-backed state does (the verifier
  forbids the rest anyway).
- The loader compiles the stages, fills the `PROG_ARRAY`, and attaches **only**
  the entry as the XDP hook. (Attaching every `SEC("xdp")` program to the netdev
  conflicts — a real bug we hit; the tail-call targets must be loaded *into the
  array*, not hooked.)

Author sees one program; the kernel runs N. This is the difference between "an
ISA" and "an ISA you can build real decoders on."

### P2 — `transform`: table-driven decode — **first table landed (Huffman)**

Landed as a decode front-end, `decode huffman`, not yet the composable `%src,%dst`
op below. The thesis holds end to end: the HPACK Huffman table is **built from
RFC 7541 by `src/huffman.js`** (validated against the RFC's own worked
examples and a 256-symbol round-trip) and baked into `bpf/include/huff_table.h`;
the `pfw_huff` tail-call stage runs it over the reassembled stream, then the
matcher scans the decoded plaintext. Shown live in the firewall repo's live demos:
wire bytes `c5af7dd3a7` carry no ASCII "GPTBot", yet the rule decodes and resets
on it, while a different Huffman string passes.

Why a stage, not the inline op yet: the decode is a data-dependent state machine
(`state ← table[state]`), which is exactly what the verifier handles worst. Three
things were needed to fit it, each the same trick the automaton (`ac_step`)
already uses — the op form wants the P1 staging compiler to apply them for you:
1. the table is a **const array read directly**, not a per-cell map lookup (a
   helper call in the loop forces the verifier to walk every iteration → the
   "8193 jumps too complex" ceiling);
2. the evolving `state`/`outpos` live **in the per-flow/per-cpu map**, reloaded
   each iteration, so the verifier launders their precision instead of tracking
   a data-dependent chain (→ the 1M-insn state explosion);
3. output goes to a **separate buffer** (`st->dec`), since decompressed output
   runs ahead of the read cursor and would clobber unread input in place.

**The general transform landed too — the table is now loaded data.** Alongside
the baked Huffman stage there is `pfw_transform` (DECODE_TRANSFORM): it runs
`tt_cells[prog->transform_table]`, a table the host loads into a map, so a new
decoding needs **no kernel change**. The cell read is a per-cell map lookup in
the loop — which on its own trips the verifier's jump budget — and it verifies
for exactly the reason point 2 above gives: the evolving state lives in the map
and is reloaded each iteration (the `ac_step` pattern). A transform table is
`state × nibble → (emit byte, next state, flags)`; `src/transform.js` builds them
(`buildByteMap(fn)` for any per-byte rewrite, `buildHuffman()` for the HPACK
code), and `decode <name>` in pfw-C selects one. So:

- **Huffman** = the HPACK table (RFC 7541 Appendix B) — baked or loaded.
- **A byte rewrite** (undo an obfuscation, normalize) = `buildByteMap(fn)`.
- **A bespoke on-the-wire obfuscation someone needs to see through** = a table
  they write, loaded, no kernel change.

Decodings became data. Verified end to end by `scripts/verify-load.mjs` (the
kernel accepts the loaded-table stage) and `test/transform.test.mjs` (the tables
decode correctly, through the same model the kernel mirrors).

The remaining tail is the **composable in-program op** — decode a *sub-region*
mid-program and keep going, rather than a whole-stream front-end:

```
transform $TABLE, (%src), %dst, $len   ; run the table over [src,src+len) mid-program
```

That one still wants the automatic staging P1 defers, because it would run inside
the interpreter loop; the front-end `decode <table>` is the shipped form.

### P3 — per-flow keyed store / ring — **ring landed**

Today a flow carries one `user_state` int and a counter. HPACK's dynamic table,
HTTP session state, per-sub-identity rate-limit buckets, and TLS resumption all
want the same shape: a small, bounded, per-connection structure the program
reads and writes.

The **ring** landed — insertion-ordered, fixed capacity (`RING_CAP`),
newest-wins indexing, the shape of the HPACK dynamic table and of rate-limit
history. Three ops that touch the flow directly (like `sload`/`bump`, so no loop
and no verifier cost):

```
rpush  %cur            ; push cur onto the flow's ring
rget   %cur            ; cur = entry at index cur (0 = newest); 0 + fault if absent
rlen   %cur            ; cur = ring length
```

In pfw-C: `ring.push(v);`, `ring.get(i)`, `ring.len`. Entries are `u32` for now
(the HPACK dynamic table's variable-length name/value strings are the next step —
they want the variable storage this ring's fixed slots don't yet have). Capacity
lives in the flow struct, trading table-count for per-flow depth as the
reassembly buffer already does. Proven in `test/ring.test.mjs` (4/4, model:
order, length, eviction at cap, absent-get) and live in `ring-live.mjs`: the ring
accumulates across a flow's data segments and resets the 3rd.

Still to come: the **key→value store** (`sput`/`sget`) for sessions and keyed
buckets, and variable-length ring entries so gap #2 (the real dynamic table)
becomes a library on this.

### P4 — `frame`: bounded iteration over length-prefixed structure — **implemented**

Gaps #3/#4/#5 (CONTINUATION, multi-frame/stream, chunked bodies) are all "walk a
length-prefixed structure": h2 frames, TLS records, chunked transfer, protobuf.
The ISA is forward-only — good, it guarantees termination — so iteration must be
a *bounded* construct, not a backward jump:

```
frame [at PTR] (len = be24 @ 0, type = u8 @ 3, head = 9) up to 8 {
    if (frame.type == 1) {                     // per-record dispatch
        if (scan(frame.data, 2048) & bot) ...  // reads clamped to this record
    }
}                                              ; advances head+len each time, <= 8 records
```

Landed as a **pure compiler construct**: the body unrolls up to `$MAX` times with
existing ISA ops, so termination holds by construction and — the deliberate
lesson from P2 — it needs **no kernel change and adds no verifier risk**. Each
copy reads the header fields into scratch (`frame.len` / `.type`, and `frame.data`
= a pointer to the payload), narrows `%end` to this record's extent so the body's
scans and loads can't bleed into the next record, runs the body, and advances the
cursor `head + len`. `%end` is now assignable for exactly this (it only ever
shrinks the readable window, so it stays memory-safe).

Proven in `test/frame.test.mjs` (5/5, model):
the same "GPTBot" bytes reset when they sit in a HEADERS-type record and pass
when they sit in a SETTINGS record or spill across a record edge — structure a
flat `scan` cannot see. The note's `bpf_loop`-or-stage lowering is the next tier
(for large `$MAX` or heavy bodies); unrolling is the small-`$MAX` case, and it is
what showed that the staging compiler (P1) is the only thing left that the heavy
primitives still want.

### P5 — `cidr`: address-set membership — **implemented**

```
mov %src, %cur        ; or any address field loaded into %cur
cidr A.B.C.D/PREFIX   ; ZF = %cur lies in the network
```

Cheap, general, and orthogonal to everything above: rule scoping, allow/deny
lists, geo buckets. The one piece of gap #6 that belongs *in* the ISA; the rest
(PROXY protocol, X-Forwarded-For) is a program that parses a header with P4 and
feeds the result to `cidr`.

Landed as the first primitive, end to end: `OP_CIDR` + a read-only `%src`
register (IPv4 source, host order) in `bpf/include/pfw.h` and the interpreter,
`cidr A.B.C.D/PREFIX` in the assembler, and the `in` operator in pfw-C
(`if (src in "10.0.0.0/8")`). It tests `%cur` rather than a fixed register, so
it also matches an address a program parsed out of a header. The network and
prefix fold into one immediate (net low-32 host-order, prefix in bits 32–39), so
the op is pure arithmetic — no map, no loop, strictly simpler for the verifier
than `load`. Pinned by `test/cidr.test.mjs` (18 boundary cases through the
reference model). IPv4 only; IPv6 is a `%src6`/128-bit follow-up.

## What stays *on top* (programs/libraries, not ISA)

- **Specific decoders** — HPACK, TLS SNI, DNS. Written against P1–P4 and shipped
  as reusable stages. The win of a general ISA is that HPACK is something a user
  *loads*, not something the kernel hardcodes.
- **Source resolution** — PROXY/XFF parsing (P4) + `cidr` (P5).
- **Rule scopes, shadow/enforce posture, the metrics/ops stack** — application
  layer, above the ISA.

## The staging compiler, sketched

```
front-end:   pfw-C  →  straight-line IR  (+ explicit @stage marks)
liveness:    for each stage boundary, the set of vars live across it
budget:      estimate per-stage cost; insert boundaries before it blows
             (instructions, nested bpf_loops, branch-factor of switch bodies)
spill:       a `struct cont { u16 stage; <live vars> }` in the flow/scratch map
codegen:     stage_k = parse(ctx)           // re-derive packet
                     + reload(cont)          // restore live vars
                     + ops_k
                     + spill(cont) + tail_call(stage_{k+1})   | verdict
loader:      compile stages → populate PROG_ARRAY → attach entry only
```

The invariant the pass must keep: **nothing but map-backed state crosses a
boundary.** That is also what the verifier enforces, so the pass is working *with*
the verifier, not around it. Everything in `match_half`'s hand-written
re-derivation and the `pfw_decode`/`pfw_resolve` state handoff is this pass, done
by a human.

## Worked example: HPACK re-expressed on the primitives

The proof the ISA is general is that the decoder we wrote in ~250 lines of
staged BPF C becomes a short program over P1–P4, with the compiler doing the
staging:

```
// hpack.pfw — decode HTTP/2 HEADERS, built entirely on ISA primitives.

transform huffman = table "hpack-huffman";   // RFC 7541 App B, built on the host
ring      dyntab[128] of (name, value);        // per-flow HPACK dynamic table (P3)

decode h2 on :8080 {                            // reassemble (substrate) + this body
  skip preface;
  frame (len = u24@0, type = u8@3, flags = u8@4) up to 8 {        // P4
    if (type != HEADERS) continue;
    if (!(flags & END_HEADERS)) reset;          // CONTINUATION: own stage, or fail closed
    @stage;                                      // hint: HPACK walk is its own program
    frame hpack(body) up to 128 {                // P4 over HPACK field encoding
      let nidx = field.name_index;
      let name  = nidx ? static_or_dyn(nidx, dyntab)      // static table | P3 ring
                       : string(field.name,  huffman);    // P2 (Huffman if H-bit)
      let value =        string(field.value, huffman);    // P2
      emit "%s: %s\n", name, value;              // the decoded view the matcher scans
      if (field.incremental) dyntab.push(name, value);    // P3
    }
  }
}
```

`string(x, huffman)` is `transform` when the HPACK H-bit is set and a raw copy
otherwise. `static_or_dyn` is the 61-entry static table (data) with a `dyntab`
fallback (P3). `frame ... up to N` is P4. The two `frame`s and the `@stage` mark
are where the compiler (P1) cuts tail-call stages. No Huffman state machine, no
dynamic-table ring, no frame walker written in C — each is a primitive or a
loaded table.

Against this, the current in-tree decoder is the *un-generalized* version: Huffman
and the dynamic table are "fail closed" precisely because they'd be hand-coded C
and a hand-grown flow field; CONTINUATION and multi-frame are "fail closed"
because the frame walk is hand-rolled and single-shot. Each is a primitive we
don't have yet, not a protocol feature we chose to skip.

## Design invariants to hold

- **Termination by construction** — forward-only jumps, and `frame`/`transform`
  bounded by constants. No primitive introduces an unbounded loop; the "always
  terminates" property that makes the ISA verifiable survives.
- **Tables as data** — `scan`, `transform`, `cidr`, the static table: all
  *loaded*, built on the host from a spec, never kernel code. Adding a protocol
  adds data and a program, not a `.bpf.c`.
- **Verifier-fit by construction** — the staging compiler guarantees each emitted
  program fits the budget; the author never reasons about 1M instructions or
  512-byte stacks.
- **Fail-closed composition** — a stage that cannot complete what it inspects
  (truncation, a gap, an unknown table entry, an evicted ring) resets the flow
  rather than passing bytes it did not understand. This is already how
  reassembly and the h2 decoder behave; it should be the default a new primitive
  inherits.

## Priority

1. **P1, compiler-managed staging** — nothing else scales without it; it also
   retires the most hand-written, error-prone code.
2. **P2, `transform`** — unblocks Huffman and every encoding at once.
3. **P3, per-flow ring/store** — the dynamic table, plus stateful rules broadly.
4. **P4, `frame`** — framing for any length-prefixed protocol.
5. **P5, `cidr`** — cheap, immediately useful for targeting, independent of the
   rest.

With P1–P4 in place, "is the ISA general?" has a falsifiable answer: re-express
HPACK (above) as a loadable program and delete the hand-written h2 decoder. If
that program compiles, stages, verifies, and catches `GPTBot` over real
(Huffman-coded, dynamic-indexed) h2 — the ISA is general. If it can't, the gap it
hits is the next primitive.
