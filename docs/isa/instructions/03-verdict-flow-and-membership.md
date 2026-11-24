# Verdicts, flow state, and membership

The 19 opcodes that end a program with a decision, read and write per-connection
state, and test an address or value against a host-loaded set.

## The verdict model

A program reaches a decision by setting `st->verdict`. Any opcode that sets it is
**terminal**: `pfw_step` checks `st->verdict` at the top of each iteration and
stops the `bpf_loop` once it is non-zero, so the first verdict wins and later ops
never run. `COUNT` and `LOG` are the exceptions — they record a side effect and
**fall through**, so the program continues to a later verdict (or the implicit
`decide pass` the compiler appends).

`finish()` (in `bpf/include/core/match.h`) turns the verdict into an XDP action
*after* the interpreter loop returns, in this order: (1) write the flow back
(mark/state/hits/rate), (2) `emit()` an event if `LOG` armed one, (3) if
**shadow mode** is on, an enforcement verdict (`V_DROP`/`V_BAN`/`V_RST`) is
counted and its mark is written but the packet is still passed (`XDP_PASS`) — a
dry run, (4) a pending `OP_REDIRECT` overrides the verdict, (5) otherwise the
verdict maps to its action. The enum is `V_NONE=0, V_PASS=1, V_DROP=2, V_BAN=3,
V_RST=4`.

Enforcement is also **cached on the flow**: `BAN`/`RST` write a mark
(`MARK_DROP=1` / `MARK_RST=2`, with a TTL) into the `flows` map, and the entry
fast path drops or resets later packets of that flow for the TTL *before* the
program even runs (also honouring shadow mode). `MARK` writes an arbitrary user
mark (≥16) the same way; `FLOW` reads it back.

Rule ids are `0..PFW_NRULES-1` (64). `drop`/`count`/`ban`/`rst` carry a rule id in
`reg`; the host keeps the id→name table, and `count` keys the `counters` map by it.

Across all entries: in pfw-C, verdicts are written `decide pass | drop("r") |
count("r") | ban("r", ttl) | rst("r", ttl)`; `log(n)`, `flow.state`,
`flow.count`, `ring.*`, and the membership operators are statements/expressions.

---

### 25 — `OP_PASS` (`pass`)

- **Assembler:** `pass` — **pfw-C:** `decide pass;`
- **Encoding:** code = 25; `reg`/`imm` unused.
- **Operation:** `st->verdict = V_PASS`. Terminal. In `finish()` the default arm
  returns `XDP_PASS` — but first, if the program recorded `redact`/`replace`
  requests (`st->rw_n`), it tail-calls the rewrite stage (`SLOT_REWRITE`) to apply
  them before the packet continues. Also the fall-through decision: a program that
  reaches its end with no verdict is treated as `V_PASS` (the compiler appends a
  `pass`).
- **Flags:** none.
- **Maps:** none (may tail-call via `decode_jmp`).
- **Example:** `if (dport != 80) decide pass;`
- **Notes:** the only non-enforcement terminal verdict; the packet proceeds up the
  stack.

### 26 — `OP_DROP` (`drop $rule`)

- **Assembler:** `drop $rule` — **pfw-C:** `decide drop("rule");`
- **Encoding:** code = 26; `reg` = rule id (`& (PFW_NRULES-1)`); `imm` unused.
- **Operation:** `st->verdict = V_DROP; st->rule = reg`. Terminal. `finish()`:
  `count_rule(rule); dropped++; return XDP_DROP` — the packet is discarded
  silently (no reset).
- **Flags:** none.
- **Maps:** `counters` (per-rule tally).
- **Example:** `decide drop("blocklist");`
- **Notes:** shadow mode turns this into a counted `XDP_PASS`. Per-packet, only
  this packet is dropped. On a reassembled stream (`reassemble` / `decode`) the
  **connection** is marked `MARK_DROP` as well: TCP retransmits the dropped
  segment, and by then its bytes have been consumed or have slid out of the
  window, so the retransmission would otherwise be judged clean and delivered.

### 27 — `OP_COUNT` (`count $rule`)

- **Assembler:** `count $rule` — **pfw-C:** `count("rule");` (a statement, not a verdict)
- **Encoding:** code = 27; `reg` = rule id / counter key; `imm` unused.
- **Operation:** increment `counters[rule]`. **Non-terminal** — it does not set
  `st->verdict`, so execution continues to a later verdict. Used for passive
  measurement.
- **Flags:** none.
- **Maps:** `counters` (`BPF_MAP_TYPE_PERCPU_ARRAY`).
- **Example:** `count("http_request");`
- **Notes:** `decide count("x")` is accepted as the verdict-form spelling but is
  equally non-blocking (it tallies, then falls through to `pass`). The host
  interpreter records the rule and continues.

### 28 — `OP_LOG` (`log $len`)

- **Assembler:** `log $len` — **pfw-C:** `log(n);`
- **Encoding:** code = 28; `imm` = byte length (`1..LOG_CAP`, `LOG_CAP = 256`);
  `reg` unused. The cursor at log time becomes the capture offset.
- **Operation:** `st->log_len = clamp(imm, LOG_CAP); st->log_off = %cur`.
  **Non-terminal.** In `finish()`, when `log_len` is set, `emit()` reserves a
  `pfw_event` on the `events` ring and copies `log_len` payload bytes from
  `log_off` into `event.data[]`, tagging it with the final verdict, the rule, the
  5-tuple, and the match mask. This is how a verdict becomes observable to
  userspace.
- **Flags:** none.
- **Maps:** `events` (ringbuf), via `finish()`.
- **Example:** `log(64); decide rst("bot", 0);`
- **Notes:** host-modelled as a no-op (the reference does not build events). Place
  `log` before the verdict; the capture is taken from wherever the cursor points.

### 29 — `OP_BAN` (`ban $rule, $ttl`)

- **Assembler:** `ban $rule, $ttl` — **pfw-C:** `decide ban("rule", ttl);`
- **Encoding:** code = 29; `reg` = rule id; `imm` = TTL in seconds.
- **Operation:** `st->verdict = V_BAN; st->rule = reg; st->ttl = imm; st->set_mark
  = MARK_DROP`. Terminal. `finish()` marks the **source address** `MARK_DROP` in
  the `sources` map with `expires = now + ttl·1e9` (0 = forever) — and the flow
  too — then `count_rule; bans++; dropped++; XDP_DROP`. For the TTL, the entry
  drops every later packet from that address, on any port, protocol or
  connection, before the program runs.
- **Flags:** none.
- **Maps:** `sources` (the ban), `flows` (mark write), `counters`.
- **Example:** `decide ban("scanner", 3600);`
- **Notes:** `ban` blocklists the source address; `rst` ends one connection;
  `drop` drops one packet. The ban is keyed on the address alone, so a reconnect
  from another port does not escape it. Shadow mode plants no source ban. The
  host model returns `source.banned`; pass that `source` back to `exec` and the
  next packet is dropped unseen.

### 30 — `OP_RST` (`rst $rule, $ttl`)

- **Assembler:** `rst $rule, $ttl` — **pfw-C:** `decide rst("rule", ttl);`
- **Encoding:** code = 30; `reg` = rule id; `imm` = TTL seconds.
- **Operation:** `st->verdict = V_RST; st->rule = reg; st->ttl = imm; st->set_mark
  = MARK_RST`. Terminal. `finish()`: `count_rule`; for an IPv4 TCP packet
  it calls `send_rst()`, which rewrites the frame in place into a TCP RST and
  returns `XDP_TX` (bounced back to the sender, counted in `rsts`); otherwise
  it falls back to `XDP_DROP` (counted in `dropped`). It does not count in
  `bans`: nothing is banned. The `MARK_RST` flow mark makes the fast path reset later packets too.
- **Flags:** none.
- **Maps:** `flows`, `counters`.
- **Example:** `decide rst("crawler", 60);`
- **Notes:** `send_rst` needs IPv4 + TCP; for anything else `rst` degrades to a
  drop. Shadow mode passes instead of resetting.

### 31 — `OP_FLOW` (`flow %cur`)

- **Assembler:** `flow %cur` — **pfw-C:** (read implicitly by the flow helpers)
- **Encoding:** code = 31; operand is `%cur`.
- **Operation:** `%cur = c->mark` — load the flow's current mark (as seen at
  entry) into the accumulator, so a program can branch on whether/how the flow is
  already marked.
- **Flags:** none.
- **Maps:** reads the cached flow mark (no lookup — passed in at entry).
- **Example:** `mov %flow? ...` (low-level; typically the compiler emits this).
- **Notes:** reads the mark captured at entry, not a live re-read.

### 32 — `OP_MARK` (`mark $v, $ttl`)

- **Assembler:** `mark $v, $ttl` (user marks start at 16) — **pfw-C:** via a flow write
- **Encoding:** code = 32; `reg` = mark value `v` (≥16; 1 and 2 are the reserved
  `MARK_DROP`/`MARK_RST`); `imm` = TTL seconds.
- **Operation:** `st->set_mark = v; st->ttl = ttl`. Deferred — `finish()` writes
  `f->mark = v`, `f->rule`, `f->expires = now + ttl·1e9` into the flow.
  **Non-terminal.**
- **Flags:** none.
- **Maps:** `flows`.
- **Example:** tag a flow for later packets to read with `flow`.
- **Notes:** an arbitrary user mark; it does not itself drop/reset (only the
  reserved marks drive the fast path's enforcement).

### 33 — `OP_SLOAD` (`sload %cur`)

- **Assembler:** `sload %cur` (or `srcload %cur`) — **pfw-C:** `flow.state` (or `src.state`)
- **Encoding:** code = 33; operand `%cur`; `reg` = scope: 0 this connection, 1 the
  source address.
- **Operation:** `%cur = c->user_state` — the per-connection state value, or 0 if
  it had expired by entry time. With the source scope, `st->src_state`: the same
  for the source address (the `sources` map).
- **Flags:** none.
- **Maps:** reads the flow's `user_state` (passed in at entry).
- **Example:** `if (flow.state == 1) decide pass;`
- **Notes:** pairs with `sstore`; see the deferred-write note there.

### 34 — `OP_SSTORE` (`sstore $state[, $ttl]`)

- **Assembler:** `sstore $state[, $ttl]` (or `srcstore`) — **pfw-C:** `flow.state = N for SECONDS;` (or `src.state = ...`)
- **Encoding:** code = 34; `reg` = TTL seconds (the full 32 bits); `imm` = the new
  state value in the low 32 bits, scope in bit 32 (1 = the source address).
- **Operation:** `st->new_state = state; st->set_state = 1; st->state_ttl = ttl`.
  Deferred — `finish()` writes `f->user_state = state` with `state_expires = now +
  ttl·1e9` (0 = never expires). **Non-terminal.**
- **Flags:** none.
- **Maps:** `flows`.
- **Example:** `flow.state = 1 for 300;`
- **Notes:** the write is **visible on the next packet**, not the one that made it
  — the kernel applies it in `finish()` after the match, and the reference
  interpreter models exactly this (the new state comes back in the returned
  `flow`, so the following `exec` sees it).

### 35 — `OP_BUMP` (`bump %cur`)

- **Assembler:** `bump %cur` (or `srcbump %cur`) — **pfw-C:** `flow.count` (or `src.count`)
- **Encoding:** code = 35; operand `%cur`; `reg` = scope: 0 this connection, 1 the
  source address (a counter that survives a reconnect).
- **Operation:** `st->hits++; st->set_hits = 1; %cur = st->hits` — increment the
  hit counter, then read it (the first read yields 1); the new value is written
  back in `finish()`. With the source scope the counter is `st->src_hits`, kept
  per source address in the `sources` map.
- **Flags:** none.
- **Maps:** `flows`, or `sources` with the source scope.
- **Example:** `if (flow.count >= 100) decide ban("flood", 600);`
- **Notes:** reading `flow.count` increments it, so each evaluation counts once.

### 39 — `OP_CIDR` (`cidr A.B.C.D/PREFIX`)

- **Assembler:** `cidr A.B.C.D/PREFIX` — **pfw-C:** `src in "10.0.0.0/8"`
- **Encoding:** code = 39; `imm` packs the network (low 32 bits, host order) and
  the prefix length (bits 32..39); `reg` unused.
- **Operation:** `mask = prefix==0 ? 0 : (prefix>=32 ? ~0 : (~0 << (32-prefix)))`;
  `ZF = (%cur & mask) == (net & mask)`. Tests the accumulator (an IPv4 address in
  host order — feed it with `mov %saddr, %cur`) against one inline network.
- **Flags:** sets **ZF**; preserves FF; clears CF.
- **Maps:** none (the network is inline in `imm`).
- **Example:** `if (src in "127.0.0.0/8") decide rst("lo", 0);`
- **Notes:** one network per op; for many prefixes use `src in set` (`LPM`).

### 40 — `OP_RPUSH` (`rpush %cur`)

- **Assembler:** `rpush %cur` — **pfw-C:** `ring.push(v);`
- **Encoding:** code = 40; operand `%cur`.
- **Operation:** push `%cur` onto the flow's ring: `ring[ring_head] = cur;
  ring_head = (ring_head+1) mod RING_CAP; ring_count saturates at RING_CAP` (16,
  newest-wins). A flow's entry is created at write-back, after its first packet
  has run; pushes made on that packet are kept and become the new entry's ring,
  so the ring behaves the same from the first packet on, for TCP and UDP alike.
- **Flags:** none.
- **Maps:** `flows` (the ring lives in the flow value).
- **Example:** `ring.push(len);`
- **Notes:** fixed 16-slot insertion-ordered ring; the oldest entry is overwritten
  once full.

### 41 — `OP_RGET` (`rget %cur`)

- **Assembler:** `rget %cur` — **pfw-C:** `ring.get(i)`
- **Encoding:** code = 41; operand `%cur` (in: the index; out: the value).
- **Operation:** `idx = %cur`; if `idx < ring_count`, `%cur =
  ring[(ring_head-1-idx) mod RING_CAP]` (index 0 = newest). Otherwise `%cur = 0`
  **and FF is set**, so `jf` can tell "absent" from a legitimately stored 0.
- **Flags:** sets **FF** on out-of-range.
- **Maps:** `flows`.
- **Example:** `let recent = ring.get(0) + ring.get(1) + ring.get(2);`
- **Notes:** 0-based from newest; combine with `rlen` to bound the index.

### 42 — `OP_RLEN` (`rlen %cur`)

- **Assembler:** `rlen %cur` — **pfw-C:** `ring.len`
- **Encoding:** code = 42; operand `%cur`.
- **Operation:** `%cur = ring_count`; saturates at 16.
- **Flags:** none.
- **Maps:** `flows`.
- **Example:** `if (ring.len == 16) ...`
- **Notes:** the live count of entries, not the capacity.

### 46 — `OP_LPM` (`lpm`)

- **Assembler:** `lpm` (tests `%cur`) — **pfw-C:** `src in set`
- **Encoding:** code = 46; no operands.
- **Operation:** build an LPM key from `%cur` as an IPv4 address — `prefixlen =
  32`, `data = htonl((u32)cur)` (network byte order, matched MSB-first) — and look
  it up in the `lpm` trie. `ZF = found`. Longest-prefix match against the whole
  host-loaded CIDR set in one lookup.
- **Flags:** sets **ZF**; preserves FF; clears CF.
- **Maps:** `lpm` (`BPF_MAP_TYPE_LPM_TRIE`).
- **Example:** `if (src in set) decide drop("blocklist");`
- **Notes:** the set is populated out of band by the host (thousands of prefixes);
  the reference models it via `opts.set`. `%cur` is host order; the op converts.

### 47 — `OP_HASH` (`hash`)

- **Assembler:** `hash` (tests `%cur`) — **pfw-C:** `x in hash`
- **Encoding:** code = 47; no operands.
- **Operation:** `k = (u32)cur`; `ZF = (hashset[k] exists)`. Exact set membership
  on the low 32 bits of the accumulator.
- **Flags:** sets **ZF**; preserves FF; clears CF.
- **Maps:** `hashset` (`BPF_MAP_TYPE_HASH`).
- **Example:** `if (dport in hash) decide rst("blocked_port", 0);`
- **Notes:** exact (no false positives); host-loaded; reference models via
  `opts.hashset`.

### 72 — `OP_FLOAD` (`fload $N`)

- **Assembler:** `fload $0` … `fload $3`, `fload $bytes`, `fload $packets` —
  **pfw-C:** `flow.r0` … `flow.r3`, `flow.bytes`, `flow.packets`
- **Encoding:** code = 72; `reg` = which (0–3 a flow register, 4 = bytes,
  5 = packets; masked to 3 bits); `imm` unused.
- **Operation:** `cur ←` the flow register as loaded at entry or as stored since
  (`st->ureg[reg & 3]`); or `flow.bytes` / `flow.packets` **with this packet
  already added**. Reading a count sets `want_acct`, which has the write-back
  create the flow's entry if it has none.
- **Flags:** none. **Maps:** `flows` (through the per-CPU state).
- **Notes:** the counts are written back for every packet of a flow that has an
  entry, whether the program read them on that packet or not.

### 73 — `OP_FSTORE` (`fstore $N`)

- **Assembler:** `fstore $0` … `fstore $3` — **pfw-C:** `flow.r0 = expr;`
- **Encoding:** code = 73; `reg` = the register (masked to 2 bits); `imm` unused.
- **Operation:** `st->ureg[reg & 3] ← cur`, and marks the registers for
  write-back to the flow (creating its entry if need be).
- **Flags:** none. **Maps:** `flows`.
- **Notes:** a store is visible to a later `fload` in the same run — unlike
  `sstore`, whose value is only read back on the next packet.

### 71 — `OP_KVGET` (`kvget [$DEFAULT]`)

- **Assembler:** `kvget`, `kvget $9` — **pfw-C:** `lookup(key)`, `lookup(key) ?? 9`
- **Encoding:** code = 71; `reg` unused; `imm` = the value an absent key yields.
- **Operation:** `cur ← kv[cur]` when the 64-bit key is present; otherwise
  `cur ← imm` and `FF` is set.
- **Flags:** `FF` on an absent key; `ZF`/`CF` untouched. A key stored with the
  value 0 reads 0 *without* a fault, which is how `jf` tells the two apart.
- **Maps:** `kv` (`BPF_MAP_TYPE_HASH`, u64 → u64, 262144 entries).
- **Example:** `let tenant = lookup(key_hash); if (tenant == 0) decide rst("unknown_key", 0);`
- **Notes:** host-loaded and shared by both generations, like `hashset`: it is
  the host's data, not the program's. The reference models it via `opts.kv`.

### 48 — `OP_BLOOM` (`bloom`)

- **Assembler:** `bloom` (tests `%cur`) — **pfw-C:** `x in bloom`
- **Encoding:** code = 48; no operands.
- **Operation:** `e = (u32)cur`; `ZF = (bpf_map_peek_elem(&bloom, &e) == 0)` —
  present (peek returns 0) sets ZF; definitely-absent (an error) clears it.
- **Flags:** sets **ZF**; preserves FF; clears CF.
- **Maps:** `bloom` (`BPF_MAP_TYPE_BLOOM_FILTER`).
- **Example:** `if (dport in bloom) decide drop("maybe_bad");`
- **Notes:** probabilistic — may false-positive, never false-negative. The
  reference models it as an exact set (`opts.bloom`).

### 49 — `OP_LPM6` (`lpm6`)

- **Assembler:** `lpm6` — **pfw-C:** `src6 in set6`
- **Encoding:** code = 49; no operands.
- **Operation:** read the IPv6 version nibble at `l3`; proceed only if it is 6.
  Read the 16-byte source address from the packet at `l3 + 8` (network order),
  build an LPM6 key (`prefixlen = 128`), and look it up in the `lpm6` trie. `ZF =
  found`. Unlike `LPM`, the address comes **from the packet**, not `%cur`.
- **Flags:** sets **ZF**; preserves FF; clears CF (ZF stays 0 for non-IPv6).
- **Maps:** `lpm6` (`BPF_MAP_TYPE_LPM_TRIE`).
- **Example:** `if (src6 in set6) decide drop("v6_blocked");`
- **Notes:** IPv6 only; host-loaded set; the reference models via `opts.src6` +
  `opts.set6`.
