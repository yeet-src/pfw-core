# pfw: a pattern-matching ISA for XDP (draft 0)

A once-verified interpreter at XDP, in the shape of walkshop's walk VM:
the program is data in a map, every instruction is one `bpf_loop` step,
the state lives in a per-CPU map element, and the C prologue parses
L2/L3/L4 and fills the registers. What is new is the pattern group: an
Aho-Corasick automaton built on the host from the program's own string
literals (h2-firewall's sparse goto + failure-link tables) and one
instruction, `scan`, that runs it over a window of the packet.

Straight-line code with forward-only jumps, so a program always ends.
Apply = assemble on the host, build the automaton, write ops + tables
into the inactive generation, flip the active index. The kernel never
sees a half-written program.

## Machine

| register | kind | meaning |
|---|---|---|
| `%frame` | ro | offset 0 of the frame (L2 or L3) |
| `%l3` `%l4` `%payload` | ro | offsets filled by the prologue |
| `%end` | rw | one past the last readable byte; assignable (only ever narrowed, e.g. by `frame`) to clip a body's reads to a sub-region |
| `%src` | ro | IPv4 source address, host byte order (`%saddr` is the same register; 0 for IPv6) |
| `%ctx` | ro | ifindex, proto, ports in a side struct the prologue fills |
| `%cur` | rw | the cursor: an offset into the frame, or a loaded value |
| `%s0`..`%s7` | rw | scratch; the compiler allocates `ptr`/`let` locals onto these by live range, so any number may be declared as long as at most eight are live at once |
| `%m` | rw | match mask: bit *i* set when pattern *i* was seen by the last `scan` |
| `ZF` `CF` | flags | set by `cmp`, `test`, `cmpstr`; read by the jumps |

Offsets, not addresses: XDP reads go through `bpf_xdp_load_bytes`, which
takes an offset and follows multi-buffer frames. The assembly looks the
same as tcpwalk2's (`movbew 2(%l4), %cur`), it is the C that differs.

## Instructions

Cursor and loads (walk VM, with big-endian loads added because every
L3/L4 field on the wire is big-endian):

```
mov    %REG, %cur            cur = reg
lea    D(%REG), %cur         cur = reg + D
add    $N, %cur  /  sub $N, %cur
movb/w/l/q  D(%cur), %cur    load little-endian N bytes at cur+D
movbew/movbel D(%cur), %cur  load big-endian 2/4 bytes (ports, lengths)
mov    %cur, %sN  /  mov %sN, %cur
add    %sN, %cur  /  sub %sN, %cur
and    $MASK, %cur
or     $N, %cur   /  shl $N, %cur  /  shr $N, %cur
```

Compare and branch (x86 flag semantics, forward-only labels):

```
cmp    $IMM, %cur            ZF = (cur == imm), CF = (cur < imm)
test   $MASK, %m             ZF = ((m & mask) == 0)
cidr   A.B.C.D/PREFIX        ZF = (cur, as an IPv4 address, lies in the network)
je jne jb jae ja jbe  LABEL
jmp    LABEL
```

`cidr` tests whatever is in `%cur`, so `mov %src, %cur` first to match the
source address, or load any address field (an `X-Forwarded-For`, a parsed
`:authority`) into `%cur` and match that. In pfw-C it is the `in` operator:
`if (src in "10.0.0.0/8")`. The network and prefix are folded into one
immediate (net in the low 32 bits, host order; prefix in bits 32–39), so the
op is pure arithmetic — no map, no loop. IPv4 only for now; IPv6 is later.

Patterns (the new group; `.pat` literals build one automaton per program):

```
.pat   NAME, "literal"        a pattern; bit NAME in %m; "\r\n", "\x00" escapes
.pat   NAME, 0x47 0x45 0x54   the same from bytes
.nocase                       fold ASCII case for every pattern in this program

scan   $LEN, (%cur)           run the automaton over [cur, cur+LEN), clipped to %end;
                              %m |= every pattern seen; first end-offset per pattern kept
mpos   $NAME, %cur            cur = offset just past the first match of NAME (fails if none)
cmpstr $NAME, (%cur)          anchored compare at cur: ZF = bytes at cur equal NAME
findb  $BYTE, $LEN            cur = offset of the first BYTE within LEN (fails if none)
skipb  $BYTE                  cur advances past a run of BYTE (spaces, tabs)
```

Verdicts and output:

```
pass                          XDP_PASS (also the fall-through at the end)
drop   $RULE                  counters[RULE]++, XDP_DROP
count  $RULE                  counters[RULE]++, continue
log    $LEN                   one event to the ring: 5-tuple, %m, the rule, LEN bytes at cur
```

Failure: a load past `%end`, a `mpos` with no match, a `findb` miss
sets the fault flag; the next `jf LABEL` (jump if fault) takes it, and a
program that never checks it ends with `pass`. Looking, never dropping,
on anything it could not read is the safe default; a program that
wants fail-closed writes `jf drop_it`.

Stateful (v1): a verdict bans the flow, not just the packet, and the
automaton state is carried across a TCP flow's segments.

```
ban    $RULE, $TTL_S          mark the 4-tuple drop, count, drop this packet
rst    $RULE, $TTL_S          mark the 4-tuple rst, answer with a TCP RST (XDP_TX)
flow   %cur                   cur = this flow's mark (0 = none)
mark   $V, $TTL_S             set the flow's mark (user marks from 16)
sload  %cur                   cur = this flow's user state (flow.state)
sstore $STATE                 set this flow's user state
bump   %cur                   cur = ++this flow's hit counter (flow.count)
rpush  %cur                   push cur onto this flow's ring (ring.push)
rget   %cur                   cur = ring entry at index cur, 0 = newest (ring.get); 0 + fault if absent
rlen   %cur                   cur = this flow's ring length (ring.len)
```

The flow table carries, across a connection: the automaton state (for
`scan` continuity), a `user_state` integer (`flow.state`, a hand-rolled
state machine), a `hits` counter (`flow.count`, for rate limiting), and a
**ring** (P3) — a fixed-capacity, newest-wins `u32` ring (`ring.push` /
`ring.get` / `ring.len`), the shape of the HPACK dynamic table and of
rate-limit history. `bump` increments and reads the counter in one op; the
ring ops need a tracked flow (always present in reasm mode).

## Budgets (draft)

| | |
|---|---|
| ops per program | 64 |
| patterns per program | 64 (one `u64` mask) |
| pattern length | 1..64 bytes |
| automaton states | 4096 (goto table 4096 × 256 × u16 = 2 MiB per generation) |
| failure chain per byte | ≤ 16 hops |
| bytes per `scan` | ≤ 2048 |
| programs | one per attached interface, two generations |

## Example: drop AI crawlers on :80

```
.nocase
.pat  gptbot,    "GPTBot"
.pat  claudebot, "ClaudeBot"
.pat  ccbot,     "CCBot"
.pat  bytespider,"Bytespider"
.pat  get,       "GET "
.pat  post,      "POST "

        movbew  2(%l4), %cur          ; tcp dport
        cmp     $80, %cur
        jne     out
        mov     %payload, %cur
        cmpstr  $get, (%cur)          ; a request line, not a continuation
        je      head
        cmpstr  $post, (%cur)
        jne     out
head:   scan    $1460, (%cur)         ; the request head, as far as the frame goes
        test    $gptbot|$claudebot|$ccbot|$bytespider, %m
        jz      out
        log     $64
        drop    $crawler
out:    pass
```

## Example: refuse the h2c preface

```
.pat  preface, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        mov     %payload, %cur
        cmpstr  $preface, (%cur)
        jne     out
        drop    $h2c
out:    pass
```

## Reassembly and decode front-ends

Two program-level directives normalize the stream before matching, so the ISA
above runs over the bytes the server will actually act on:

```
.reasm [PORT]            match the reassembled TCP stream, not the packet (dport PORT only)
.decode h2 [PORT]        HTTP/2 HEADERS/HPACK -> "name: value" plaintext, then match
.decode huffman [PORT]   HPACK-Huffman-decode the stream, then match
```

A decode front-end implies `.reasm`. `huffman` is the first instance of P2 in
docs/primitives.md — "a decoding is data": the table is built from RFC 7541 by
`src/huffman.js` and baked into `bpf/include/huff_table.h`, and the
kernel just runs it. In pfw-C: `decode huffman PORT;` (alongside `decode h2`).
Invalid input fails closed (reset).

## Walking length-prefixed structure: `frame`

```
frame [at PTR] (len = be24 @ 0, type = u8 @ 3, head = 9) up to 8 {
    ... frame.len, frame.type, frame.data available; reads clipped to this record ...
}
```

Walk up to `$MAX` records, each a `head`-byte header (fields read by name, size
and offset: `u8`/`u16`/`u32` and `be16`/`be24`/`be32`) then `len` payload bytes.
In the body, `frame.len` and `frame.type` are the parsed fields and `frame.data`
points at the payload; `%end` is narrowed to the record so a `scan`/load cannot
read past it. The cursor advances `head + len` per record. This is P4 of
docs/primitives.md — a pfw-C-only construct that unrolls to the ops above, so the
ISA's forward-only termination guarantee is preserved.
