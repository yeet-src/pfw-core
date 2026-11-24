# 8. Decode front-ends and the rewrite stage

A program may normalise the reassembled stream before matching
(`pfw_prog.decode`): `DECODE_NONE (0)`, `DECODE_H2 (1)` (HPACK, HTTP/2 HEADERS),
`DECODE_HUFFMAN (2)` (HPACK-Huffman via a baked table), `DECODE_TRANSFORM (3)` (a
host-loaded `tt_cells` table chosen by `transform_table`). Decoding and matching
are **separate eBPF programs** so each stays within the verifier's per-program
budget; they are wired through the `decode_jmp` PROG_ARRAY:

| slot | program |
|---|---|
| `SLOT_DECODE (0)` | `pfw_decode` — h2 frames: walk and consume frames, gather header blocks |
| `SLOT_MATCH (1)` | `pfw_match` — the matcher, over the decoded view |
| `SLOT_RESOLVE (2)` | `pfw_resolve` — h2: table resolution, dynamic-table updates, the text view |
| `SLOT_HUFF (3)` | `pfw_huff` — Huffman decode of a whole stream |
| `SLOT_TRANSFORM (4)` | `pfw_transform` — loadable-table decode |
| `SLOT_REWRITE (5)` | `pfw_rewrite` — apply recorded `redact`/`replace` + fix the L4 checksum |
| `SLOT_HPACK (6)` | `pfw_hpack` — h2: HPACK field parsing and Huffman string decode |
| `SLOT_DISPATCH (7)` | `pfw_dispatch` — the entry again, without the first program: where a packet the first program passed is sent on to its own |

A loader must attach all seven before the entry; `PfwVm` (`pfw-core/loader`)
does.

The entry (`pfw_xdp`) parses L2–L4, does TCP reassembly when enabled, initialises
the per-CPU state, and either tail-calls a decode stage or runs the matcher
inline. On the pass path, if the program recorded any rewrites, the matcher
tail-calls `SLOT_REWRITE` before the packet continues.

### What the matcher reads

A decode stage never rewrites the flow's reassembled stream. It leaves its output
in `st->view` (per-CPU, `REASM_CAP` bytes) and points `%payload`/`%cur`/`%end`/
`%len` at it; `pfw_match` reads the view, `pfw_xdp` (no decode) reads the stream.
Each program therefore has a single read source (`pfw_ctx.rsrc`). `log(N)`
captures from that same source.

### `decode h2` in detail

Three passes (`bpf/include/decode/h2.h`), each a small `bpf_loop` callback whose
cursors live in the per-CPU state so the verifier does not track them precisely:

1. **frames** — walk the frames at the front of the window. Header sequences
   (`HEADERS` + `CONTINUATION`*, with `PADDED`/`PRIORITY` stripped) that are
   complete are gathered; everything walked is **consumed** — shifted out of the
   reassembly window — so the connection is followed across any number of
   requests. A non-header frame body larger than the window (`DATA`) is skipped as
   its bytes arrive, without buffering.
2. **hpack** — parse the block into a normalized intermediate: every field as
   (kind, index) plus raw strings. Multi-byte integers and Huffman-coded strings
   (the baked RFC 7541 table) are decoded here.
3. **resolve** — expand to `name: value\n` lines, resolving static-table (1–61)
   and dynamic-table (62+) references, and apply the block's insertions to the
   connection's dynamic table (`h2conns`, the newest `H2_DYN_SLOTS = 64` entries,
   `H2_ENT_CAP = 256` bytes each).

The view a program sees for one packet is the header lines of the blocks that
packet completed — pseudo-headers as `:method: GET` — followed by one
`:frame: rst_stream` line per `RST_STREAM` frame it carried (at most 8). It is
empty (`len == 0`) when the packet completed none.

| situation | behaviour |
|---|---|
| the connection does not open with the client preface | matched as a plain stream (`H2_MODE_RAW`): HTTP/1.1 on the same port works (`h2_raw`) |
| a reference to an entry older than the 64 kept | shown as `?`, counted in `h2_unresolved` |
| the decoded lines exceed the view | truncated at `REASM_CAP`, counted in `h2_trunc` |
| a malformed frame or header block | reset (`h2_failed`) |
| a header sequence that cannot fit the window (> ~4 kB compressed) | reset (`reasm_over`) |
| the dynamic table was evicted under a live connection (`H2_CONNS = 1024`, LRU) | reset (`h2_failed`) |
| one TCP segment larger than the window | reset — fine at a 1500-byte MTU; jumbo frames and loopback writes over 4 kB hit it |

Only the client-to-server direction is decoded, and only cleartext HTTP/2 (h2c
with prior knowledge). An `Upgrade: h2c` handshake starts as HTTP/1.1 and stays
in raw mode. TLS-wrapped h2 is ciphertext at XDP.

---
