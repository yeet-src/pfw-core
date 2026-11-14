# 8. Decode front-ends and the rewrite stage

A program may normalise the reassembled stream before matching
(`pfw_prog.decode`): `DECODE_NONE (0)`, `DECODE_H2 (1)` (HPACK, HTTP/2 HEADERS),
`DECODE_HUFFMAN (2)` (HPACK-Huffman via a baked table), `DECODE_TRANSFORM (3)` (a
host-loaded `tt_cells` table chosen by `transform_table`). Decoding and matching
are **separate eBPF programs** so each stays within the verifier's per-program
budget; they are wired through the `decode_jmp` PROG_ARRAY:

| slot | program |
|---|---|
| `SLOT_DECODE (0)` | HPACK/h2 decode |
| `SLOT_MATCH (1)` | the matcher (`pfw_match`) |
| `SLOT_RESOLVE (2)` | HPACK index resolution |
| `SLOT_HUFF (3)` | Huffman decode |
| `SLOT_TRANSFORM (4)` | loadable-table decode |
| `SLOT_REWRITE (5)` | apply recorded `redact`/`replace` + fix the L4 checksum |

The entry (`pfw_xdp`) parses L2–L4, does TCP reassembly when enabled, initialises
the per-CPU state, and either tail-calls a decode stage or runs the matcher
inline. On the pass path, if the program recorded any rewrites, the matcher
tail-calls `SLOT_REWRITE` before the packet continues.

---
