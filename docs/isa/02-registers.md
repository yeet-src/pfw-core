# 2. Registers

40 registers, 64-bit each, in a file of 64 (`st->r[]`, `NREGS = 64`). The index
is masked `& (NREGS - 1)`, so `NREGS` must stay a power of two; indices 40–63
are padding that reads zero. Read with `mov %reg, %cur`
(`MOV_RC`); write with `mov %cur, %reg` (`MOV_CR`, which ignores a write to
`%cur`).

| idx | name(s) | role | set by |
|---|---|---|---|
| 0 | `%frame` | offset 0 of the L2 frame | entry |
| 1 | `%l3` | offset of the IP header | entry (parse) |
| 2 | `%l4` | offset of the TCP/UDP header | entry (parse) |
| 3 | `%payload` | first byte after L4 | entry (parse) |
| 4 | `%end` | one past the last readable byte | entry (parse) |
| 5 | `%proto` | IP protocol (`6` TCP, `17` UDP) | entry |
| 6 | `%sport` | source port | entry |
| 7 | `%dport` | destination port | entry |
| 8–11 | `%s0`–`%s3` | scratch / `let` locals | program |
| 12 | `%m` | match mask (scan results) | `scan` |
| 13 | `%cur` | **the cursor / accumulator** | most ops |
| 14 | `%ifindex` | ingress interface index | entry |
| 15 | `%len` | payload byte count (`end − payload`) | entry |
| 16–19 | `%s4`–`%s7` | more scratch / `let` locals | program |
| 20 | `%saddr` (`%src`) | IPv4 source, **host byte order** (0 for IPv6) | entry |
| 21 | `%shadow` | the host shadow-mode flag (read-only intent) | entry |
| 22 | `%sp` | data-stack pointer | `push`/`pop`/`call`/`ret`, writable |
| 23 | `%bp` | data-stack base pointer (frame marker) | program, writable |
| 24–30 | `%a0`–`%a6` | subroutine argument registers | caller |
| 31 | `%rv` | subroutine return-value register | callee |
| 32–39 | `%s8`–`%s15` | more scratch / `let` locals | program |

Notes:

- `%src` is purely an assembler/host alias for `%saddr` (same index 20).
- At entry, `%cur` is initialised to `%payload`. In reassembly mode `%payload`,
  `%cur` are 0 and `%end`/`%len` span the reassembled prefix.
- Every register is physically writable via `MOV_CR` (except `%cur`, which takes
  op results); by convention a program writes only `%s0`–`%s15`, `%sp`/`%bp`,
  `%a0`–`%a6`, `%rv`. `%m` is written by `scan`.

---
