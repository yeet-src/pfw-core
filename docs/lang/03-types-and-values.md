# 3. Types and values

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
