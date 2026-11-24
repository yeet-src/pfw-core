# 11. Gotchas and limits

**Compile-time rules**

- `scan(ptr, N)` — `N` is a constant, never a variable or `argv`.
- `redact`/`replace` — literal pattern or **fixed-length** regex only; `replace`
  replacement must equal the match length.
- Verdicts use **`decide`**; `return` is a subroutine value. `return <verdict>`
  is a compile error that points you at `decide`.
- `any`/`all`/`seq`/`rate`/membership are **conditions**, not values — use them in
  `if`, don't store or `return` them.
- Subroutines: ≤ 7 params; `fn`/`match`/`switch`/`push`/`pop` are source-only
  (not in the DSL); keep the data stack balanced across a call; a0..a6/rv are
  caller-saved.
- `console`: ≤ 8 numeric args + ≤ 2 `%s` (packet pointer). `emit`: ≤ 8 values,
  and one name always carries the same number of them. `printk`: ≤ 3 numeric
  args, no `%s`.
- `rate` and `dnat` take values as well as constants (`argv`, `knob("…")`,
  locals); `redirect`'s ifindex and `scan`'s length are constants. A computed
  `dnat` address of 0 steers nothing, and a computed `rate` burst of 0 passes
  nothing. `knob("x") ?? d` seeds `d` at load; it is overridable to `0`, not an
  if-zero default. `kstr("…")` is a condition only.

**Runtime behaviour worth knowing**

- `ban` bans the **source address**, on every port and protocol, until its TTL.
  Do not ban on a signal an attacker can make a victim's address produce.
- `flow.*` is per connection (the 4-tuple); `src.*` is per source address and
  survives a reconnect. "Repeat offender" logic wants `src.count`.
- `flow.count` / `src.count` **increment on every read**. Read once into a `let`.
- `flow.packets` and `flow.bytes` count the connection's packets whether the
  program reads them or not — once it has read either on some packet of that
  connection. They include the packet being judged.
- `flow.r0`–`flow.r3` survive a program swap, like all flow state: a new program
  that uses a register finds what the last one left in it.
- On a reassembled stream (`reassemble` / `decode`), `decide drop` blackholes the
  **connection**, not just the packet — otherwise TCP's retransmission of the
  dropped segment would get through.
- `scan` accumulates: the match mask holds every pattern any scan has seen so
  far (and, per-packet, earlier segments of the connection). To ask what lies in
  one window — a header value, a frame — use `within(ptr, N)`.
- `reassemble` follows a connection for its whole life through a sliding
  2048-byte window. A pattern is seen whole if it is at most 64 bytes long.
- `decode h2` shows one packet's completed header blocks, not the whole
  connection, and `len == 0` when a packet completed none. It needs cleartext
  HTTP/2 and segments no larger than the window (see isa §8).
- Payload on a TLS port is ciphertext. Only the handshake (`ClientHello`: SNI,
  versions, cipher list) is readable there.
- `dnat` is two-way for TCP/UDP over IPv4, but it cannot move a connection that
  is already established: divert from the first packet (see `honeypot.pfc`).

**Budgets** (`LIMITS` in `src/isa.js`, mirrored in `bpf/include/pfw.h`)

| limit | value |
|---|---|
| instructions / program | 65536 |
| patterns (`scan` matches all at once) | 64 |
| pattern length | 64 B |
| scan window | 4096 B |
| AC automaton states | 16384 |
| regex DFA states | 8192 |
| scratch registers (locals, by live range) | 16 |
| subroutine args | 7 (`%a0..%a6`) |
| data-stack depth | 256 |
| rules (named verdicts) | 1024 |
| runtime args (`argv`) | 64 |
| lookup tables / cells in all | 16 / 131072 |
| `lookup` map entries | 262144 |
| numeric knobs (`knob`) | 256 |
| string knobs (`kstr`) | 64 (≤ 64 B, scans 256 B) |
| per-flow ring | 16 |
| `sample` length / tags | 2048 B / 63 |
| per-flow registers (`flow.r0`…) | 4 |
| `console` %s capture | 256 B |
| `printk` formats / length | 16 / 64 B |

See [`isa.md`](isa.md) for the machine these compile to, and the README for the
public JS interface and loading a program into the kernel.
