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
- `console`: ≤ 4 numeric args + ≤ 2 `%s` (packet pointer). `printk`: ≤ 3 numeric
  args, no `%s`.
- `argv` and `knob("…")` are not `rate`/`dnat`/`redirect` arguments (those need
  constants). `knob("x") ?? d` seeds `d` at load; it is overridable to `0`, not an
  if-zero default. `kstr("…")` is a condition only.

**Runtime behaviour worth knowing**

- `ban` bans the **source address**, on every port and protocol, until its TTL.
  Do not ban on a signal an attacker can make a victim's address produce.
- `flow.*` is per connection (the 4-tuple); `src.*` is per source address and
  survives a reconnect. "Repeat offender" logic wants `src.count`.
- `flow.count` / `src.count` **increment on every read**. Read once into a `let`.
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
| instructions / program | 8192 |
| patterns (`scan` matches all at once) | 64 |
| pattern length | 64 B |
| scan window | 2048 B |
| AC automaton states | 4096 |
| regex DFA states | 1024 |
| scratch registers (locals, by live range) | 16 |
| subroutine args | 7 (`%a0..%a6`) |
| data-stack depth | 64 |
| rules (named verdicts) | 64 |
| runtime args (`argv`) | 16 |
| numeric knobs (`knob`) | 32 |
| string knobs (`kstr`) | 16 (≤ 64 B, scans 256 B) |
| per-flow ring | 16 |
| `console` %s capture | 256 B |
| `printk` formats / length | 8 / 64 B |

See [`isa.md`](isa.md) for the machine these compile to, and the README for the
public JS interface and loading a program into the kernel.
