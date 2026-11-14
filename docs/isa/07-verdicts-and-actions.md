# 7. Verdicts and actions

`enum pfw_verdict { V_NONE, V_PASS, V_DROP, V_BAN, V_RST }`. `finish()`
(`match_half`) turns the final verdict into an XDP action:

| verdict | XDP action | side effects |
|---|---|---|
| `PASS` (or none) | `XDP_PASS` (or tail-call the rewrite stage if `rw_n`) | — |
| `DROP` | `XDP_DROP` | `count_rule`, `dropped++`. In reassembly/decode mode the **connection** is marked `MARK_DROP` too: TCP would retransmit the dropped segment after its bytes were consumed or slid out of the window, and it would then pass |
| `BAN` | `XDP_DROP` | the **source address** is marked `MARK_DROP` in `sources` for the TTL (and so is the flow); every later packet from that address is dropped at the entry |
| `RST` | `XDP_TX` (IPv4 TCP: a crafted RST) else `XDP_DROP` | flow marked `MARK_RST` for the TTL |

Overrides and fast paths:

- **`redirect`** takes precedence over any verdict: `maybe_redirect` issues
  `bpf_redirect(ifindex)` and returns `XDP_REDIRECT`.
- **Shadow mode**: when `shadow` is set, a `DROP`/`BAN`/`RST` is still counted,
  logged, and its flow mark written, but the packet is returned `XDP_PASS`
  (`shadowed++`). `%shadow` also exposes the flag to the program.
- **Source ban**: the first check after parsing. A packet whose source address
  carries a live ban is dropped (`src_enforced++`) whatever its port or protocol;
  an expired ban is lifted there. Shadow mode passes it and plants no ban.
- **Reverse NAT**: a packet that is the reply on a connection `dnat` diverted has
  its source restored to the address the client dialled and is passed; the
  program does not run on it (`nat_reversed++`).
- **Entry fast path**: before running the program, an established flow already
  carrying `MARK_DROP`/`MARK_RST` (and not expired) is enforced immediately
  (dropped or RST), honouring shadow mode. A fresh TCP SYN clears a stale mark in
  reassembly mode so a reused ephemeral port is judged on its own bytes.
- **Flow write-back** (marks, user state, hits, rate tokens, automaton state) is
  applied after the run, visible on the next packet.

`enum pfw_mark { MARK_NONE, MARK_DROP = 1, MARK_RST = 2 }` (user marks via `mark`
use values from 16 up).

---
