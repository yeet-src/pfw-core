# Upgrade notes

What changes for a program, or a host, written against an earlier pfw-core.
Additions that leave existing behaviour alone are not listed; this is the
changes that can make something behave differently.

## Programs

**The reassembly window is 4096 bytes** (it was 2048). Over a reassembled or
decoded stream, `scan(payload, N)` reads the first `N` bytes of the window and
nothing behind them, so a program that says `scan(payload, 2048)` now covers
the front half only. Say `scan(payload, 4096)`. The compiler lists every such
scan in `warnings`, and `node test/node/examples.mjs` prints them for the
programs in this repo.

**A segment larger than the window is read whole.** A reassembling program
used to see only the first window's worth of a segment longer than the window
(loopback and jumbo frames carry up to 64 kB). It now runs over the segment a
piece at a time, and the packet passes only if every piece does. A rule that
relied on the tail of a large segment going unread now sees it.

**A connection open before the program is followed, not reset.** `reassemble`
used to reset a connection whose start it had not seen, which cut every
keep-alive connection on the port when a first policy loaded. It follows such a
connection from the segment it picks it up at. A program that decodes (`decode
h2`, `huffman`, a transform table) still resets one: a decode cannot begin
part-way.

**Regexes read the bytes as they are.** Under `nocase` a regex still ignores
case, as before. What is new is that a regex beginning `(?-i)` does not, and one
beginning `(?i)` does whatever the program says.

**Limits went up**, and one name changed with them: a `skip` with no cap still
passes over at most 64 bytes, though a pattern may now be 256. The current
figures are in [`lang.md`](lang.md) §11 and [`isa.md`](isa.md) §9.

## Hosts

**`stats().rules[name]` counts decisions, not packets.** It was bumped again by
every later packet of a connection the rule had marked — each retransmission of
a dropped segment — and by every packet from a source it had banned. The
packets are now in `stats().enforced_rules[name]`. A host that reports
"blocked requests" wants `rules`; one that reports packets stopped wants
`dropped + rsts`.

**`bans` counts `ban` verdicts only.** A reset is in `rsts`, and no longer in
`bans` as well. A host that added `dropped + rsts + bans` counted every reset
twice.

**Shadow mode counts verdicts apart from packets.** `shadowed` is the verdicts
shadow mode let through; `shadow_enforced` is the packets a standing mark or
ban would then have stopped. `shadowed` used to be both.

**Events carry `route`.** Every verdict, console, emit and sample event says
which installed program raised it: `"default"`, `"first"`, or a route's name.
`ruleId` is the rule's id within that program.

**A host that writes the maps itself** (not through `PfwVm`) needs the new
layout, in [`isa.md`](isa.md) §5 and §6:

- The instructions are the `ops` map, one an entry, not an array inside
  `struct pfw_prog`.
- `struct pfw_prog` gains where the program's share of each pool begins
  (`ops_base`, `ac_base`, `re_base`, `tbl_base`, `rule_base`), the regex start
  states (`re_ngroups`, `re_start`, `re_pat_start`), and the stage fields.
- `programs` is indexed by slot, and the program a packet runs is
  `default_slot`, or what `dispatch` / `dispatch_dst` say; `active_gen` is gone.
- The tail-call array has ten entries: `pfw_dispatch`, `pfw_stage` and
  `pfw_continue` after the seven there were.

**Memory.** The kernel side holds more: larger automaton tables, a connection
record of about 4.8 kB (it was 2.5 kB), and about 17 MB for stage programs'
per-connection state, all allocated when the object loads.
