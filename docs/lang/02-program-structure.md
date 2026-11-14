# 2. Program structure

A program is a sequence of top-level items in **any order**, exactly one of which
is the required `filter` block:

```
nocase;                         // case-fold all matching
reassemble [PORT];              // match the coalesced TCP stream (optional dport filter)
decode h2|huffman|<table> [PORT];  // normalize the stream before matching (implies reassembly)
pattern NAME = "lit" | { bytes } [, NAME = ...];
regex NAME = "regex";
knob struct NAME { f [?? d], ... };  // group live control knobs, read as NAME.f (§4)
macro NAME { statements }       // a reusable statement block, expanded by `NAME;`
fn NAME(p0, …) { statements }   // a subroutine (§7)
filter { statements }           // REQUIRED — the program body
```

Pattern/`regex` references resolve regardless of declaration order. `decode`
takes a built-in front-end (`h2` HPACK headers, `huffman` HPACK-Huffman) or the
name of a loadable byte-transform table; it implies `reassemble`. The optional
`PORT` on `reassemble`/`decode` restricts reassembly to that TCP destination port
(`0`/omitted = every TCP flow).

A `knob struct` is **sugar** that reserves consecutive knob slots for a set of
related live controls (see [§4, Live control knobs](04-expressions.md)), read as
`NAME.field`. Each field may carry a `?? default` seeded by the loader. It is a
naming convenience — the fields are ordinary numeric knobs.

```c
knob struct cfg { rate ?? 50, burst ?? 100, mode };
filter {
  if (len > cfg.rate) decide drop("rate");   // cfg.rate, cfg.burst, cfg.mode
  decide pass;                                // occupy three consecutive slots
}
```

```c
nocase;
reassemble 8080;
pattern gptbot = "GPTBot", claudebot = "ClaudeBot";
filter {
  if (dport != 80) decide pass;
  if (scan(payload, 1460) & (gptbot | claudebot)) decide rst("crawler", 60);
  decide pass;
}
```

---
