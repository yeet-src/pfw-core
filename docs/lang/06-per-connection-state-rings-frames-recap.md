# 6. Per-connection and per-source state, rings, frames (recap)

`flow.state` (a small user state machine, with optional TTL), `flow.count` (a hit
counter), the per-flow `ring` (push/get/len), and the `frame` walker above are the
stateful/structural features. They persist across packets of the same connection
(state/count/ring) or structure one packet (`frame`). See [`isa.md`](isa.md) for
the backing map layout and the deferred-write model.

### Per-source state

`src.state`, `src.count` and `src.rate(per_second, burst)` are `flow.state`,
`flow.count` and `rate(...)` keyed on the **source address** rather than the
connection. Use them whenever the question is about a client rather than one of
its connections — a flow entry is gone the moment the client reconnects from
another port:

```c
filter {
  if (src.state == 1) decide drop("flagged");            // set on an earlier connection
  if (src.rate(50, 100)) decide drop("too_many_packets"); // one bucket for all its connections
  if (scan(payload, 1460) & probe) {
    let strikes = src.count;                              // increments on read: read once
    if (strikes >= 3) src.state = 1 for 600;
    decide rst("probe", 0);
  }
  decide pass;
}
```

Bare `src` is still the IPv4 source address (`src in "10.0.0.0/8"`). `ban` is the
built-in use of the same table: it bans the source address.

---
