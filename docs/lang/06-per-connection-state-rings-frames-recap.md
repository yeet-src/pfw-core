# 6. Per-connection state, rings, frames (recap)

`flow.state` (a small user state machine, with optional TTL), `flow.count` (a hit
counter), the per-flow `ring` (push/get/len), and the `frame` walker above are the
stateful/structural features. They persist across packets of the same connection
(state/count/ring) or structure one packet (`frame`). See [`isa.md`](isa.md) for
the backing map layout and the deferred-write model.

---
