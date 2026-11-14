/* `rate(per_second, burst)` — a per-flow token-bucket rate limit. The condition
 * is true when the flow is OVER the limit (the packet found no token to spend).
 * Kernel state (tokens + last-refill time) lives in the flow; the reference
 * interpreter models it through a persistent `bucket` object + a `now` clock the
 * caller threads across packets, so these tests pin both the lowering and the
 * bucket algorithm the kernel mirrors. */
import * as C from "#/dsl.js";
import { compile } from "#/clang";
import { assemble } from "#/asm.js";
import { OP } from "#/isa.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const J = (ops) => JSON.stringify(ops, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));

/* `if (rate(r,b)) decide drop; decide pass;` — pass = allowed, drop = limited. */
const limiter = (r, b) => C.program(C.filter(C.iff(C.rate(r, b), C.drop("rl")), C.pass()));
const S = 1_000_000_000; // one second in ns

yeet.test("rate lowers to OP_RATE packing rate | burst<<32", () => {
  const op = limiter(10, 20).program.ops.find((o) => o.code === OP.RATE);
  if (!op) throw new Error("no OP_RATE emitted");
  eq(Number(op.imm & 0xffffffffn), 10, "rate");
  eq(Number((op.imm >> 32n) & 0xffffffffn), 20, "burst");
});

yeet.test("burst is allowed, then the bucket runs dry", () => {
  const p = limiter(1, 3); // 1 tok/s, bucket of 3
  const bucket = {};
  const hit = (now) => p.exec(enc("x"), { bucket, now: BigInt(now) }).verdict;
  // all at t=0: first 3 (the burst) pass, the 4th+ are limited
  eq(hit(0), "pass", "burst 1");
  eq(hit(0), "pass", "burst 2");
  eq(hit(0), "pass", "burst 3");
  eq(hit(0), "drop", "over the burst");
  eq(hit(0), "drop", "still over");
});

yeet.test("the bucket refills over time", () => {
  const p = limiter(1, 3);
  const bucket = {};
  const hit = (now) => p.exec(enc("x"), { bucket, now: BigInt(now) }).verdict;
  hit(0); hit(0); hit(0);          // drain the burst
  eq(hit(0), "drop", "empty");
  eq(hit(1 * S), "pass", "one token back after 1s"); // refill 1 tok/s
  eq(hit(1 * S), "drop", "and dry again");
  eq(hit(3 * S), "pass", "refilled after 3s");
});

yeet.test("pfw-C, DSL and asm all lower rate identically", () => {
  const s = compile(`filter { if (rate(5, 10)) decide drop("rl"); decide pass; }`);
  if (!s.ok) throw new Error("source: " + JSON.stringify(s.errors));
  const d = limiter(5, 10);
  if (J(s.program.ops) !== J(d.program.ops)) throw new Error("DSL != source");

  const a = assemble(`        rate $5, $10\n        je over\n        pass\n over: drop $rl`);
  if (!a.ok) throw new Error("asm: " + JSON.stringify(a.errors));
  const aop = a.program.ops.find((o) => o.code === OP.RATE);
  if (!aop || Number(aop.imm & 0xffffffffn) !== 5 || Number((aop.imm >> 32n) & 0xffffffffn) !== 10) throw new Error("asm rate imm wrong");
});

yeet.test("pfw-C rejects bad rate arguments", () => {
  for (const bad of [`rate(10)`, `rate(0, 5)`, `rate(5, 0)`, `rate(1, 2, 3)`]) {
    const r = compile(`filter { if (${bad}) decide drop("x"); decide pass; }`);
    if (r.ok) throw new Error("should have rejected: " + bad);
  }
});
