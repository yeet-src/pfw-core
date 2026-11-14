/* Per-flow ring (P3): push / newest-wins get / len / eviction at RING_CAP /
 * out-of-range. Each program ends in rst("ok") only if every assertion held,
 * else drop(reason) — so a break names the invariant that failed. */
import { fromC, V } from "./helpers.mjs";

const ok = (src) => {
  const { run, rules } = fromC(src);
  const res = run(new Uint8Array(8), {}, { proto: 6, dport: 8080 });
  if (res.verdict !== V.RST) throw new Error("broke invariant: " + (rules[res.rule]?.name ?? res.rule));
};

yeet.test("order & length", () => ok(`filter {
  ring.push(10); ring.push(20); ring.push(30);
  if (ring.len != 3) decide drop("len");
  if (ring.get(0) != 30) decide drop("newest");
  if (ring.get(1) != 20) decide drop("mid");
  if (ring.get(2) != 10) decide drop("oldest");
  decide rst("ok", 0);
}`));

yeet.test("eviction at capacity (16)", () => ok(`filter {
  let i = 0;
  repeat(20) { ring.push(i); i = i + 1; }
  if (ring.len != 16) decide drop("cap");
  if (ring.get(0) != 19) decide drop("newest");
  if (ring.get(15) != 4) decide drop("oldest");
  decide rst("ok", 0);
}`));

yeet.test("out-of-range get is 0", () => ok(`filter {
  if (ring.get(5) != 0) decide drop("not0");
  if (ring.len != 0) decide drop("len");
  decide rst("ok", 0);
}`));

yeet.test("single push", () => ok(`filter {
  ring.push(777);
  if (ring.len != 1) decide drop("len");
  if (ring.get(0) != 777) decide drop("val");
  if (ring.get(1) != 0) decide drop("absent");
  decide rst("ok", 0);
}`));
