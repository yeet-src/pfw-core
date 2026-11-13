/* Per-flow ring (P3): push / newest-wins get / len / eviction at RING_CAP /
 * out-of-range. Each program ends in rst("ok") only if every assertion held,
 * else drop(reason) — so a break names the invariant that failed. */
import { compile } from "#/src/clang.js";
import { assemble } from "#/src/asm.js";
import { build } from "#/src/ac.js";
import { machine, V } from "#/src/interp.js";

const ok = (src) => {
  const c = compile(src);
  if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors));
  const asm = assemble(c.asm);
  if (!asm.ok) throw new Error("assemble: " + JSON.stringify(asm.errors));
  const res = machine({ asm, tables: build(asm.patterns, asm.nocase) })(new Uint8Array(8), 0, { ac: 0, mask: 0n }, { proto: 6, dport: 8080 });
  if (res.verdict !== V.RST) throw new Error("broke invariant: " + (asm.rules[res.rule]?.name ?? res.rule));
};

yeet.test("order & length", () => ok(`filter {
  ring.push(10); ring.push(20); ring.push(30);
  if (ring.len != 3) return drop("len");
  if (ring.get(0) != 30) return drop("newest");
  if (ring.get(1) != 20) return drop("mid");
  if (ring.get(2) != 10) return drop("oldest");
  return rst("ok", 0);
}`));

yeet.test("eviction at capacity (16)", () => ok(`filter {
  let i = 0;
  repeat(20) { ring.push(i); i = i + 1; }
  if (ring.len != 16) return drop("cap");
  if (ring.get(0) != 19) return drop("newest");
  if (ring.get(15) != 4) return drop("oldest");
  return rst("ok", 0);
}`));

yeet.test("out-of-range get is 0", () => ok(`filter {
  if (ring.get(5) != 0) return drop("not0");
  if (ring.len != 0) return drop("len");
  return rst("ok", 0);
}`));

yeet.test("single push", () => ok(`filter {
  ring.push(777);
  if (ring.len != 1) return drop("len");
  if (ring.get(0) != 777) return drop("val");
  if (ring.get(1) != 0) return drop("absent");
  return rst("ok", 0);
}`));
