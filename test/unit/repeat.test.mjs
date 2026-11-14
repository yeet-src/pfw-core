/* repeat(N) { ... } — a compile-time unroll (forward-only, so termination is by
 * construction). N copies of the body are emitted; the ring is a convenient way
 * to observe how many times the body actually ran. */
import { fromC, V } from "./helpers.mjs";

const run = (src) => fromC(src).run(new Uint8Array(0), {}, { dport: 8080 });
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("repeat(N) runs the body N times", () => {
  const r = run(`filter { repeat(5) { ring.push(1); } if (ring.len == 5) decide drop("ok"); decide pass; }`);
  eq(r.verdict, V.DROP, "pushed 5");
});

yeet.test("repeat with a counter local", () => {
  // i runs 0..9, accumulated; sum 0+1+..+9 == 45
  const r = run(`filter { let i = 0; let acc = 0; repeat(10) { acc = acc + i; i = i + 1; } if (acc == 45) decide drop("ok"); decide pass; }`);
  eq(r.verdict, V.DROP, "sum 0..9 == 45");
});

yeet.test("repeat(1) is just the body once", () => {
  const r = run(`filter { repeat(1) { ring.push(9); } if (ring.len == 1) decide drop("ok"); decide pass; }`);
  eq(r.verdict, V.DROP, "ran once");
});

yeet.test("repeat(0) emits nothing", () => {
  const r = run(`filter { repeat(0) { ring.push(9); } if (ring.len == 0) decide drop("ok"); decide pass; }`);
  eq(r.verdict, V.DROP, "body never ran");
});
