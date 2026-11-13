/* Per-connection state — flow.state (read, write, `for` TTL) and flow.count
 * (read-then-increment). Writes defer to the next packet, exactly as the kernel
 * applies them, so a write is observed on the following run, not this one. */
import { fromC, V } from "./helpers.mjs";

const run = (src, flow = {}, opts = {}) => fromC(src).run(new Uint8Array(0), flow, opts);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("flow.state read matches the carried state", () => {
  const s = `filter { if (flow.state == 7) return drop("s"); return pass; }`;
  eq(run(s, { userState: 7 }).verdict, V.DROP, "matches");
  eq(run(s, { userState: 1 }).verdict, V.PASS, "differs");
});

yeet.test("flow.state write is deferred, then visible next packet", () => {
  const s = `filter { if (flow.state == 1) return pass; flow.state = 1; return drop("first"); }`;
  const r1 = run(s, {});
  eq(r1.verdict, V.DROP, "first packet still sees state 0");
  eq(r1.flow.userState, 1, "but the write is carried out");
  eq(run(s, r1.flow).verdict, V.PASS, "next packet sees state 1");
});

yeet.test("flow.state = N for TTL compiles and carries the value", () => {
  const r = run(`filter { flow.state = 5 for 300; return pass; }`, {});
  eq(r.flow.userState, 5, "ttl form still sets the state");
});

yeet.test("flow.count is read-then-increment (post-increment value)", () => {
  const s = `filter { if (flow.count >= 3) return rst("rate", 0); return pass; }`;
  eq(run(s, { hits: 0 }).verdict, V.PASS, "1st hit -> count 1");
  eq(run(s, { hits: 1 }).verdict, V.PASS, "2nd hit -> count 2");
  eq(run(s, { hits: 2 }).verdict, V.RST, "3rd hit -> count 3 trips");
  eq(run(s, { hits: 2 }).flow.hits, 3, "counter advanced to 3");
});
