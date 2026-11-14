/* knob("name") — a live, host-set control value read per-packet from the `knobs`
 * map. Unlike argv (positional, baked into the program at load), knobs are named
 * and the host rewrites them at any time to drive the running program. The
 * compiler assigns each name a slot (program.knobs[slot] === name); exec takes
 * the current values as { name: value }. */
import { compile } from "#/clang.js";
import { toProgram } from "#/program.js";
import * as C from "#/dsl.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };

yeet.test("a knob drives the verdict and defaults to 0", () => {
  const p = prog(`filter { if (knob("block") == 1) decide drop("blocked"); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "pass", "unset knob -> 0 -> pass");
  eq(p.exec(enc("x"), { knobs: { block: 1 } }).verdict, "drop", "block=1 -> drop");
  eq(p.exec(enc("x"), { knobs: { block: 0 } }).verdict, "pass", "block=0 -> pass");
});

yeet.test("the compiler exposes the name -> slot binding", () => {
  const c = compile(`filter { if (knob("mode") > 0) decide drop("m"); if (len > knob("cap")) decide rst("c", 0); decide pass; }`);
  eq(c.ok, true, "compiles");
  eq(c.knobs[0], "mode", "slot 0");
  eq(c.knobs[1], "cap", "slot 1");
});

yeet.test("a knob works as a runtime threshold", () => {
  const p = prog(`filter { if (len > knob("cap")) decide drop("too_big"); decide pass; }`);
  eq(p.exec(enc("x".repeat(50)), { knobs: { cap: 100 } }).verdict, "pass", "under cap");
  eq(p.exec(enc("x".repeat(50)), { knobs: { cap: 10 } }).verdict, "drop", "over cap");
});

yeet.test("knob(\"name\") ?? default seeds an initial value (overridable, even to 0)", () => {
  const p = prog(`filter { if (dport != knob("port") ?? 8080) decide pass; decide rst("hit", 0); }`);
  const c = compile(`filter { if (dport != knob("port") ?? 8080) decide pass; decide rst("hit", 0); }`);
  eq(Number(c.knobDefaults[0]), 8080, "default recorded");
  eq(p.exec(enc(""), { dport: 8080 }).verdict, "rst", "default 8080 in effect");
  eq(p.exec(enc(""), { dport: 9090 }).verdict, "pass", "default ignores :9090");
  eq(p.exec(enc(""), { dport: 9090, knobs: { port: 9090 } }).verdict, "rst", "host override to 9090");
  eq(p.exec(enc(""), { dport: 0, knobs: { port: 0 } }).verdict, "rst", "override to 0 works (0 is not 'unset')");
});

yeet.test("conflicting defaults for one knob are rejected", () => {
  const r = compile(`filter { if (knob("x") ?? 1) decide drop("a"); if (knob("x") ?? 2) decide drop("b"); decide pass; }`);
  if (r.ok) throw new Error("expected a conflicting-default error");
});

yeet.test("the same knob reused keeps one slot", () => {
  const c = compile(`filter { if (knob("x") == 1) decide drop("a"); if (knob("x") == 2) decide drop("b"); decide pass; }`);
  eq(c.knobs.length, 1, "one slot for repeated name");
});

yeet.test("DSL knob() lowers the same as the source", () => {
  const s = compile(`filter { if (knob("block") == 1) decide drop("b"); decide pass; }`);
  const d = C.program(C.filter(C.iff(C.eq(C.knob("block"), 1), C.drop("b")), C.pass()));
  const J = (ops) => JSON.stringify(ops, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));
  if (J(s.program.ops) !== J(d.program.ops)) throw new Error("DSL != source");
});
