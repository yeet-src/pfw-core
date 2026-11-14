/* The runnable Program API: exec() with args, verdict names, rule names, the
 * per-flow state carried out and back in (multi-packet), src as a dotted string,
 * payload offset, and the loader artifacts bytes()/tables(). */
import * as C from "#/dsl.js";
import { load } from "#/index.js";
import { LIMITS } from "#/isa.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };

yeet.test("exec returns verdict name, code and rule name", () => {
  const p = C.program(C.pattern("bot", "GPTBot"), C.filter(C.iff(C.band(C.scan(C.payload, 256), "bot"), C.rst("crawler", 0)), C.pass()));
  const hit = p.exec(enc("x GPTBot"), {});
  eq(hit.verdict, "rst", "verdict"); eq(hit.ruleName, "crawler", "ruleName"); eq(hit.rule, 1, "rule id");
  eq(p.exec(enc("clean"), {}).verdict, "pass", "miss passes");
});

yeet.test("src accepts a dotted-quad string", () => {
  const p = C.program(C.filter(C.iff(C.inCidr(C.src, "192.168.0.0/16"), C.drop("lan")), C.pass()));
  eq(p.exec(enc(""), { src: "192.168.5.5" }).verdict, "drop", "in lan");
  eq(p.exec(enc(""), { src: "192.169.0.1" }).verdict, "pass", "outside lan");
});

yeet.test("flow carries out and back in (multi-packet rate limit)", () => {
  // reset once the flow has produced 3 data segments; thread the returned flow.
  const p = C.program(C.filter(C.ringPush(C.len), C.iff(C.ge(C.ringLen, 3), C.rst("rate", 0)), C.pass()));
  let flow = {};
  const verdicts = [];
  for (let i = 0; i < 4; i++) { const r = p.exec(enc("seg"), { flow }); verdicts.push(r.verdict); flow = r.flow; }
  eq(JSON.stringify(verdicts), JSON.stringify(["pass", "pass", "rst", "rst"]), "3rd segment resets");
});

yeet.test("payload offset is honoured", () => {
  const p = C.program(C.pattern("bot", "GPTBot"), C.filter(C.iff(C.band(C.scan(C.payload, 256), "bot"), C.drop("x")), C.pass()));
  // GPTBot is at offset 4; scanning from payload 0 finds it, from payload 8 does not.
  eq(p.exec(enc("xxxxGPTBot"), { payload: 0 }).verdict, "drop", "from 0");
  eq(p.exec(enc("xxxxGPTBot"), { payload: 8 }).verdict, "pass", "from 8 (past it)");
});

yeet.test("bytes() is the fixed-size programs value; tables() is the automaton", () => {
  const p = C.program(C.pattern("bot", "GPTBot"), C.filter(C.iff(C.band(C.scan(C.payload, 256), "bot"), C.drop("x")), C.pass()));
  const bytes = p.bytes();
  if (!(bytes instanceof Uint8Array)) throw new Error("bytes() should be a Uint8Array");
  // header + MAX_OPS*16 + MAX_PATS*(4+PAT_CAP)
  const expect = 32 + LIMITS.MAX_OPS * 16 + LIMITS.MAX_PATS * (4 + LIMITS.PAT_CAP);
  eq(bytes.length, expect, "serialized size");
  if (p.tables().edges.length === 0) throw new Error("automaton should have edges for a pattern");
});

yeet.test("load() compiles source to the same runnable Program", () => {
  const src = `pattern bot = "GPTBot"; filter { if (scan(payload,256) & bot) decide rst("x",0); decide pass; }`;
  eq(load(src).exec(enc("a GPTBot b"), {}).verdict, "rst", "load+exec");
});

yeet.test("a compile error throws from load()", () => {
  let threw = false;
  try { load("filter { if (dport) return nonsense; }"); } catch { threw = true; }
  if (!threw) throw new Error("expected load() to throw on a bad program");
});
