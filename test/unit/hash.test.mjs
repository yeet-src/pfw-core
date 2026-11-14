/* `x in hash` — exact set membership against a host-loaded u32 set (ports,
 * 32-bit hashes/fingerprints). The set is host-loaded, so the reference
 * interpreter takes it via opts.hashset; the kernel uses the real hash map
 * (test/kernel/hash.mjs). */
import * as C from "#/dsl.js";
import { compile } from "#/clang.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const J = (ops) => JSON.stringify(ops, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));

yeet.test("dport in hash — membership", () => {
  const p = C.program(C.filter(C.iff(C.inHash(C.dport), C.drop("badport")), C.pass()));
  const set = [31337, 4444, 6667];
  eq(p.exec(enc(""), { dport: 31337, hashset: set }).verdict, "drop", "in set");
  eq(p.exec(enc(""), { dport: 80, hashset: set }).verdict, "pass", "not in set");
  eq(p.exec(enc(""), { dport: 31337, hashset: [] }).verdict, "pass", "empty set never matches");
});

yeet.test("x in hash — pfw-C compiles and the DSL matches it", () => {
  const s = compile(`filter { if (dport in hash) return drop("b"); return pass; }`);
  if (!s.ok) throw new Error("source: " + JSON.stringify(s.errors));
  const d = C.program(C.filter(C.iff(C.inHash(C.dport), C.drop("b")), C.pass()));
  if (J(s.program.ops) !== J(d.program.ops)) throw new Error("DSL != source");
});

yeet.test("hash works on a computed value and negates", () => {
  // allow only known ports: drop if dport NOT in the set
  const p = C.program(C.filter(C.iff(C.not(C.inHash(C.dport)), C.drop("unknown_port")), C.pass()));
  const set = [80, 443];
  eq(p.exec(enc(""), { dport: 443, hashset: set }).verdict, "pass", "known passes");
  eq(p.exec(enc(""), { dport: 22, hashset: set }).verdict, "drop", "unknown dropped");
});
