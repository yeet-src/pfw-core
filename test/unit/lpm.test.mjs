/* `src in set` — longest-prefix membership against the lpm_trie CIDR set. The
 * set is host-loaded, so the reference interpreter takes it via opts.set (CIDR
 * strings) and does the membership test; the kernel uses the real trie
 * (test/kernel/lpm.mjs). */
import * as C from "#/dsl.js";
import { compile } from "#/clang";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const J = (ops) => JSON.stringify(ops, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));

yeet.test("src in set — membership across prefixes", () => {
  const p = C.program(C.filter(C.iff(C.inSet(C.src), C.drop("blocked")), C.pass()));
  const set = ["10.0.0.0/8", "192.168.1.0/24", "203.0.113.7/32"];
  eq(p.exec(enc(""), { src: "10.1.2.3", set }).verdict, "drop", "in 10/8");
  eq(p.exec(enc(""), { src: "192.168.1.50", set }).verdict, "drop", "in 192.168.1/24");
  eq(p.exec(enc(""), { src: "203.0.113.7", set }).verdict, "drop", "exact /32");
  eq(p.exec(enc(""), { src: "203.0.113.8", set }).verdict, "pass", "just outside /32");
  eq(p.exec(enc(""), { src: "8.8.8.8", set }).verdict, "pass", "not in any");
  eq(p.exec(enc(""), { src: "10.0.0.1", set: [] }).verdict, "pass", "empty set never matches");
});

yeet.test("src in set — pfw-C compiles and the DSL matches it", () => {
  const s = compile(`filter { if (src in set) decide drop("b"); decide pass; }`);
  if (!s.ok) throw new Error("source: " + JSON.stringify(s.errors));
  const d = C.program(C.filter(C.iff(C.inSet(C.src), C.drop("b")), C.pass()));
  if (J(s.program.ops) !== J(d.program.ops)) throw new Error("DSL != source");
});

yeet.test("src in set — negatable and combinable", () => {
  // allow internal, drop everything else that isn't in the set
  const p = C.program(C.filter(C.iff(C.not(C.inSet(C.src)), C.drop("external")), C.pass()));
  const set = ["10.0.0.0/8"];
  eq(p.exec(enc(""), { src: "10.5.5.5", set }).verdict, "pass", "internal passes");
  eq(p.exec(enc(""), { src: "1.2.3.4", set }).verdict, "drop", "external dropped");
});
