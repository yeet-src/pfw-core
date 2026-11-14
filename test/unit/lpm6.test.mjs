/* `src6 in set6` — IPv6 longest-prefix membership against a host-loaded set of
 * v6 CIDRs. The op reads the v6 source from the packet in the kernel; the
 * reference interpreter takes the source + set via opts (src6 / set6). */
import * as C from "#/dsl.js";
import { compile } from "#/clang.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const J = (ops) => JSON.stringify(ops, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));

yeet.test("src6 in set6 — membership across v6 prefixes", () => {
  const p = C.program(C.filter(C.iff(C.inSet6(), C.drop("v6")), C.pass()));
  const set6 = ["2001:db8::/32", "fe80::/10", "::1/128"];
  eq(p.exec(enc(""), { src6: "2001:db8::5", set6 }).verdict, "drop", "in 2001:db8::/32");
  eq(p.exec(enc(""), { src6: "fe80::1", set6 }).verdict, "drop", "link-local");
  eq(p.exec(enc(""), { src6: "::1", set6 }).verdict, "drop", "exact ::1/128");
  eq(p.exec(enc(""), { src6: "2001:dead::1", set6 }).verdict, "pass", "not in any");
  eq(p.exec(enc(""), { src6: "::2", set6 }).verdict, "pass", "just outside ::1/128");
  eq(p.exec(enc(""), { src6: "2001:db8::5", set6: [] }).verdict, "pass", "empty set");
});

yeet.test("src6 in set6 — pfw-C compiles and the DSL matches it", () => {
  const s = compile(`filter { if (src6 in set6) decide drop("v6"); decide pass; }`);
  if (!s.ok) throw new Error("source: " + JSON.stringify(s.errors));
  const d = C.program(C.filter(C.iff(C.inSet6(), C.drop("v6")), C.pass()));
  if (J(s.program.ops) !== J(d.program.ops)) throw new Error("DSL != source");
});
