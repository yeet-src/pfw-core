/* macro NAME { ... } — a named block expanded inline at its call site (no calls
 * on the forward-only machine). The emitted bytecode must be identical to
 * writing the statements out by hand, and multiple macros expand independently. */
import { compile } from "#/clang.js";
import { fromC, V } from "./helpers.mjs";

const J = (p) => JSON.stringify(p.ops, (_, x) => (typeof x === "bigint" ? "0x" + x.toString(16) : x));
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const same = (a, b, m) => {
  const ca = compile(a), cb = compile(b);
  if (!ca.ok) throw new Error(`${m}: macro src failed ${JSON.stringify(ca.errors)}`);
  if (!cb.ok) throw new Error(`${m}: inline src failed ${JSON.stringify(cb.errors)}`);
  if (J(ca.program) !== J(cb.program)) throw new Error(`${m}: expansion != inline`);
};

yeet.test("a macro expands to exactly the inline statements", () => {
  const withMacro = `macro guard { if (proto != 6) return pass; if (dport != 80) return pass; }
    filter { guard; return drop("x"); }`;
  const inline = `filter { if (proto != 6) return pass; if (dport != 80) return pass; return drop("x"); }`;
  same(withMacro, inline, "single macro");
});

yeet.test("two macros expand independently and in order", () => {
  const withMacros = `macro a { if (proto != 6) return pass; }
    macro b { if (dport != 80) return pass; }
    filter { a; b; return drop("x"); }`;
  const inline = `filter { if (proto != 6) return pass; if (dport != 80) return pass; return drop("x"); }`;
  same(withMacros, inline, "two macros");
});

yeet.test("the expanded program behaves", () => {
  const src = `macro only80 { if (dport != 80) return pass; }
    filter { only80; return drop("blocked"); }`;
  const prog = fromC(src);
  eq(prog.run(new Uint8Array(0), {}, { dport: 80 }).verdict, V.DROP, "on :80 the body runs");
  eq(prog.run(new Uint8Array(0), {}, { dport: 22 }).verdict, V.PASS, "off :80 the guard returns");
});
