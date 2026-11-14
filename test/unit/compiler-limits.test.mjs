/* Three compiler defects, pinned:
 *   1. a subroutine's local could share a register with a caller's local that is
 *      live across the call, so the callee overwrote it;
 *   2. a regex whose DFA is larger than the kernel's table (LIMITS.RE_STATES)
 *      compiled anyway, and would have indexed past the table in the kernel;
 *   3. a program over the instruction budget threw from compile() instead of
 *      returning { ok: false }. */
import { compile } from "#/clang";
import { load } from "#/index.js";
import { LIMITS } from "#/isa.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("a callee's locals do not clobber a caller's local live across the call", () => {
  const p = load(`fn f() { let s = 7; let t = 9; return s + t; }
    filter { let x = 1; let y = f(); if (x != 1) decide drop("clobbered"); if (y != 16) decide drop("bad_return"); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "pass", "x survives the call, y is the return value");
});

yeet.test("...with several caller locals, args, and a nested call", () => {
  const p = load(`fn inner(a) { let k = a + 100; let j = k + 1; return j; }
    fn outer(a, b) { let keep = a + b; let r = inner(keep); if (keep != 30) return 0; return r; }
    filter { let p1 = 11; let p2 = 22; let p3 = 33; let got = outer(10, 20);
      if (p1 != 11) decide drop("p1"); if (p2 != 22) decide drop("p2"); if (p3 != 33) decide drop("p3");
      if (got != 131) decide drop("got"); decide pass; }`);
  const r = p.exec(enc("x"), {});
  eq(r.verdict === "pass" ? "pass" : `${r.verdict}(${r.ruleName})`, "pass", "all locals intact, nested result correct");
});

yeet.test("a local that is NOT live across a call may still share a register", () => {
  /* Eight filter locals, none live across the call: the callee's two still fit. */
  const decls = Array.from({ length: 6 }, (_, i) => `let v${i} = ${i};`).join(" ");
  const uses = Array.from({ length: 6 }, (_, i) => `if (v${i} != ${i}) decide drop("v${i}");`).join(" ");
  const c = compile(`fn f() { let s = 7; let t = 9; return s + t; } filter { let y = f(); ${decls} ${uses} if (y != 16) decide drop("y"); decide pass; }`);
  if (!c.ok) throw new Error(JSON.stringify(c.errors));
});

yeet.test("a regex DFA over the kernel's table size is a compile error", () => {
  const c = compile(`regex key = "AKIA[A-Z0-9]{16}"; filter { if (scan(payload, 256) & key) decide drop("k"); decide pass; }`);
  eq(c.ok, false, "must not compile");
  if (!/DFA too large/.test(c.errors[0].text) || !c.errors[0].text.includes(String(LIMITS.RE_STATES))) throw new Error("unhelpful error: " + c.errors[0].text);
  const small = compile(`regex ssn = "\\\\d{3}-\\\\d{2}-\\\\d{4}"; filter { if (scan(payload, 256) & ssn) decide drop("k"); decide pass; }`);
  eq(small.ok, true, "an ordinary regex still compiles");
  if (small.regex.nstates > LIMITS.RE_STATES) throw new Error("accepted DFA exceeds the table");
});

yeet.test("a program over the instruction budget is a compile error, not a throw", () => {
  const body = Array.from({ length: 3000 }, (_, i) => `if (len == ${i}) decide drop("r");`).join("\n");
  let c;
  try { c = compile(`filter { ${body} decide pass; }`); } catch (e) { throw new Error("compile() threw: " + e.message); }
  eq(c.ok, false, "must not compile");
  if (!c.errors[0].text.includes(String(LIMITS.MAX_OPS))) throw new Error("unhelpful error: " + c.errors[0].text);
});
