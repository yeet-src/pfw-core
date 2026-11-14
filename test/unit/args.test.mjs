/* Subroutine calling convention: `fn name(p0, p1)` binds params to the arg
 * registers %a0..%a3; the caller loads args before the call; the return value
 * comes back in %a0 (so `let r = name(x)` works). Up to 4 args. Routines are
 * caller-saved over a0..a3 — a nested call reuses them. */
import { compile } from "#/clang";
import { toProgram } from "#/program";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };

yeet.test("args in via %a0..; return value out via %rv", () => {
  const p = prog(`fn add(a, b) { rv = a + b; } filter { let r = add(3, 4); if (r == 7) decide rst("sum", 0); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "rst", "3+4 == 7");
});

yeet.test("a param is read like a register", () => {
  const p = prog(`fn is_port(p) { rv = 0; if (p == 443) rv = 1; } filter { if (is_port(dport)) decide drop("https"); decide pass; }`);
  eq(p.exec(enc("x"), { dport: 443 }).verdict, "drop", "matches");
  eq(p.exec(enc("x"), { dport: 80 }).verdict, "pass", "doesn't match");
});

yeet.test("nested calls: an arg may itself be a call", () => {
  const p = prog(`fn dbl(x) { rv = x + x; } filter { let r = dbl(dbl(5)); if (r == 20) decide rst("nested", 0); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "rst", "dbl(dbl(5)) == 20");
});

yeet.test("a call is usable directly in a condition", () => {
  const p = prog(`fn max(a, b) { rv = a; if (b > a) rv = b; } filter { if (max(dport, sport) == 8080) decide drop("hi"); decide pass; }`);
  eq(p.exec(enc("x"), { dport: 8080, sport: 1 }).verdict, "drop", "max is 8080");
  eq(p.exec(enc("x"), { dport: 1, sport: 2 }).verdict, "pass", "max is 2");
});

yeet.test("up to 7 args (a0..a6)", () => {
  const p = prog(`fn sum7(a, b, c, d, e, f, g) { rv = a + b + c + d + e + f + g; } filter { let r = sum7(1, 2, 3, 4, 5, 6, 7); if (r == 28) decide rst("sum7", 0); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "rst", "1..7 sums to 28");
  const bad = compile(`fn f(a, b, c, d, e, g, h, i) { rv = a; } filter { decide pass; }`);
  if (bad.ok) throw new Error("expected an 8-param error");
});

yeet.test("return <expr> returns a value from a subroutine", () => {
  const p = prog(`fn add(a, b) { return a + b; } filter { let r = add(10, 5); if (r == 15) decide rst("r", 0); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "rst", "return a + b");
  // early/conditional return
  const p2 = prog(`fn clamp(x) { if (x > 100) return 100; return x; } filter { if (clamp(dport) == 100) decide drop("hi"); decide pass; }`);
  eq(p2.exec(enc("x"), { dport: 500 }).verdict, "drop", "clamped to 100");
  eq(p2.exec(enc("x"), { dport: 50 }).verdict, "pass", "under the clamp");
});

yeet.test("return still means the verdict in the filter and in routines", () => {
  const p = prog(`fn bail() { decide drop("sub_verdict"); } filter { bail(); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "drop", "a verdict in a routine is terminal");
});

yeet.test("arity is checked", () => {
  const r = compile(`fn add(a, b) { rv = a + b; } filter { let r = add(1); decide pass; }`);
  if (r.ok) throw new Error("expected an arity error");
  if (!JSON.stringify(r.errors).includes("takes 2 arg")) throw new Error("wrong error: " + JSON.stringify(r.errors));
});
