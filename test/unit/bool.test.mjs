/* Boolean logic — &&, ||, !, if/else, nesting, and short-circuit evaluation
 * (lowered to forward jumps: && skips to the else on the first false, || skips
 * to the body on the first true). */
import { fromC, V } from "./helpers.mjs";

const v = (src, opts = {}, len = 0) => fromC(src).run(new Uint8Array(len), {}, opts).verdict;
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("&& requires both operands", () => {
  const s = `filter { if (dport == 80 && proto == 6) decide drop("a"); decide pass; }`;
  eq(v(s, { dport: 80, proto: 6 }), V.DROP, "both");
  eq(v(s, { dport: 80, proto: 17 }), V.PASS, "one false");
  eq(v(s, { dport: 81, proto: 6 }), V.PASS, "other false");
});

yeet.test("|| needs either operand", () => {
  const s = `filter { if (dport == 80 || dport == 443) decide drop("o"); decide pass; }`;
  eq(v(s, { dport: 80 }), V.DROP, "first");
  eq(v(s, { dport: 443 }), V.DROP, "second");
  eq(v(s, { dport: 22 }), V.PASS, "neither");
});

yeet.test("! negates", () => {
  const s = `filter { if (!(dport == 80)) decide drop("n"); decide pass; }`;
  eq(v(s, { dport: 22 }), V.DROP, "not true");
  eq(v(s, { dport: 80 }), V.PASS, "not false");
});

yeet.test("if / else picks a branch", () => {
  const s = `filter { if (dport == 80) decide rst("y", 0); else decide drop("z"); }`;
  eq(v(s, { dport: 80 }), V.RST, "then");
  eq(v(s, { dport: 81 }), V.DROP, "else");
});

yeet.test("nested conditions and mixed precedence", () => {
  // (a || b) && c
  const s = `filter { if ((dport == 80 || dport == 443) && proto == 6) decide drop("m"); decide pass; }`;
  eq(v(s, { dport: 443, proto: 6 }), V.DROP, "b and c");
  eq(v(s, { dport: 443, proto: 17 }), V.PASS, "c false");
  eq(v(s, { dport: 22, proto: 6 }), V.PASS, "a,b false");
});

yeet.test("short-circuit: the second operand is not required to decide", () => {
  // If && didn't short-circuit the first false, this still must be PASS; the
  // point is the verdict is correct regardless of the right operand's value.
  const s = `filter { if (proto == 6 && dport == 80) decide drop("x"); decide pass; }`;
  eq(v(s, { proto: 17, dport: 80 }), V.PASS, "first false -> skip");
});
