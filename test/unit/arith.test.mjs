/* Arithmetic and locals — let/assign parked in scratch registers, the operators
 * (+, -, &, |, <<, >>), register+register add, and scratch reuse across dead
 * ranges (more named locals than the eight physical registers). */
import { fromC, V } from "./helpers.mjs";

/* Compute `expr` into x and drop("hit") iff x == want; so a pass means the
 * arithmetic produced something other than `want`. len comes from frame length. */
const isVal = (expr, want, len = 0, opts = {}) =>
  fromC(`filter { let x = ${expr}; if (x == ${want}) decide drop("hit"); decide pass; }`)
    .run(new Uint8Array(len), {}, opts).verdict === V.DROP;
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("each operator against a constant", () => {
  eq(isVal("5 + 3", 8), true, "+");
  eq(isVal("10 - 4", 6), true, "-");
  eq(isVal("12 & 10", 8), true, "& (0b1100 & 0b1010)");
  eq(isVal("12 | 3", 15), true, "| (0b1100 | 0b0011)");
  eq(isVal("3 << 4", 48), true, "<<");
  eq(isVal("255 >> 4", 15), true, ">>");
});

yeet.test("arithmetic on a register operand (len)", () => {
  eq(isVal("len + 1", 6, 5), true, "len(5)+1");
  eq(isVal("len << 1", 10, 5), true, "len(5)<<1");
  eq(isVal("len + 1", 6, 2), false, "len(2)+1 != 6");
});

yeet.test("register + register", () => {
  // len(4) + dport(80) == 84
  eq(fromC(`filter { let x = len + dport; if (x == 84) decide drop("h"); decide pass; }`)
    .run(new Uint8Array(4), {}, { dport: 80 }).verdict, V.DROP, "reg+reg");
});

yeet.test("assign updates an existing local", () => {
  const s = `filter { let x = 1; x = x + 10; x = x << 1; if (x == 22) decide drop("h"); decide pass; }`;
  eq(fromC(s).run(new Uint8Array(0), {}, {}).verdict, V.DROP, "(1+10)<<1 == 22");
});

yeet.test("many locals with non-overlapping live ranges reuse registers", () => {
  // Ten named locals (> 8 registers) but each dies before the next is needed.
  let body = "let acc = 0;";
  for (let i = 1; i <= 10; i++) body += ` let t${i} = ${i}; acc = acc + t${i};`;
  const s = `filter { ${body} if (acc == 55) decide drop("h"); decide pass; }`;
  eq(fromC(s).run(new Uint8Array(0), {}, {}).verdict, V.DROP, "sum 1..10 == 55");
});
