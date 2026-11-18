/* Comparisons — the six relational operators against an immediate, a register,
 * and a scratch local, plus unsigned boundaries (cmp is CF/ZF-based, so there
 * are no negatives). Each program drops("hit") when the comparison holds. */
import { fromC, V } from "./helpers.mjs";

const hit = (expr, opts = {}, len = 0) =>
  fromC(`filter { if (${expr}) decide drop("hit"); decide pass; }`)
    .run(new Uint8Array(len), {}, opts).verdict === V.DROP;
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("the six operators vs an immediate (dport)", () => {
  const at = (p) => ({ dport: p });
  eq(hit("dport == 80", at(80)), true, "=="); eq(hit("dport == 80", at(81)), false, "== f");
  eq(hit("dport != 80", at(81)), true, "!="); eq(hit("dport != 80", at(80)), false, "!= f");
  eq(hit("dport <  80", at(79)), true, "<");  eq(hit("dport <  80", at(80)), false, "< f");
  eq(hit("dport >  80", at(81)), true, ">");  eq(hit("dport >  80", at(80)), false, "> f");
  eq(hit("dport <= 80", at(80)), true, "<=(eq)"); eq(hit("dport <= 80", at(81)), false, "<= f");
  eq(hit("dport >= 80", at(80)), true, ">=(eq)"); eq(hit("dport >= 80", at(79)), false, ">= f");
});

yeet.test("comparison on a derived register (len = frame length)", () => {
  eq(hit("len == 5", {}, 5), true, "len eq");
  eq(hit("len == 5", {}, 4), false, "len neq");
  eq(hit("len >= 8", {}, 8), true, "len ge");
  eq(hit("len < 1", {}, 0), true, "empty payload len 0");
});

yeet.test("register vs register, and vs a scratch local", () => {
  // len (5) vs dport (5): reg-to-reg compare
  eq(hit("len == dport", { dport: 5 }, 5), true, "reg==reg true");
  eq(hit("len == dport", { dport: 6 }, 5), false, "reg==reg false");
  // a let-local on the right-hand side
  eq(fromC(`filter { let x = 80; if (dport == x) decide drop("h"); decide pass; }`)
    .run(new Uint8Array(0), {}, { dport: 80 }).verdict, V.DROP, "var rhs eq");
});

yeet.test("unsigned boundaries (no negatives)", () => {
  eq(hit("dport > 0", { dport: 0 }), false, "0 not > 0");
  eq(hit("dport >= 0", { dport: 0 }), true, "0 >= 0");
  eq(hit("dport < 65535", { dport: 65534 }), true, "below max");
  eq(hit("dport == 65535", { dport: 65535 }), true, "at max");
});

/* ---- arithmetic on either side of a comparison ---- */
{
  const { load } = await import("#/index.js");
  const { compile } = await import("#/clang");
  const hit = (cond, opts = {}, len = 4) => load(`pattern a = "x"; filter { if (${cond}) decide drop("y"); decide pass; }`).exec(new Uint8Array(len), { dport: 80, sport: 40000, ...opts }).verdict === "drop";
  const yes = (cond, opts, len) => { if (!hit(cond, opts, len)) throw new Error(`${cond} should hold`); };
  const no = (cond, opts, len) => { if (hit(cond, opts, len)) throw new Error(`${cond} should not hold`); };

  yeet.test("arithmetic on the left of a comparison", () => {
    yes("len + 1 == 5"); no("len + 1 == 6");
    yes("sport % 16 == 0"); no("sport % 16 == 1");
    yes("dport * 2 > 150"); yes("dport - 80 == 0"); yes("dport << 1 == 160"); yes("dport >> 4 == 5");
  });
  yeet.test("arithmetic on the right, and on both sides", () => {
    yes("dport == 40 * 2"); yes("160 == dport * 2"); yes("dport < len * 100");
    yes("len + dport == sport - 39916"); no("len + dport == sport - 1");
  });
  yeet.test("a masked value compares: & is the bitwise and when its left is not a scan", () => {
    yes("dport & 0xf0 == 0x50"); no("dport & 0x0f == 5");
    yes("(dport & 0x10) != 0"); yes("u8(payload) & 1 == 0");
    yes("dport == 0x40 | 0x10");
  });
  yeet.test("it composes with && || ! and parentheses", () => {
    yes("len + 1 == 5 && dport % 2 == 0"); no("len + 1 == 5 && dport % 2 == 1");
    yes("len + 1 == 9 || sport % 16 == 0"); yes("!(len * 2 == 9)"); yes("(len + 1 == 5) && (dport == 80)");
  });
  yeet.test("the mask test and pattern-or still mean what they meant", () => {
    const p = load(`pattern a = "abc", b = "xyz"; filter { if (scan(payload, 16) & (a | b)) decide drop("y"); mask m = scan(payload, 16); if (m & a) decide drop("z"); decide pass; }`);
    if (p.exec(Uint8Array.from("..xyz..", (c) => c.charCodeAt(0)), {}).verdict !== "drop") throw new Error("scan & (a | b)");
    if (p.exec(Uint8Array.from("......", (c) => c.charCodeAt(0)), {}).verdict !== "pass") throw new Error("no match");
  });
  yeet.test("a bare sum is not a condition", () => {
    const r = compile(`filter { if (len + 1) decide drop("y"); decide pass; }`);
    if (r.ok || !/has to be compared/.test(r.errors[0].text)) throw new Error(JSON.stringify(r.errors));
  });
}
