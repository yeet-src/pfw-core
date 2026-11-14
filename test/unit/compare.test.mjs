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
