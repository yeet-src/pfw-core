/* Pattern matching — one Aho-Corasick scan into the match mask, interrogated by
 * band (one pattern), the or-mask `(a|b|c)`, any/all/seq, and a reusable `mask`
 * variable. Also anchored compare via starts (pattern ref and inline literal). */
import { fromC, V } from "./helpers.mjs";

const v = (src, payload = "") => {
  const b = new TextEncoder().encode(payload);
  return fromC(src).run(b, {}, { dport: 80 }).verdict;
};
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("band: a single pattern in the window", () => {
  const s = `pattern bot = "GPTBot"; filter { if (scan(payload, 256) & bot) return rst("b", 0); return pass; }`;
  eq(v(s, "x GPTBot y"), V.RST, "present");
  eq(v(s, "x Chrome y"), V.PASS, "absent");
});

yeet.test("or-mask (a | b | c): any of several", () => {
  const s = `pattern a="foo", b="bar", c="baz"; filter { if (scan(payload,256) & (a|b|c)) return drop("m"); return pass; }`;
  eq(v(s, "has bar"), V.DROP, "middle");
  eq(v(s, "has qux"), V.PASS, "none");
});

yeet.test("any / all over a scan", () => {
  const anyP = `pattern a="foo", b="bar"; filter { if (any(scan(payload,256), a, b)) return drop("x"); return pass; }`;
  eq(v(anyP, "has bar"), V.DROP, "any one"); eq(v(anyP, "has baz"), V.PASS, "any none");
  const allP = `pattern a="foo", b="bar"; filter { if (all(scan(payload,256), a, b)) return drop("x"); return pass; }`;
  eq(v(allP, "foo and bar"), V.DROP, "all both"); eq(v(allP, "foo only"), V.PASS, "all one");
});

yeet.test("seq: patterns in left-to-right order", () => {
  const s = `pattern a="AAA", b="BBB"; filter { if (seq(scan(payload,256), a, b)) return drop("x"); return pass; }`;
  eq(v(s, "AAA then BBB"), V.DROP, "in order");
  eq(v(s, "BBB then AAA"), V.PASS, "out of order");
  eq(v(s, "AAA only"), V.PASS, "second missing");
});

yeet.test("a mask variable: one scan, interrogated several ways", () => {
  const s = `pattern a="foo", b="bar", c="baz";
    filter { mask m = scan(payload, 256);
      if (seq(m, a, b) && any(m, c)) return rst("all3", 0);
      if (any(m, a, b)) return drop("some");
      return pass; }`;
  eq(v(s, "foo bar baz"), V.RST, "seq foo<bar and baz present");
  eq(v(s, "foo bar"), V.DROP, "some (no baz)");
  eq(v(s, "bar foo"), V.DROP, "any but not in seq order");
  eq(v(s, "nothing"), V.PASS, "none");
});

yeet.test("starts: anchored compare (pattern ref and inline literal)", () => {
  const ref = `pattern g="GET"; filter { if (starts(payload, g)) return drop("m"); return pass; }`;
  eq(v(ref, "GET /"), V.DROP, "ref hit"); eq(v(ref, "POST /"), V.PASS, "ref miss");
  const lit = `filter { if (starts(payload, "PUT")) return drop("m"); return pass; }`;
  eq(v(lit, "PUT /x"), V.DROP, "literal hit"); eq(v(lit, "GET /x"), V.PASS, "literal miss");
});

yeet.test("scan window bound: a match past the limit is not seen", () => {
  const s = `pattern bot="BOT"; filter { if (scan(payload, 4) & bot) return drop("m"); return pass; }`;
  eq(v(s, "BOT here"), V.DROP, "within 4");
  eq(v(s, "....BOT"), V.PASS, "beyond 4");
});
