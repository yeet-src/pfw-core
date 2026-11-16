/* The questions a program asks of one scan — any / all / seq over a `mask`
 * local — and byte-list patterns. seq is the one that reads positions (mpos):
 * it holds only when every pattern matched AND each first ended strictly after
 * the one before it. */
import { compile } from "#/clang";
import { toProgram } from "#/program";

const bytes = (s) => Uint8Array.from(s, (ch) => ch.charCodeAt(0) & 0xff);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };
const verdict = (p, payload) => p.exec(bytes(payload), {}).verdict;

const SQL = `pattern kw_union = "UNION"; pattern kw_select = "SELECT"; pattern kw_from = "FROM";`;

yeet.test("seq holds when the patterns appear in the order given", () => {
  const p = prog(`${SQL} filter { mask m = scan(payload, 256); if (seq(m, kw_union, kw_select)) decide drop("sqli"); decide pass; }`);
  eq(verdict(p, "1 UNION SELECT x"), "drop", "in order");
  eq(verdict(p, "1 UNION ALL  SELECT x"), "drop", "in order, with a gap");
});

yeet.test("seq fails when the order is reversed", () => {
  const p = prog(`${SQL} filter { mask m = scan(payload, 256); if (seq(m, kw_union, kw_select)) decide drop("sqli"); decide pass; }`);
  eq(verdict(p, "SELECT x UNION y"), "pass", "reversed");
});

yeet.test("seq fails when any pattern is missing", () => {
  const p = prog(`${SQL} filter { mask m = scan(payload, 256); if (seq(m, kw_union, kw_select)) decide drop("sqli"); decide pass; }`);
  eq(verdict(p, "1 UNION x"), "pass", "second missing");
  eq(verdict(p, "1 SELECT x"), "pass", "first missing");
  eq(verdict(p, "nothing here"), "pass", "both missing");
});

yeet.test("seq over three patterns needs every adjacent pair in order", () => {
  const p = prog(`${SQL} filter { mask m = scan(payload, 256); if (seq(m, kw_union, kw_select, kw_from)) decide drop("sqli"); decide pass; }`);
  eq(verdict(p, "UNION SELECT a FROM t"), "drop", "a < b < c");
  eq(verdict(p, "UNION FROM t SELECT a"), "pass", "b and c swapped");
  eq(verdict(p, "SELECT a UNION FROM t"), "pass", "a and b swapped");
  eq(verdict(p, "UNION SELECT a"), "pass", "c missing");
});

yeet.test("seq compares where each pattern FIRST matched", () => {
  const p = prog(`${SQL} filter { mask m = scan(payload, 256); if (seq(m, kw_union, kw_select)) decide drop("sqli"); decide pass; }`);
  // SELECT first ends before UNION does; the later SELECT does not rescue it.
  eq(verdict(p, "SELECT UNION SELECT"), "pass", "first positions decide");
});

yeet.test("seq takes a scan directly, and negates", () => {
  const direct = prog(`${SQL} filter { if (seq(scan(payload, 256), kw_union, kw_select)) decide drop("sqli"); decide pass; }`);
  eq(verdict(direct, "UNION SELECT"), "drop", "seq(scan(...), …)");
  const neg = prog(`${SQL} filter { mask m = scan(payload, 256); if (!seq(m, kw_union, kw_select)) decide pass; decide drop("sqli"); }`);
  eq(verdict(neg, "UNION SELECT"), "drop", "!seq, in order");
  eq(verdict(neg, "SELECT UNION"), "pass", "!seq, reversed");
});

yeet.test("seq needs at least two patterns", () => {
  const c = compile(`${SQL} filter { mask m = scan(payload, 256); if (seq(m, kw_union)) decide drop("x"); decide pass; }`);
  if (c.ok) throw new Error("seq with one pattern should not compile");
});

yeet.test("all needs every pattern, in any order; any needs one", () => {
  const p = prog(`${SQL} filter { mask m = scan(payload, 256); if (all(m, kw_union, kw_select)) decide drop("both"); if (any(m, kw_union, kw_select)) decide rst("one", 0); decide pass; }`);
  eq(verdict(p, "SELECT then UNION"), "drop", "all, reversed order");
  eq(verdict(p, "only UNION"), "rst", "any");
  eq(verdict(p, "neither"), "pass", "none");
});

yeet.test("one mask answers several questions", () => {
  const p = prog(`${SQL} pattern comment = "--"; filter { mask m = scan(payload, 256); if (seq(m, kw_union, kw_select) && any(m, comment)) decide drop("sqli"); decide pass; }`);
  eq(verdict(p, "UNION SELECT 1 --"), "drop", "seq && any");
  eq(verdict(p, "UNION SELECT 1"), "pass", "seq without the comment");
});

yeet.test("a byte-list pattern matches raw bytes, including NUL and 0xff", () => {
  const p = prog(`pattern java = { 0xac, 0xed, 0x00, 0x05 }; pattern hi = { 0xff, 0xff }; filter { mask m = scan(payload, 64); if (any(m, java)) decide drop("java_ser"); if (any(m, hi)) decide rst("ff", 0); decide pass; }`);
  eq(verdict(p, "xx\xac\xed\x00\x05yy"), "drop", "the magic");
  eq(verdict(p, "xx\xac\xed\x00\x06yy"), "pass", "last byte differs");
  eq(verdict(p, "a\xff\xffb"), "rst", "0xff bytes");
});

yeet.test("a byte-list pattern works with starts() and after()", () => {
  const p = prog(`pattern magic = { 0x16, 0x03 }; filter { if (!starts(payload, magic)) decide pass; mask m = scan(payload, 16); let at = after(magic); if (at == 2) decide drop("tls"); decide pass; }`);
  eq(verdict(p, "\x16\x03\x01"), "drop", "anchored + position");
  eq(verdict(p, "x\x16\x03"), "pass", "not at the start");
});
