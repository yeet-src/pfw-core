/* Every pfw-C construct, authored with the JS program builder (dsl.js) and run
 * through the VM, asserting the verdict. This is the broad behavioral sweep —
 * comparisons, boolean logic, pattern matching, arithmetic, locals, pointers,
 * per-flow state, the ring, cidr, repeat, skip, frame. Decode front-ends are
 * kernel stages (not modelled by the host interpreter) so they are checked at
 * the compile level, in dsl.test.mjs. */
import * as C from "#/dsl.js";

const enc = (s) => new TextEncoder().encode(s);
/* Run `prog` over `frame` with opts, return the verdict name. */
const v = (prog, frame = "", opts = {}) => prog.exec(enc(frame), opts).verdict;
const eq = (got, want, msg) => { if (got !== want) throw new Error(`${msg}: got ${got}, want ${want}`); };

/* ---- comparisons ---- */
yeet.test("all six comparisons on dport", () => {
  const mk = (cmp) => C.program(C.filter(C.iff(cmp(C.dport, 80), C.drop("hit")), C.pass()));
  eq(v(mk(C.eq), "", { dport: 80 }), "drop", "eq true"); eq(v(mk(C.eq), "", { dport: 81 }), "pass", "eq false");
  eq(v(mk(C.ne), "", { dport: 81 }), "drop", "ne true"); eq(v(mk(C.ne), "", { dport: 80 }), "pass", "ne false");
  eq(v(mk(C.lt), "", { dport: 79 }), "drop", "lt true"); eq(v(mk(C.lt), "", { dport: 80 }), "pass", "lt false");
  eq(v(mk(C.gt), "", { dport: 81 }), "drop", "gt true"); eq(v(mk(C.gt), "", { dport: 80 }), "pass", "gt false");
  eq(v(mk(C.le), "", { dport: 80 }), "drop", "le eq"); eq(v(mk(C.le), "", { dport: 81 }), "pass", "le false");
  eq(v(mk(C.ge), "", { dport: 80 }), "drop", "ge eq"); eq(v(mk(C.ge), "", { dport: 79 }), "pass", "ge false");
});

/* ---- boolean logic: &&, ||, ! and else ---- */
yeet.test("and / or / not / if-else", () => {
  const andP = C.program(C.filter(C.iff(C.and(C.eq(C.dport, 80), C.eq(C.proto, 6)), C.drop("a")), C.pass()));
  eq(v(andP, "", { dport: 80, proto: 6 }), "drop", "and both"); eq(v(andP, "", { dport: 80, proto: 17 }), "pass", "and one");
  const orP = C.program(C.filter(C.iff(C.or(C.eq(C.dport, 80), C.eq(C.dport, 443)), C.drop("o")), C.pass()));
  eq(v(orP, "", { dport: 443 }), "drop", "or second"); eq(v(orP, "", { dport: 22 }), "pass", "or neither");
  const notP = C.program(C.filter(C.iff(C.not(C.eq(C.dport, 80)), C.drop("n")), C.pass()));
  eq(v(notP, "", { dport: 22 }), "drop", "not true"); eq(v(notP, "", { dport: 80 }), "pass", "not false");
  const elseP = C.program(C.filter(C.iff(C.eq(C.dport, 80), C.rst("y", 0), C.drop("z"))));
  eq(v(elseP, "", { dport: 80 }), "rst", "else then"); eq(v(elseP, "", { dport: 81 }), "drop", "else else");
});

/* ---- pattern matching: band, any, all, seq, starts ---- */
yeet.test("scan + band / any / all / seq / starts", () => {
  const band = C.program(C.pattern("bot", "GPTBot"), C.filter(C.iff(C.band(C.scan(C.payload, 256), "bot"), C.rst("b", 0)), C.pass()));
  eq(v(band, "x GPTBot y"), "rst", "band hit"); eq(v(band, "x Chrome y"), "pass", "band miss");
  const anyP = C.program(C.pattern("a", "foo"), C.pattern("b", "bar"), C.filter(C.iff(C.any(C.scan(C.payload, 256), "a", "b"), C.drop("x")), C.pass()));
  eq(v(anyP, "has bar"), "drop", "any second"); eq(v(anyP, "has baz"), "pass", "any none");
  const allP = C.program(C.pattern("a", "foo"), C.pattern("b", "bar"), C.filter(C.iff(C.all(C.scan(C.payload, 256), "a", "b"), C.drop("x")), C.pass()));
  eq(v(allP, "foo and bar"), "drop", "all both"); eq(v(allP, "foo only"), "pass", "all one");
  const seqP = C.program(C.pattern("a", "AAA"), C.pattern("b", "BBB"), C.filter(C.iff(C.seq(C.scan(C.payload, 256), "a", "b"), C.drop("x")), C.pass()));
  eq(v(seqP, "AAA then BBB"), "drop", "seq in order"); eq(v(seqP, "BBB then AAA"), "pass", "seq out of order");
  const starts = C.program(C.pattern("g", "GET"), C.filter(C.iff(C.starts(C.payload, "g"), C.drop("m")), C.pass()));
  eq(v(starts, "GET /"), "drop", "starts hit"); eq(v(starts, "POST /"), "pass", "starts miss");
});

/* ---- a mask variable reused across any/all ---- */
yeet.test("mask decl reused", () => {
  const p = C.program(C.pattern("a", "foo"), C.pattern("b", "bar"),
    C.filter(C.mask("m", C.scan(C.payload, 256)), C.iff(C.any("m", "a", "b"), C.drop("x")), C.pass()));
  eq(v(p, "bar"), "drop", "mask any"); eq(v(p, "baz"), "pass", "mask none");
});

/* ---- arithmetic in let / assign ---- */
yeet.test("let arithmetic and assign", () => {
  // let x = len + 1; if (x == 6) drop
  const p = C.program(C.filter(C.let_("x", C.add(C.len, 1)), C.iff(C.eq("x", 6), C.drop("hit")), C.pass()));
  eq(v(p, "hello"), "drop", "len 5 + 1 == 6"); // payload "hello" => len 5
  eq(v(p, "hi"), "pass", "len 2 + 1 != 6");
  const sh = C.program(C.filter(C.let_("x", C.shl(3, 4)), C.iff(C.eq("x", 48), C.drop("hit")), C.pass()));
  eq(v(sh, ""), "drop", "3 << 4 == 48");
});

/* ---- per-flow state: flow.state (setState) and flow.count (bump) ---- */
yeet.test("flow.state and flow.count", () => {
  const st = C.program(C.filter(C.iff(C.eq(C.flowState, 7), C.drop("s")), C.pass()));
  eq(v(st, "", { flow: { userState: 7 } }), "drop", "state matches"); eq(v(st, "", { flow: { userState: 1 } }), "pass", "state differs");
  const cnt = C.program(C.filter(C.iff(C.ge(C.flowCount, 3), C.rst("rate", 0)), C.pass()));
  eq(cnt.exec(enc(""), { flow: { hits: 2 } }).verdict, "rst", "3rd hit resets"); // bump 2 -> 3
  eq(cnt.exec(enc(""), { flow: { hits: 0 } }).verdict, "pass", "1st hit passes");
});

/* ---- per-flow state: writing flow.state (setState), incl. the `for TTL` form ---- */
yeet.test("flow.state write persists across packets (and the ttl form)", () => {
  // A greet gate: first packet must start "HELLO" -> set state 1; then it passes.
  const mk = (ttl) => C.program(C.pattern("hi", "HELLO"), C.filter(
    C.iff(C.eq(C.flowState, 1), C.pass()),
    C.iff(C.starts(C.payload, "hi"), C.block(ttl == null ? C.setState(1) : C.setState(1, ttl), C.pass())),
    C.drop("no_greeting")));
  for (const ttl of [null, 300]) {
    const p = mk(ttl);
    const g = p.exec(enc("HELLO x"), {});
    eq(g.verdict, "pass", `greet passes (ttl=${ttl})`);
    eq(g.flow.userState, 1, `greet set state 1 (ttl=${ttl})`);
    eq(p.exec(enc("data"), { flow: g.flow }).verdict, "pass", `greeted flow passes (ttl=${ttl})`);
    eq(p.exec(enc("data"), {}).verdict, "drop", `ungreeted drops (ttl=${ttl})`);
  }
});

/* ---- ring: push / len / get ---- */
yeet.test("ring push/len/get", () => {
  const p = C.program(C.filter(
    C.ringPush(C.num(42)),
    C.iff(C.eq(C.ringLen, 1), C.iff(C.eq(C.ringGet(0), 42), C.drop("ok"))),
    C.pass()));
  eq(v(p, ""), "drop", "pushed 42, len 1, get(0)=42");
});

/* ---- cidr membership ---- */
yeet.test("cidr in / not in", () => {
  const p = C.program(C.filter(C.iff(C.inCidr(C.src, "10.0.0.0/8"), C.drop("rfc1918")), C.pass()));
  eq(v(p, "", { src: "10.1.2.3" }), "drop", "in 10/8"); eq(v(p, "", { src: "8.8.8.8" }), "pass", "not in 10/8");
});

/* ---- repeat unrolls ---- */
yeet.test("repeat unrolls (bump 5x)", () => {
  const p = C.program(C.filter(C.repeat(5, C.ringPush(C.num(1))), C.iff(C.eq(C.ringLen, 5), C.drop("ok")), C.pass()));
  eq(v(p, ""), "drop", "repeat(5) pushed 5");
});

/* ---- pointer + find + skip + starts ---- */
yeet.test("ptr, find, skip", () => {
  // p = find(payload, ' ', 32); skip leading spaces; starts(p, "ok")?  — exercises ptr/find/skip
  const p = C.program(C.pattern("ok", "ok"), C.filter(
    C.ptr("p", C.find(C.payload, " ", 32)),
    C.skip("p", " "),
    C.iff(C.starts("p", "ok"), C.drop("found")),
    C.pass()));
  eq(v(p, "GET   ok"), "drop", "after space(s) comes ok");
  eq(v(p, "GET   no"), "pass", "after space(s) comes no");
});
