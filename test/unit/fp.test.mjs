/* The functional combinator layer (fp.js) composes the same programs the plain
 * value builder and source do — guards, when/unless, allOf/anyOf/none, match, and
 * reusable fragments built from closures (including generated from a list). */
import * as C from "#/dsl.js";
import { when, unless, guard, allOf, anyOf, none, match, rules, each } from "#/fp.js";
import { compile } from "#/clang.js";

const J = (x) => JSON.stringify(x, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));
const same = (name, prog, src) => {
  const c = compile(src);
  if (!c.ok) throw new Error(`${name}: source failed: ${J(c.errors)}`);
  if (J(prog.program.ops) !== J(c.program.ops)) throw new Error(`${name}: combinators != source\n ${J(prog.program.ops)}\n ${J(c.program.ops)}`);
};
const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: ${g} != ${w}`); };

yeet.test("guard + a reusable closure fragment == source", () => {
  const blockUA = (pat, verdict) => guard(C.band(C.scan(C.payload, 1460), pat), verdict);
  const p = C.program(
    C.nocase(), C.pattern("gptbot", "GPTBot"), C.pattern("claudebot", "ClaudeBot"),
    C.filter(guard(C.ne(C.dport, 80), C.pass()), blockUA("gptbot", C.rst("crawler", 60)), blockUA("claudebot", C.rst("crawler", 60)), C.pass()),
  );
  same("blockUA", p, `nocase; pattern gptbot="GPTBot",claudebot="ClaudeBot";
    filter { if (dport!=80) return pass;
      if (scan(payload,1460)&gptbot) return rst("crawler",60);
      if (scan(payload,1460)&claudebot) return rst("crawler",60);
      return pass; }`);
});

yeet.test("when(...) curried + allOf + match == source", () => {
  const p = C.program(C.pattern("bot", "GPTBot"), C.filter(
    when(allOf(C.eq(C.proto, 6), C.eq(C.dport, 80)))(C.log(16), guard(match(C.scan(C.payload, 256)).has("bot"), C.rst("b", 0))),
    C.pass(),
  ));
  same("when/allOf/match", p, `pattern bot="GPTBot"; filter {
    if (proto==6 && dport==80) { log(16); if (scan(payload,256)&bot) return rst("b",0); }
    return pass; }`);
});

yeet.test("unless / anyOf / none compose the expected conditions", () => {
  const p = C.program(C.filter(
    unless(anyOf(C.eq(C.dport, 80), C.eq(C.dport, 443)))(C.drop("odd")),
    C.iff(none(C.eq(C.proto, 6)), C.pass()),
    C.pass(),
  ));
  same("unless/anyOf/none", p, `filter {
    if (!(dport==80 || dport==443)) { return drop("odd"); }
    if (!(proto==6)) return pass;
    return pass; }`);
});

yeet.test("fragments generated from a list (closure map) behave", () => {
  const BOTS = ["gptbot", "claudebot", "bytespider"];
  const p = C.program(
    C.nocase(), ...BOTS.map((b) => C.pattern(b, b)),
    rules(
      guard(C.ne(C.dport, 80), C.pass()),
      each(BOTS, (b) => guard(C.band(C.scan(C.payload, 1460), b), C.rst("crawler", 60))),
      C.pass(),
    ),
  );
  eq(p.exec(enc("hi claudebot"), { dport: 80 }).verdict, "rst", "a listed bot matches");
  eq(p.exec(enc("hi chrome"), { dport: 80 }).verdict, "pass", "non-bot passes");
  eq(p.exec(enc("hi gptbot"), { dport: 443 }).verdict, "pass", "wrong port passes");
});
