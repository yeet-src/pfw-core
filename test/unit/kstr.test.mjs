/* kstr("name") — a live, host-set STRING knob. A runtime string the host writes
 * into the `knob_strs` map; `kstr("name")` is a condition true when that string
 * occurs in the payload (a bounded substring search). Unlike compile-time
 * patterns (baked into the Aho-Corasick automaton), a string knob is set and
 * changed live — e.g. push the current bad host/token and block it without a
 * reload. The compiler assigns each name a slot (program.knobStrs[slot] === name);
 * exec takes the current strings as { name: "needle" }. */
import { compile } from "#/clang";
import { toProgram } from "#/program";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };

yeet.test("a string knob matches when its value appears in the payload", () => {
  const p = prog(`filter { if (kstr("bad")) decide drop("blocked"); decide pass; }`);
  eq(p.exec(enc("GET /login?u=evil"), { knobStrs: { bad: "evil" } }).verdict, "drop", "contains 'evil'");
  eq(p.exec(enc("GET /login?u=safe"), { knobStrs: { bad: "evil" } }).verdict, "pass", "does not contain");
  eq(p.exec(enc("GET /login?u=evil"), {}).verdict, "pass", "unset string knob -> no match");
});

yeet.test("the string knob is live — change it, the match changes", () => {
  const p = prog(`filter { if (kstr("host")) decide rst("blocked_host", 0); decide pass; }`);
  const body = enc("Host: shop.example.com");
  eq(p.exec(body, { knobStrs: { host: "shop.example.com" } }).verdict, "rst", "blocks current host");
  eq(p.exec(body, { knobStrs: { host: "other.example.com" } }).verdict, "pass", "a different host set -> no match");
});

yeet.test("the compiler exposes the string-knob name -> slot binding", () => {
  const c = compile(`filter { if (kstr("a")) decide drop("x"); if (kstr("b")) decide drop("y"); decide pass; }`);
  eq(c.ok, true, "compiles");
  eq(c.knobStrs[0], "a", "slot 0");
  eq(c.knobStrs[1], "b", "slot 1");
});

yeet.test("a string knob composes with other conditions", () => {
  const p = prog(`filter { if (dport == 80 && kstr("tok")) decide ban("leak", 60); decide pass; }`);
  eq(p.exec(enc("x tok123 y"), { dport: 80, knobStrs: { tok: "tok123" } }).verdict, "ban", "port + token");
  eq(p.exec(enc("x tok123 y"), { dport: 443, knobStrs: { tok: "tok123" } }).verdict, "pass", "wrong port");
});
