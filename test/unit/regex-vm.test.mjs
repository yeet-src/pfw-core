/* Regex patterns through the VM: a `regex` pattern compiles into the DFA, `scan`
 * runs it alongside the Aho-Corasick automaton (both set %m bits), and the usual
 * band/any/seq tests work on regex bits the same as literal ones. Reference
 * interpreter, so this is the host behaviour the kernel mirrors. */
import * as C from "#/dsl.js";
import { load } from "#/index.js";
import { compile } from "#/clang.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("pfw-C: a regex pattern matched by scan", () => {
  const p = load(`regex ssn = "\\d{3}-\\d{2}-\\d{4}";
    filter { if (scan(payload, 256) & ssn) decide drop("ssn"); decide pass; }`);
  eq(p.exec(enc("my ssn 123-45-6789 ok")).verdict, "drop", "ssn present");
  eq(p.exec(enc("id 12-345-6789")).verdict, "pass", "wrong shape");
  eq(p.exec(enc("nothing here")).verdict, "pass", "absent");
});

yeet.test("literal and regex patterns mix in one scan / any()", () => {
  const p = C.program(
    C.pattern("bot", "GPTBot"),
    C.regex("email", "[a-z0-9._]+@[a-z0-9.]+\\.[a-z]+"),
    C.regex("card", "\\d{13,16}"),
    C.filter(C.iff(C.any(C.scan(C.payload, 1460), "bot", "email", "card"), C.drop("hit")), C.pass()));
  eq(p.exec(enc("x GPTBot")).verdict, "drop", "literal bot");
  eq(p.exec(enc("mail a.b@host.com")).verdict, "drop", "regex email");
  eq(p.exec(enc("pan 4111111111111111")).verdict, "drop", "regex card");
  eq(p.exec(enc("just text")).verdict, "pass", "none");
});

yeet.test("regex bit is independent (band on a specific regex)", () => {
  const p = C.program(
    C.regex("ssn", "\\d{3}-\\d{2}-\\d{4}"),
    C.regex("email", "[a-z]+@[a-z]+\\.[a-z]+"),
    C.filter(
      C.iff(C.band(C.scan(C.payload, 256), "ssn"), C.rst("ssn", 0)),
      C.iff(C.band(C.scan(C.payload, 256), "email"), C.drop("email")),
      C.pass()));
  eq(p.exec(enc("123-45-6789")).verdict, "rst", "ssn -> rst");
  eq(p.exec(enc("a@b.co")).verdict, "drop", "email -> drop");
  eq(p.exec(enc("neither")).verdict, "pass", "neither");
});

yeet.test("a bad regex is a compile error", () => {
  const r = compile(`regex x = "a[b"; filter { if (scan(payload,8) & x) decide drop("y"); decide pass; }`);
  if (r.ok) throw new Error("expected a regex compile error");
});
