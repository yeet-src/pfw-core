/* `nocase` + `regex`. Under nocase the matcher folds every input byte to lower
 * case before stepping the regex DFA (interp.js here, fold() in the kernel's
 * scan.h / rewrite.h), so the DFA has to be built case-insensitive as well. It
 * was not: a regex with an upper-case literal or class (`AKIA[A-Z0-9]{4}`)
 * could never match under nocase, and redact/replace on it silently did nothing.
 * compileRegexes(regexes, nocase) now closes literals and classes over ASCII case. */
import { compile } from "#/clang";
import { toProgram } from "#/program";
import { compileRegexes, runDFA } from "#/regex.js";

const enc = (s) => new TextEncoder().encode(s);
const dec = (u) => String.fromCharCode(...u);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };
const hit = (dfa, s) => (runDFA(dfa, enc(s)) & 1n) === 1n;

const KEY = String.raw`regex key = "AKIA[A-Z0-9]{4}";`;

yeet.test("nocase scan matches a regex written in upper case, in any input case", () => {
  const p = prog(`nocase; ${KEY} filter { if (any(scan(payload, 256), key)) decide drop("key"); decide pass; }`);
  for (const s of ["id=AKIAIOSF", "id=akiaiosf", "id=AkIaIoSf"]) eq(p.exec(enc(s)).verdict, "drop", s);
  eq(p.exec(enc("id=AKIAIOS")).verdict, "pass", "one byte short");
  eq(p.exec(enc("id=AKIBIOSFODNN7EXAMPLE")).verdict, "pass", "wrong prefix");
});

yeet.test("without nocase the same regex stays case-sensitive", () => {
  const p = prog(`${KEY} filter { if (any(scan(payload, 256), key)) decide drop("key"); decide pass; }`);
  eq(p.exec(enc("id=AKIAIOSF")).verdict, "drop", "exact case");
  eq(p.exec(enc("id=akiaiosf")).verdict, "pass", "lower case does not match");
});

yeet.test("nocase replace / redact rewrite an upper-case regex match", () => {
  const rep = prog(`nocase; ${KEY} filter { replace(key, "AKIAXXXX"); decide pass; }`);
  let buf = enc("aws_access_key_id=AKIAIOSF;");
  rep.exec(buf, {});
  eq(dec(buf), "aws_access_key_id=AKIAXXXX;", "replaced");
  buf = enc("k=akiaiosf;");
  rep.exec(buf, {});
  eq(dec(buf), "k=AKIAXXXX;", "a lower-case spelling is replaced too");

  const red = prog(`nocase; ${KEY} filter { redact(key); decide pass; }`);
  buf = enc("k=AKIAIOSF;");
  red.exec(buf, {});
  eq(dec(buf), "k=********;", "redacted");
});

yeet.test("nocase folds the class before negating it", () => {
  const ci = compileRegexes([{ src: "x[^A-C]y", bit: 0 }], true);
  eq(hit(ci, "xay"), false, "[^A-C] excludes a under nocase");
  eq(hit(ci, "xAy"), false, "[^A-C] excludes A under nocase");
  eq(hit(ci, "xdy"), true, "d is outside the class");
  eq(hit(ci, "XDY"), true, "literals are case-insensitive");
  const cs = compileRegexes([{ src: "x[^A-C]y", bit: 0 }]);
  eq(hit(cs, "xay"), true, "case-sensitive: a is not in A-C");
  eq(hit(cs, "XDY"), false, "case-sensitive literals");
});

yeet.test("nocase leaves digits, punctuation and \\d \\s classes alone", () => {
  const d = compileRegexes([{ src: String.raw`\d{3}-\d{2}`, bit: 0 }], true);
  eq(hit(d, "123-45"), true, "digits");
  eq(hit(d, "123_45"), false, "punctuation is exact");
});

yeet.test("one rule of a nocase program can match a request line exactly", () => {
  /* The literal is found in any case, as the program says. The request line is
   * a regex that says its own: a chat prompt that merely mentions the request
   * in lower case does not look like one. */
  const p = prog(String.raw`nocase; pattern agent = "gptbot";
    regex probe = "(?-i)POST /guardrails/test_custom_code[^ \r\n]* HTTP/1\.[01]";
    filter { mask m = scan(payload, 512); if (m & probe) decide drop("probe"); if (m & agent) decide drop("agent"); decide pass; }`);
  eq(p.exec(enc("POST /guardrails/test_custom_code HTTP/1.1\r\nHost: x\r\n\r\n")).verdict, "drop", "the request itself");
  eq(p.exec(enc("POST /chat HTTP/1.1\r\n\r\n{\"prompt\":\"how do i post /guardrails/test_custom_code http/1.1 safely\"}")).verdict, "pass", "prose that mentions it");
  eq(p.exec(enc("GET / HTTP/1.1\r\nUser-Agent: GPTBot\r\n\r\n")).verdict, "drop", "and the literal still ignores case");
});
