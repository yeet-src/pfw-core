/* Regex-driven redact / replace: overwrite a REGEX match in place, not just a
 * literal. Only fixed-length regexes are allowed (the match end fixes the start),
 * so e.g. an SSN or a dashed card number can be scrubbed, while a variable-length
 * pattern is rejected at compile time. The reference interpreter rewrites the
 * frame buffer, so these assert on the bytes after exec. */
import { compile } from "#/clang";
import { toProgram } from "#/program";

const enc = (s) => new TextEncoder().encode(s);
const dec = (u) => String.fromCharCode(...u);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };

yeet.test("redact a regex (SSN) fills the whole fixed-length match", () => {
  const p = prog(String.raw`regex ssn = "\d{3}-\d{2}-\d{4}"; filter { redact(ssn); decide pass; }`);
  const buf = enc("id 123-45-6789 and 987-65-4321 end");
  eq(p.exec(buf, {}).verdict, "pass", "verdict");
  eq(dec(buf), "id *********** and *********** end", "both SSNs redacted (11 bytes each)");
});

yeet.test("redact a regex with a custom fill byte", () => {
  const p = prog(String.raw`regex ssn = "\d{3}-\d{2}-\d{4}"; filter { redact(ssn, 'X'); decide pass; }`);
  const buf = enc("x 111-22-3333 y"); p.exec(buf, {});
  eq(dec(buf), "x XXXXXXXXXXX y", "filled with X");
});

yeet.test("replace a fixed-length regex (card) with a same-length literal", () => {
  const p = prog(String.raw`regex card = "\d{4}-\d{4}-\d{4}-\d{4}"; filter { replace(card, "XXXX-XXXX-XXXX-XXXX"); decide pass; }`);
  const buf = enc("pan 4111-1111-1111-1111 ok"); p.exec(buf, {});
  eq(dec(buf), "pan XXXX-XXXX-XXXX-XXXX ok", "card number masked, same length");
});

yeet.test("redact a regex leaves non-matches untouched", () => {
  const p = prog(String.raw`regex ssn = "\d{3}-\d{2}-\d{4}"; filter { redact(ssn); decide pass; }`);
  const buf = enc("no pii here 12-34"); p.exec(buf, {});
  eq(dec(buf), "no pii here 12-34", "unchanged");
});

yeet.test("redact rejects a variable-length regex at compile time", () => {
  const r = compile(String.raw`regex em = "[a-z]+@[a-z]+"; filter { redact(em); decide pass; }`);
  if (r.ok) throw new Error("expected a fixed-length error");
  if (!JSON.stringify(r.errors).includes("fixed-length")) throw new Error("wrong error: " + JSON.stringify(r.errors));
});

yeet.test("replace rejects a regex whose fixed length != replacement length", () => {
  const r = compile(String.raw`regex ssn = "\d{3}-\d{2}-\d{4}"; filter { replace(ssn, "XX"); decide pass; }`);
  if (r.ok) throw new Error("expected a same-length error");
  if (!JSON.stringify(r.errors).includes("same length")) throw new Error("wrong error: " + JSON.stringify(r.errors));
});

yeet.test("a regex match longer than 127 bytes is redacted whole", () => {
  /* The match length rides in the instruction; at seven bits a 200-byte match
   * was recorded as 72, and only its tail was overwritten. */
  const p = prog(String.raw`regex blob = "#[a-f0-9]{199}"; filter { redact(blob); decide pass; }`);
  const buf = enc("k=#" + "a1".repeat(99) + "f;"); p.exec(buf, {});
  eq(dec(buf), "k=" + "*".repeat(200) + ";", "all 200 bytes");
});

yeet.test("a regex in the second DFA is rewritten from that DFA's start", () => {
  /* The key id and the account number do not share a DFA cheaply, so the number lands in
   * a second one, whose states do not begin at 0. */
  const src = String.raw`regex key = "AKIA[A-Z0-9]{16}"; regex iban = "[A-Z]{2}[0-9]{2}[A-Z0-9]{12}"; filter { redact(iban); decide pass; }`;
  const c = compile(src);
  if (!c.ok) throw new Error(JSON.stringify(c.errors));
  const bit = c.patterns.find((p) => p.name === "iban").id;
  if (c.regex.startOf[bit] === 0) throw new Error("the account number shares the first DFA: this test no longer tests a second one");
  const buf = enc("a GB29NWBK60161331 b AKIAIOSFODNN7EXAMPLE c"); toProgram(c).exec(buf, {});
  eq(dec(buf), "a **************** b AKIAIOSFODNN7EXAMPLE c", "the account number, and not the key");
});
