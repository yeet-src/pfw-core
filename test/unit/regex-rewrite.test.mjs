/* Regex-driven redact / replace: overwrite a REGEX match in place, not just a
 * literal. Only fixed-length regexes are allowed (the match end fixes the start),
 * so e.g. an SSN or a dashed card number can be scrubbed, while a variable-length
 * pattern is rejected at compile time. The reference interpreter rewrites the
 * frame buffer, so these assert on the bytes after exec. */
import { compile } from "#/clang.js";
import { toProgram } from "#/program.js";

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
