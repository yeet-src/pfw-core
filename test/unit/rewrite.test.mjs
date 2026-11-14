/* Packet rewrite (redact / replace): overwrite every match of a pattern in the
 * frame, in place, same length. redact fills with a byte; replace copies a
 * same-length string. The reference interpreter rewrites the frame buffer, so
 * these assert on the bytes after exec. */
import * as C from "#/dsl.js";
import { compile } from "#/clang.js";

const enc = (s) => new TextEncoder().encode(s);
const dec = (u) => String.fromCharCode(...u);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };

yeet.test("redact fills every match with '*'", () => {
  const p = C.program(C.pattern("tok", "secret"), C.filter(C.redact("tok"), C.pass()));
  const buf = enc("a secret b secret c");
  const r = p.exec(buf, {});
  eq(r.verdict, "pass", "verdict");
  eq(dec(buf), "a ****** b ****** c", "both occurrences redacted, same length");
});

yeet.test("redact with a custom fill byte", () => {
  const p = C.program(C.pattern("pw", "pw"), C.filter(C.redact("pw", "X"), C.pass()));
  const buf = enc("x pw y pw"); p.exec(buf, {});
  eq(dec(buf), "x XX y XX", "filled with X");
});

yeet.test("redact leaves non-matches untouched", () => {
  const p = C.program(C.pattern("tok", "secret"), C.filter(C.redact("tok"), C.pass()));
  const buf = enc("nothing to see"); p.exec(buf, {});
  eq(dec(buf), "nothing to see", "unchanged");
});

yeet.test("replace swaps a same-length string", () => {
  const p = C.program(C.pattern("bot", "GPTBot"), C.filter(C.replace("bot", "NOTBOT"), C.pass()));
  const buf = enc("UA: GPTBot! and GPTBot"); p.exec(buf, {});
  eq(dec(buf), "UA: NOTBOT! and NOTBOT", "every match replaced");
});

yeet.test("replace rejects a different-length replacement at compile time", () => {
  const r = compile(`pattern bot = "GPTBot"; filter { replace(bot, "NO"); return pass; }`);
  if (r.ok) throw new Error("expected a same-length error");
  if (!JSON.stringify(r.errors).includes("same-length")) throw new Error("wrong error: " + JSON.stringify(r.errors));
});

yeet.test("nocase redact matches any case (fills the actual bytes)", () => {
  const p = C.program(C.nocase(), C.pattern("tok", "secret"), C.filter(C.redact("tok"), C.pass()));
  const buf = enc("X SeCrEt Y"); p.exec(buf, {});
  eq(dec(buf), "X ****** Y", "case-insensitive match redacted");
});

yeet.test("redact is payload-relative (not cursor-relative)", () => {
  // redact scans the whole payload regardless of where the cursor was moved, so
  // every match is filled — moving the cursor first does not shield earlier ones.
  const p = C.program(C.pattern("x", "AA"), C.filter(C.ptr("q", C.find(C.payload, "B", 16)), C.redact("x"), C.pass()));
  const buf = enc("AA B AA"); p.exec(buf, {});
  eq(dec(buf), "** B **", "every match redacted, cursor position ignored");
});
