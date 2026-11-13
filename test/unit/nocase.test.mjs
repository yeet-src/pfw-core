/* nocase case-folding, for both the automaton (scan) and anchored compare
 * (cmpstr/starts). The interpreter must fold input bytes the same way the kernel
 * does (ac_step / cmpstr_step fold) — this pins the fix for a divergence the
 * builder surfaced (a nocase scan silently failed to match in the interpreter). */
import * as C from "#/dsl.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

const scanProg = (nocase) => {
  const parts = [C.pattern("bot", "GPTBot"), C.filter(C.iff(C.band(C.scan(C.payload, 256), "bot"), C.drop("hit")), C.pass())];
  return C.program(...(nocase ? [C.nocase(), ...parts] : parts));
};

yeet.test("nocase scan matches any case; case-sensitive matches only exact", () => {
  const ci = scanProg(true), cs = scanProg(false);
  for (const s of ["x GPTBot", "x gptbot", "x GpTbOt", "x gPtBoT"]) eq(ci.exec(enc(s)).verdict, "drop", `nocase ${s}`);
  eq(cs.exec(enc("x GPTBot")).verdict, "drop", "cs exact");
  eq(cs.exec(enc("x gptbot")).verdict, "pass", "cs lowercase misses");
  eq(ci.exec(enc("x Chrome")).verdict, "pass", "nocase non-match passes");
});

yeet.test("nocase cmpstr (starts) folds both sides", () => {
  const ci = C.program(C.nocase(), C.pattern("get", "GET"), C.filter(C.iff(C.starts(C.payload, "get"), C.drop("m")), C.pass()));
  const cs = C.program(C.pattern("get", "GET"), C.filter(C.iff(C.starts(C.payload, "get"), C.drop("m")), C.pass()));
  for (const s of ["GET /", "get /", "GeT /"]) eq(ci.exec(enc(s)).verdict, "drop", `nocase starts ${s}`);
  eq(cs.exec(enc("get /")).verdict, "pass", "cs starts lowercase misses");
  eq(cs.exec(enc("GET /")).verdict, "drop", "cs starts exact");
});

yeet.test("nocase leaves non-letters untouched", () => {
  // digits/punct must not be folded; a pattern with them still matches exactly.
  const p = C.program(C.nocase(), C.pattern("v", "v1.2-OK_"), C.filter(C.iff(C.band(C.scan(C.payload, 256), "v"), C.drop("m")), C.pass()));
  eq(p.exec(enc("has V1.2-ok_ here")).verdict, "drop", "letters fold, punct/digits exact");
  eq(p.exec(enc("has v1!2-ok_ here")).verdict, "pass", "a changed punct breaks the match");
});
