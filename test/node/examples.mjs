/* Every .pfc program compiles — the showcase in examples/ and the untested
 * starting points in contrib/ alike. Guards the compiler/assembler surface and
 * keeps the programs (real pfw-C) from rotting. It also checks that a program's
 * regex DFA fits the kernel's table (LIMITS.RE_STATES): the compiler accepts a
 * larger one, but the kernel indexes states modulo that size, so such a program
 * would load and then match wrongly. What a program DOES is tested for
 * examples/ in examples-behavior.mjs; contrib/ is compile-checked only.
 *
 * A node script, not a yeet test, because it reads the files from disk (the
 * yeet sandbox has no file I/O); run by `npm run test:node`. */
import { readFileSync, readdirSync } from "node:fs";
import { compile } from "#/clang";
import { LIMITS } from "#/isa.js";

let bad = 0, total = 0;
for (const name of ["examples", "contrib"]) {
  const dir = new URL(`../../${name}/`, import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith(".pfc")).sort();
  for (const f of files) {
    total++;
    let c;
    try { c = compile(readFileSync(new URL(f, dir), "utf8")); }
    catch (e) { c = { ok: false, errors: [{ line: 0, text: e.message }] }; } // e.g. the op budget
    if (!c.ok) { bad++; console.log(`FAIL ${name}/${f}: ${JSON.stringify(c.errors)}`); }
    else if (c.regex && c.regex.nstates > LIMITS.RE_STATES) { bad++; console.log(`FAIL ${name}/${f}: regex DFA has ${c.regex.nstates} states (kernel table holds ${LIMITS.RE_STATES})`); }
    else console.log(`ok   ${name}/${f} (${c.program.nops} ops)`);
  }
  if (!files.length) { bad++; console.log(`FAIL ${name}/: no .pfc programs found`); }
}
console.log(bad ? `${bad}/${total} failed` : `${total}/${total} programs compiled (examples/ + contrib/)`);
process.exit(bad ? 1 : 0);
