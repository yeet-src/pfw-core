/* Every example .pfc program compiles — guards the compiler/assembler surface
 * and keeps the examples (real pfw-C programs) from rotting. A node script, not
 * a yeet test, because it reads the example files from disk (the yeet sandbox
 * has no file I/O); run by `npm run test:node`. */
import { readFileSync, readdirSync } from "node:fs";
import { compile } from "#/clang";

const dir = new URL("../../examples/", import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith(".pfc")).sort();
let bad = 0;
for (const f of files) {
  const c = compile(readFileSync(new URL(f, dir), "utf8"));
  if (!c.ok) { bad++; console.log(`FAIL ${f}: ${JSON.stringify(c.errors)}`); }
  else console.log(`ok   ${f} (${c.program.nops} ops)`);
}
console.log(bad ? `${bad}/${files.length} failed` : `${files.length}/${files.length} examples compiled`);
process.exit(bad ? 1 : 0);
