/* Every shipped example program compiles — guards the compiler/assembler surface
 * and keeps the examples from rotting. */
import { compile } from "#/src/clang.js";
import { examples } from "#/examples/index.js";

for (const [name, src] of Object.entries(examples)) {
  yeet.test(`example "${name}" compiles`, () => {
    const c = compile(src);
    if (!c.ok) throw new Error(JSON.stringify(c.errors));
  });
}
