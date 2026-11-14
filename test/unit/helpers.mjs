/* Shared helpers for the behavioral (yeet) tests: compile/assemble a program and
 * get a `run(frame, flow, opts)` over the reference interpreter, plus a few
 * conveniences. Not a test module itself (no `.test.` suffix), just imported. */
import { assemble } from "#/asm.js";
import { compile } from "#/clang";
import { build } from "#/ac.js";
import { machine, V } from "#/interp.js";

export { V };
export const enc = new TextEncoder();
export const toStr = (u8) => String.fromCharCode(...u8);

/* Assemble `src` and return { run, rules, program }. `run(frame, flow, opts)`
 * runs it through the interpreter; flow defaults to a fresh flow. */
export function fromAsm(src) {
  const asm = assemble(src);
  if (!asm.ok) throw new Error("assemble: " + JSON.stringify(asm.errors));
  const m = machine({ asm, tables: build(asm.patterns, asm.nocase) });
  return { run: (frame = new Uint8Array(64), flow = {}, opts = {}) => m(frame, 0, { ac: 0, mask: 0n, ...flow }, opts), rules: asm.rules, program: asm.program };
}

/* Compile pfw-C `src` and return the same shape (compile builds the program
 * directly via the Builder — no assembly-text round-trip). */
export function fromC(src) {
  const c = compile(src);
  if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors));
  const m = machine({ asm: { program: c.program }, tables: build(c.patterns, c.nocase) });
  return { run: (frame = new Uint8Array(64), flow = {}, opts = {}) => m(frame, 0, { ac: 0, mask: 0n, ...flow }, opts), rules: c.rules, program: c.program };
}
