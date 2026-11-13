/* Shared helpers for the behavioral (yeet) tests: compile/assemble a program and
 * get a `run(frame, flow, opts)` over the reference interpreter, plus a few
 * conveniences. Not a test module itself (no `.test.` suffix), just imported. */
import { assemble } from "#/asm.js";
import { compile } from "#/clang.js";
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

/* Compile pfw-C `src` (then assemble) and return the same shape. */
export function fromC(src) {
  const c = compile(src);
  if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors));
  const a = assemble(c.asm);
  if (!a.ok) throw new Error("assemble: " + JSON.stringify(a.errors));
  const m = machine({ asm: a, tables: build(a.patterns, a.nocase) });
  return { run: (frame = new Uint8Array(64), flow = {}, opts = {}) => m(frame, 0, { ac: 0, mask: 0n, ...flow }, opts), rules: a.rules, program: c.program };
}
