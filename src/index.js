/* pfw-core: the programmable-firewall VM — ISA, assembler, pfw-C compiler,
 * bytecode, the Aho-Corasick and Huffman table builders, and a reference
 * interpreter. Import this to lower programs onto the VM:
 *
 *   import { compile, serializeProgram, build, machine } from "pfw-core";
 *   const c = compile(source);           // pfw-C -> ops, patterns, rules
 *   const bytes = serializeProgram(c.program);   // the `programs` map value
 *   const tables = build(c.patterns, c.nocase);  // the ac_* automaton
 *   const run = machine({ asm: c, tables });     // the reference interpreter
 *
 * The kernel backend (the once-verified eBPF interpreter) is built from bpf/
 * by `make bpf`; it reads exactly the bytes serializeProgram/build produce.
 */

// The ISA contract (mirrors bpf/include/pfw.h; the test suite checks they agree).
export { OP, OP_NAME, REG, REG_NAME, LIMITS, VERDICT, DECODE, LOAD_BE, DECIDE_BOUNDS } from "#/isa.js";

// Assembler: AT&T-syntax text -> program.
export { assemble } from "#/asm";

// The op Builder: emit ops programmatically (both front-ends target it); opText
// disassembles one op.
export { Builder, opText } from "#/builder";

// pfw-C compiler: source -> Builder -> program.
export { compile, compileAst, compileToAsm } from "#/clang";

// A compiled program as a runnable object (.exec(frame, opts), .bytes(), .tables()).
export { Program } from "#/program";
import { compile as _compile } from "#/clang";
import { Program as _Program } from "#/program";
/** Compile pfw-C source straight to a runnable Program (throws on error). */
export function load(source) {
  const c = _compile(source);
  if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors));
  return new _Program(c);
}

// Bytecode: the `programs` map value, and coloured map dumps.
export { serializeProgram, mapModel, mapDump } from "#/bytes";

// Aho-Corasick: patterns -> the ac_goto / ac_fail / ac_accept tables.
export { build } from "#/ac.js";

// HPACK Huffman (P2): build the decode table from RFC 7541, decode, emit the
// kernel's const header.
export { buildHuffman, huffDecode, codes, headerText, TT_CELL } from "#/huffman";

// Loadable transform tables (general P2): build a table, the name→id registry,
// and the flat cells the host loads into the tt_cells map.
export { buildByteMap, TRANSFORM_TABLES, transformCells, TT_CELLS } from "#/transform.js";

// The reference interpreter: run a compiled program over a frame.
// flowHash is `flow.hash` on the host: what the kernel computes for a packet,
// for building a table it will index.
export { machine, V, flowHash } from "#/interp.js";

// Authoring front-ends are namespace submodules (imported directly, not via this
// barrel, so their short constructor names don't collide):
//   import * as C from "pfw-core/dsl.js";   // value builder -> Program
//   import { when, guard, allOf } from "pfw-core/fp.js";  // combinators over C
