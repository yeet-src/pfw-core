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
export { OP, OP_NAME, REG, REG_NAME, LIMITS, VERDICT, DECODE, LOAD_BE } from "#/isa.js";

// Assembler: AT&T-syntax text -> program. `opText` disassembles one op.
export { assemble, opText } from "#/asm.js";

// pfw-C compiler: source -> assembly -> program (via the assembler).
export { compile, compileToAsm } from "#/clang.js";

// Bytecode: the `programs` map value, and coloured map dumps.
export { serializeProgram, mapModel, mapDump } from "#/bytes.js";

// Aho-Corasick: patterns -> the ac_goto / ac_fail / ac_accept tables.
export { build } from "#/ac.js";

// HPACK Huffman (P2): build the decode table from RFC 7541, decode, emit the
// kernel's const header.
export { buildHuffman, huffDecode, codes, headerText, TT_CELL } from "#/huffman.js";

// Loadable transform tables (general P2): build a table, the name→id registry,
// and the flat cells the host loads into the tt_cells map.
export { buildByteMap, TRANSFORM_TABLES, transformCells, TT_CELLS } from "#/transform.js";

// The reference interpreter: run a compiled program over a frame.
export { machine, V } from "#/interp.js";
