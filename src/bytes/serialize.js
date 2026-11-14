/* The compiled program serialized to the bytes that go into the `programs` map,
 * exactly as struct pfw_prog (bpf/include/pfw.h). Layout constants are exported
 * for the dump pretty-printer.
 */
import { LIMITS } from "#/isa.js";

export const OPS = LIMITS.MAX_OPS; // 64
export const PATS = LIMITS.MAX_PATS; // 64
export const PATCAP = LIMITS.PAT_CAP; // 64
export const OP_SIZE = 16;
export const PAT_SIZE = 4 + PATCAP; // 68
export const OPS_AT = 32; // after nops,npats,nocase,gen,reasm,reasm_dport,decode,_pad
export const PATS_AT = OPS_AT + OPS * OP_SIZE; // 1048
export const TOTAL = PATS_AT + PATS * PAT_SIZE; // 5392

/** Serialize a compiled program into its `struct pfw_prog` bytes. */
export function serializeProgram(program, gen = 0) {
  const buf = new Uint8Array(TOTAL);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, program.nops >>> 0, true);
  dv.setUint32(4, program.npats >>> 0, true);
  dv.setUint32(8, program.nocase >>> 0, true);
  dv.setUint32(12, gen >>> 0, true);
  dv.setUint32(16, (program.reasm ?? 0) >>> 0, true);
  dv.setUint32(20, (program.reasm_dport ?? 0) >>> 0, true); // reasm_dport
  dv.setUint32(24, (program.decode ?? 0) >>> 0, true); // decode
  dv.setUint32(28, (program.transform_table ?? 0) >>> 0, true); // transform_table (DECODE_TRANSFORM)
  for (let i = 0; i < OPS; i++) {
    const op = program.ops[i];
    const b = OPS_AT + i * OP_SIZE;
    if (!op) continue;
    dv.setUint32(b, op.code >>> 0, true);
    dv.setUint32(b + 4, op.reg >>> 0, true);
    dv.setBigUint64(b + 8, BigInt(op.imm ?? 0), true);
  }
  for (let i = 0; i < PATS; i++) {
    const p = program.pats[i];
    const b = PATS_AT + i * PAT_SIZE;
    if (!p) continue;
    dv.setUint32(b, p.len >>> 0, true);
    for (let j = 0; j < PATCAP; j++) buf[b + 4 + j] = (p.bytes[j] ?? 0) & 0xff;
  }
  return buf;
}
