/* The ISA as the host sees it: opcodes, registers and limits mirrored
 * from bpf/include/pfw.h. Change both or neither. */
export const OP = {
  END: 0, MOV_RC: 1, MOV_CR: 2, ADD_I: 3, SUB_I: 4, ADD_R: 5, SUB_R: 6, AND_I: 7, LOAD: 8,
  CMP_I: 9, CMP_R: 10, TEST: 11, JMP: 12, JE: 13, JNE: 14, JB: 15, JAE: 16, JA: 17, JBE: 18, JF: 19,
  SCAN: 20, MPOS: 21, CMPSTR: 22, FINDB: 23, SKIPB: 24,
  PASS: 25, DROP: 26, COUNT: 27, LOG: 28, BAN: 29, RST: 30, FLOW: 31, MARK: 32, SLOAD: 33, SSTORE: 34,
  BUMP: 35, OR_I: 36, SHL_I: 37, SHR_I: 38, CIDR: 39, RPUSH: 40, RGET: 41, RLEN: 42,
  REDACT: 43, REPLACE: 44, DNAT: 45, LPM: 46, HASH: 47, BLOOM: 48, LPM6: 49,
  REDIRECT: 50, RATE: 51, ARG: 52, ARGC: 53, FARG: 54, FARGS: 55, CONSOLE: 56, PRINTK: 57,
  PUSH: 58, POP: 59, CALL: 60, RET: 61, KNOB: 62, KNOBHAS: 63,
  MUL_I: 64, MUL_R: 65, MOD_I: 66, MOD_R: 67, FHASH: 68, EMIT: 69, TLOAD: 70, KVGET: 71, FLOAD: 72, FSTORE: 73, SAMPLE: 74,
};

/* L7 decode front-ends (pfw_prog.decode), mirroring DECODE_* in pfw.h. Each
 * normalizes the reassembled stream to a plaintext view the matcher scans.
 * huffman decodes an HPACK-Huffman stream through a table huffman.js builds. */
export const DECODE = { none: 0, h2: 1, huffman: 2, transform: 3 };

export const OP_NAME = Object.fromEntries(Object.entries(OP).map(([k, v]) => [v, k.toLowerCase()]));

export const REG = {
  frame: 0, l3: 1, l4: 2, payload: 3, end: 4, proto: 5, sport: 6, dport: 7,
  s0: 8, s1: 9, s2: 10, s3: 11, m: 12, cur: 13, ifindex: 14, len: 15,
  s4: 16, s5: 17, s6: 18, s7: 19, src: 20, saddr: 20, // src is the assembler alias
  shadow: 21, sp: 22, bp: 23,
  a0: 24, a1: 25, a2: 26, a3: 27, a4: 28, a5: 29, a6: 30, // subroutine argument registers
  rv: 31, // subroutine return-value register
  s8: 32, s9: 33, s10: 34, s11: 35, s12: 36, s13: 37, s14: 38, s15: 39, // the second eight scratch registers
  s16: 40, s17: 41, s18: 42, s19: 43, s20: 44, s21: 45, s22: 46, s23: 47, // scratch through the end of the file
  s24: 48, s25: 49, s26: 50, s27: 51, s28: 52, s29: 53, s30: 54, s31: 55,
  s32: 56, s33: 57, s34: 58, s35: 59, s36: 60, s37: 61, s38: 62, s39: 63,
};
/* %s0..%s39, in order: the registers the compilers place locals on. */
export const SCRATCH = Object.keys(REG).filter((k) => /^s\d+$/.test(k)).sort((a, b) => a.slice(1) - b.slice(1)).map((k) => REG[k]);
export const NREGS = 64; // the register file, a power of two: indices are masked & (NREGS - 1)
export const REG_NAME = Object.fromEntries(Object.entries(REG).map(([k, v]) => [v, k]));

export const LIMITS = {
  MAX_OPS: 65536, MAX_PATS: 64, PAT_CAP: 256, NRULES: 1024, GENS: 2,
  AC_STATES: 16384, SCAN_CAP: 4096, REASM_CAP: 4096, LOG_CAP: 256, RE_STATES: 32768, RE_GROUPS: 4, ARGC: 64, FARGS: 8, FSTR: 2, STRARG: 256,
  FLOW_REGS: 4, SAMPLE_CAP: 4096, SAMPLE_TAGS: 64,
  TABLE_CELLS: 131072, TABLES: 16, KV_MAX: 262144,
  FMTS: 16, FMT_CAP: 64, STACK: 256, KNOBS: 256, KNOBSTRS: 64, KNOBSTR_CAP: 64, KNOB_SCAN: 256,
  AC_MAX_FAIL: 16, RING_CAP: 16, SKIP_CAP: 64,
};

/* The limits the kernel never sees: the compiler alone enforces them. Every
 * other key of LIMITS has a #define in pfw.h, and test/node/check-isa.mjs
 * fails when the two disagree. */
export const HOST_LIMITS = ["SAMPLE_TAGS", "TABLES"];

/* Upper bounds, in nanoseconds, of the decision-time histogram's buckets
 * (DECIDE_BOUNDS in pfw.h): bucket i counts decisions that took less than
 * DECIDE_BOUNDS[i] and at least DECIDE_BOUNDS[i - 1]; one more bucket after
 * the last bound has no upper limit. */
export const DECIDE_BOUNDS = [63, 100, 159, 252, 400, 635, 1008, 1600, 2540, 4032, 6400, 10159, 16127, 25600, 40637];

export const VERDICT = { 0: "none", 1: "pass", 2: "drop", 3: "ban", 4: "rst" };

/* What OP_FLOAD reads, by its `reg`: the per-flow registers 0..FLOW_REGS-1, then
 * the two things the kernel counts for the flow itself. */
export const FLOW_FIELD = { bytes: 4, packets: 5 };

/* The LOAD op packs size and byte order into `reg`. */
export const LOAD_BE = 16;
