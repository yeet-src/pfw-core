/* The ISA as the host sees it: opcodes, registers and limits mirrored
 * from bpf/include/pfw.h. Change both or neither. */
export const OP = {
  END: 0, MOV_RC: 1, MOV_CR: 2, ADD_I: 3, SUB_I: 4, ADD_R: 5, SUB_R: 6, AND_I: 7, LOAD: 8,
  CMP_I: 9, CMP_R: 10, TEST: 11, JMP: 12, JE: 13, JNE: 14, JB: 15, JAE: 16, JA: 17, JBE: 18, JF: 19,
  SCAN: 20, MPOS: 21, CMPSTR: 22, FINDB: 23, SKIPB: 24,
  PASS: 25, DROP: 26, COUNT: 27, LOG: 28, BAN: 29, RST: 30, FLOW: 31, MARK: 32, SLOAD: 33, SSTORE: 34,
  BUMP: 35, OR_I: 36, SHL_I: 37, SHR_I: 38, CIDR: 39, RPUSH: 40, RGET: 41, RLEN: 42,
  REDACT: 43, REPLACE: 44, DNAT: 45, LPM: 46, HASH: 47, BLOOM: 48, LPM6: 49,
  REDIRECT: 50, RATE: 51, ARG: 52, ARGC: 53, FARG: 54, FARGS: 55, CONSOLE: 56,
};

/* events whose `verdict` field carries a non-verdict message kind, read by the host. */
export const EV = { CONSOLE: 100 };

/* L7 decode front-ends (pfw_prog.decode), mirroring DECODE_* in pfw.h. Each
 * normalizes the reassembled stream to a plaintext view the matcher scans.
 * huffman decodes an HPACK-Huffman stream through a table huffman.js builds. */
export const DECODE = { none: 0, h2: 1, huffman: 2, transform: 3 };

export const OP_NAME = Object.fromEntries(Object.entries(OP).map(([k, v]) => [v, k.toLowerCase()]));

export const REG = {
  frame: 0, l3: 1, l4: 2, payload: 3, end: 4, proto: 5, sport: 6, dport: 7,
  s0: 8, s1: 9, s2: 10, s3: 11, m: 12, cur: 13, ifindex: 14, len: 15,
  s4: 16, s5: 17, s6: 18, s7: 19, src: 20, saddr: 20, // src is the assembler alias
  shadow: 21,
};
export const REG_NAME = Object.fromEntries(Object.entries(REG).map(([k, v]) => [v, k]));

export const LIMITS = {
  MAX_OPS: 8192, MAX_PATS: 64, PAT_CAP: 64, NRULES: 64, GENS: 2,
  AC_STATES: 4096, SCAN_CAP: 2048, LOG_CAP: 256, RE_STATES: 1024, ARGC: 16, FARGS: 4, FSTR: 2, STRARG: 32,
};

export const VERDICT = { 0: "none", 1: "pass", 2: "drop", 3: "ban", 4: "rst" };

/* The LOAD op packs size and byte order into `reg`. */
export const LOAD_BE = 16;
