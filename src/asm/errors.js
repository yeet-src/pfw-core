/* The assembler's error type and the throw helper, caught at the assemble()
 * boundary and turned into { ok:false, errors:[...] }. */
export class AsmError extends Error {}
export const fail = (msg) => { throw new AsmError(msg); };
