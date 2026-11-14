/* Shared pfw-C language constants: the register names and the verdict keywords,
 * used by both the parser (keyword recognition) and codegen (lowering). */
export const ARGREGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6"];
export const REGISTERS = new Set(["payload", "sport", "dport", "proto", "len", "l3", "l4", "end", "ifindex", "frame", "src", "shadow", "sp", "bp", ...ARGREGS, "rv"]);
export const WRITABLE_REGS = new Set(["sp", "bp", "rv", ...ARGREGS]); // registers a program may assign to
export const VERDICTS = new Set(["pass", "drop", "count", "ban", "rst"]);
