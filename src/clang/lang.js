/* Shared pfw-C language constants: the register names and the verdict keywords,
 * used by both the parser (keyword recognition) and codegen (lowering). */
export const ARGREGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6"];
export const REGISTERS = new Set(["payload", "sport", "dport", "proto", "len", "l3", "l4", "end", "ifindex", "frame", "src", "shadow", "sp", "bp", ...ARGREGS, "rv"]);
export const WRITABLE_REGS = new Set(["sp", "bp", "rv", ...ARGREGS]); // registers a program may assign to
/* The direct reads: `u8(p)`, `be16(p + 2)`... one field of the packet at a
 * pointer. The same type names a `frame` header field takes, plus the 64-bit pair. */
export const READS = new Set(["u8", "u16", "u32", "u64", "be16", "be24", "be32", "be64"]);
export const VERDICTS = new Set(["pass", "drop", "count", "ban", "rst"]);
