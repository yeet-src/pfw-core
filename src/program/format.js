/* printf-style formatting for console()/printk() messages. Numeric args (%d %i %u
 * %o %x %X %c) come from `nums` (u64 BigInt/number), string args (%s) from `strs`,
 * each pulled in format order; %% is literal. Flags/width are parsed but not
 * padded (a debug formatter). Shared by the reference interpreter and the loader. */
const U64M = (1n << 64n) - 1n;

export function formatMsg(fmt, nums = [], strs = []) {
  let ni = 0, si = 0;
  const trimNul = (s) => s.replace(/\0+$/, "");
  return String(fmt).replace(/%[-#0 +]*\d*(?:\.\d+)?[diouxXcs%]/g, (spec) => {
    const conv = spec[spec.length - 1];
    if (conv === "%") return "%";
    if (conv === "s") return trimNul(strs[si++] ?? "");
    const a = nums[ni++];
    const n = (typeof a === "bigint" ? a : BigInt(a ?? 0)) & U64M;
    switch (conv) {
      case "d": case "i": return BigInt.asIntN(64, n).toString();
      case "u": return n.toString();
      case "o": return n.toString(8);
      case "x": return n.toString(16);
      case "X": return n.toString(16).toUpperCase();
      case "c": return String.fromCharCode(Number(n & 0xffn));
      default: return spec;
    }
  });
}
