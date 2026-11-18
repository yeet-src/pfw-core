/* pfw assembler operands: literal + operand parsing (%reg, $imm, D(%reg), CIDR). */
import { REG } from "#/isa.js";
import { fail } from "#/asm/errors.js";

/* ---- literals ------------------------------------------------------------ */

const ESC = { n: 10, r: 13, t: 9, 0: 0, "\\": 92, '"': 34, "'": 39 };

export function unescape(body) {
  const out = [];
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c !== "\\") {
      out.push(c.charCodeAt(0) & 0xff);
      continue;
    }
    const e = body[++i];
    if (e === "x") {
      const hex = body.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) fail(`bad \\x escape`);
      out.push(parseInt(hex, 16));
      i += 2;
    } else if (e in ESC) out.push(ESC[e]);
    else fail(`unknown escape \\${e}`);
  }
  return out;
}

export function parseNumber(tok) {
  if (/^-?0x[0-9a-fA-F]+$/.test(tok)) return BigInt(tok.replace("-", "")) * (tok.startsWith("-") ? -1n : 1n);
  if (/^-?\d+$/.test(tok)) return BigInt(tok);
  if (/^'(\\.|[^'\\])'$/.test(tok)) return BigInt(unescape(tok.slice(1, -1))[0]);
  return null;
}

/* "A.B.C.D/PREFIX" → the OP_CIDR immediate: net in the low 32 bits (host
 * order, as %saddr is), prefix length in bits 32..39. */
export function parseCidr(text) {
  const m = text.replace(/^\$/, "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) fail(`bad CIDR \`${text}\` (want A.B.C.D/PREFIX)`);
  const oct = m.slice(1, 5).map(Number);
  const prefix = Number(m[5]);
  if (oct.some((x) => x > 255)) fail("CIDR octet 0–255");
  if (prefix > 32) fail("CIDR prefix 0–32");
  const net = ((oct[0] << 24) | (oct[1] << 16) | (oct[2] << 8) | oct[3]) >>> 0;
  return (BigInt(prefix) << 32n) | BigInt(net);
}

/* ---- operands ------------------------------------------------------------ */

/* {kind:"imm", text} | {kind:"reg", name, idx} | {kind:"mem", disp, base} | {kind:"label", name} */
export function parseOperand(tok) {
  if (tok.startsWith("$")) return { kind: "imm", text: tok.slice(1) };
  if (tok.startsWith("%")) {
    const name = tok.slice(1).toLowerCase();
    if (!(name in REG)) fail(`no register \`%${name}\``);
    return { kind: "reg", name, idx: REG[name] };
  }
  const m = tok.match(/^(-?(?:0x[0-9a-fA-F]+|\d+))?\((%\w+)\)$/);
  if (m) {
    const base = parseOperand(m[2]);
    const disp = m[1] ? parseNumber(m[1]) : 0n;
    return { kind: "mem", disp, base };
  }
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tok)) return { kind: "label", name: tok };
  fail(`bad operand \`${tok}\``);
}

export const isCur = (o) => o?.kind === "reg" && o.name === "cur";
/* The registers a program may write (docs/isa/02-registers.md): scratch, the
 * match mask, the stack and frame pointers, and the subroutine argument and
 * return registers — the same set pfw-C can assign. %end is writable so `frame`
 * can shrink the readable window to one record; it only ever narrows reads
 * (window/load clamp to it), so it stays safe. The packet fields are read-only. */
export const isWritable = (o) => o?.kind === "reg" && /^(s[0-9]|s1[0-5]|m|end|sp|bp|a[0-6]|rv)$/.test(o.name);

/* ---- the assembler ------------------------------------------------------- */

