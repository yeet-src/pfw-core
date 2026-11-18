/* Disassemble one op to text, for listings and the Assembly view. The text form
 * is only ever *output* here — neither front-end round-trips through it. */
import { LOAD_BE, OP, OP_NAME, REG_NAME } from "#/isa.js";

export function opText(op, patterns = [], rules = []) {
  const name = OP_NAME[op.code] ?? String(op.code);
  const pat = (i) => patterns[i]?.name ?? String(i);
  const rule = (i) => rules[i]?.name ?? String(i);
  switch (op.code) {
    case OP.OR_I: return `or ${op.imm}`;
    case OP.SHL_I: return `shl ${op.imm}`;
    case OP.SHR_I: return `shr ${op.imm}`;
    case OP.CIDR: {
      const prefix = Number(op.imm >> 32n), net = Number(op.imm & 0xffffffffn);
      return `cidr ${[(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join(".")}/${prefix}`;
    }
    case OP.MUL_I: return `mul ${op.imm}`;
    case OP.MOD_I: return `mod ${op.imm}`;
    case OP.MUL_R: return `mul %${REG_NAME[op.reg] ?? op.reg}`;
    case OP.MOD_R: return `mod %${REG_NAME[op.reg] ?? op.reg}`;
    case OP.FHASH: return "fhash";
    case OP.MOV_RC: case OP.MOV_CR: case OP.ADD_R: case OP.SUB_R: case OP.CMP_R:
      return `${name} %${REG_NAME[op.reg] ?? op.reg}`;
    case OP.LOAD: return `load ${op.reg & 15}${op.reg & LOAD_BE ? "be" : ""} +${op.imm}`;
    case OP.TEST: {
      const names = patterns.filter((p) => (op.imm >> BigInt(p.id)) & 1n).map((p) => p.name);
      return `test ${names.length ? names.join("|") : "0x" + op.imm.toString(16)}`;
    }
    case OP.MPOS: case OP.CMPSTR: return `${name} ${pat(op.reg)}`;
    case OP.REDACT: return `redact ${pat(op.reg & 0x3fff)}, 0x${(op.imm & 0xffn).toString(16)}${op.reg & 0x8000 ? " [re]" : ""}`;
    case OP.REPLACE: return `replace ${pat(op.reg & 0x3fff)}, ${pat(Number(op.imm & 0x3fn))}${op.reg & 0x8000 ? " [re]" : ""}`;
    case OP.DNAT: {
      const ip = Number(op.imm & 0xffffffffn), port = Number((op.imm >> 32n) & 0xffffn);
      return `dnat ${(ip >>> 24) & 255}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}:${port}`;
    }
    case OP.REDIRECT: return `redirect ${op.imm}`;
    case OP.RATE: return `${op.reg ? "srcrate" : "rate"} ${Number(op.imm & 0xffffffffn)} ${Number((op.imm >> 32n) & 0xffffffffn)}`;
    case OP.ARG: { const idx = Number((op.imm >> 32n) & 0xffffn), def = Number(op.imm & 0xffffffffn); return def ? `arg ${idx} ?? ${def}` : `arg ${idx}`; }
    case OP.ARGC: return `argc`;
    case OP.KNOB: return `knob ${op.imm}`;
    case OP.KNOBHAS: return `knobhas ${op.imm}`;
    case OP.FARG: return `farg`;
    case OP.FARGS: return `fargs ${op.imm}`;
    case OP.CONSOLE: return `console ${op.imm}`;
    case OP.PRINTK: return `printk ${op.imm}`;
    case OP.FINDB: case OP.SKIPB: return `${name} 0x${op.reg.toString(16)} ${op.imm}`;
    case OP.DROP: case OP.COUNT: return `${name} ${rule(op.reg)}`;
    case OP.BAN: case OP.RST: return `${name} ${rule(op.reg)} ${op.imm}s`;
    case OP.MARK: return `mark ${op.reg} ${op.imm}s`;
    case OP.SSTORE: { const m = (op.imm >> 32n) & 1n ? "srcstore" : "sstore", v = op.imm & 0xffffffffn; return op.reg ? `${m} ${v}, ${op.reg}s` : `${m} ${v}`; }
    case OP.SLOAD: return op.reg ? "srcload" : "sload";
    case OP.BUMP: return op.reg ? "srcbump" : "bump";
    case OP.CALL: return `call ${op.imm}`;
    case OP.PASS: case OP.FLOW: case OP.RPUSH: case OP.RGET: case OP.RLEN: case OP.LPM: case OP.HASH: case OP.BLOOM: case OP.LPM6: case OP.PUSH: case OP.POP: case OP.RET: case OP.END:
      return name;
    default: return op.imm ? `${name} ${op.imm}` : name;
  }
}
