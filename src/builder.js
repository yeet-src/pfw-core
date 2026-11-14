/* The program Builder: an LLVM-IRBuilder-style emitter that constructs ops,
 * resolves labels, allocates scratch registers, and interns patterns and rules —
 * the single op-construction core both front-ends target. The assembler (asm.js)
 * parses text into Builder calls; the pfw-C compiler (clang.js) emits Builder
 * calls directly. Neither goes through an assembly-text round-trip; the text form
 * is only ever *output* (disassembled from the ops by `opText`).
 *
 *   const b = new Builder();
 *   b.movToCur(REG.saddr); b.cidr(net, prefix); b.je("hit"); b.pass();
 *   b.label("hit"); b.rst(b.ruleId("lo"), 0n);
 *   const { program, patterns, rules, listing, errors } = b.finalize();
 *
 * Register operands may be a physical register index or a virtual register from
 * b.vreg() (for compiler locals); finalize() maps the virtuals onto the eight
 * scratch registers by live range. Jumps take a label name, resolved (forward
 * only) at finalize. Methods throw BuildError on misuse; callers that parse
 * untrusted text (the assembler) catch per line.
 */
import { LIMITS, LOAD_BE, OP, OP_NAME, REG, REG_NAME } from "#/isa.js";

export class BuildError extends Error {}
const fail = (m) => { throw new BuildError(m); };

const VREG_BASE = 1 << 20; // reg values >= this are virtual (allocated at finalize)
const SCRATCH = [REG.s0, REG.s1, REG.s2, REG.s3, REG.s4, REG.s5, REG.s6, REG.s7];

export class Builder {
  constructor() {
    this.ops = [];
    this.labels = new Map();      // name -> op index
    this.patterns = [];           // { id, name, bytes, text }
    this.patByName = new Map();
    this.rules = [{ id: 0, name: "-" }];
    this.ruleByName = new Map();
    this.vregs = [];              // vreg token -> { name, line } for diagnostics
    this.nocase = 0;
    this.reasm = 0;
    this.reasmDport = 0;
    this.decode = 0;
    this.transformTable = 0;
    this._line = 0;              // stamped onto emitted ops
  }

  at(line) { this._line = line; return this; }

  /* The one primitive: push an op. `regSlot` marks reg as an allocatable register
   * (so a virtual one is mapped at finalize); other ops put ids/bytes/sizes in reg. */
  op(code, reg = 0, imm = 0n, { label = null, regSlot = false } = {}) {
    if (this.ops.length >= LIMITS.MAX_OPS) fail(`more than ${LIMITS.MAX_OPS} instructions`);
    this.ops.push({ code, reg: reg >>> 0 === reg || reg >= VREG_BASE ? reg : reg >>> 0, imm: BigInt(imm), label, regSlot, line: this._line });
    return this;
  }

  // ---- register / arithmetic (reg is an allocatable register) ----
  movToCur(reg) { return this.op(OP.MOV_RC, reg, 0n, { regSlot: true }); }   // cur = reg
  movFromCur(reg) { return this.op(OP.MOV_CR, reg, 0n, { regSlot: true }); } // reg = cur
  addReg(reg) { return this.op(OP.ADD_R, reg, 0n, { regSlot: true }); }
  subReg(reg) { return this.op(OP.SUB_R, reg, 0n, { regSlot: true }); }
  cmpReg(reg) { return this.op(OP.CMP_R, reg, 0n, { regSlot: true }); }

  // ---- immediate arithmetic / compare ----
  addImm(n) { return this.op(OP.ADD_I, 0, n); }
  subImm(n) { return this.op(OP.SUB_I, 0, n); }
  andImm(n) { return this.op(OP.AND_I, 0, n); }
  orImm(n) { return this.op(OP.OR_I, 0, n); }
  shlImm(n) { return this.op(OP.SHL_I, 0, n); }
  shrImm(n) { return this.op(OP.SHR_I, 0, n); }
  cmpImm(n) { return this.op(OP.CMP_I, 0, n); }
  load(size, be, disp) { return this.op(OP.LOAD, (size & 15) | (be ? LOAD_BE : 0), disp); }
  test(mask) { return this.op(OP.TEST, 0, mask); }
  cidr(net, prefix) { return this.op(OP.CIDR, 0, (BigInt(prefix & 0xff) << 32n) | BigInt(net >>> 0)); }

  // ---- jumps (label resolved at finalize) ----
  jmp(l) { return this.op(OP.JMP, 0, 0n, { label: l }); }
  je(l) { return this.op(OP.JE, 0, 0n, { label: l }); }
  jne(l) { return this.op(OP.JNE, 0, 0n, { label: l }); }
  jb(l) { return this.op(OP.JB, 0, 0n, { label: l }); }
  jae(l) { return this.op(OP.JAE, 0, 0n, { label: l }); }
  ja(l) { return this.op(OP.JA, 0, 0n, { label: l }); }
  jbe(l) { return this.op(OP.JBE, 0, 0n, { label: l }); }
  jf(l) { return this.op(OP.JF, 0, 0n, { label: l }); }

  // ---- patterns ----
  scan(len) { return this.op(OP.SCAN, 0, len); } // runs AC (literals) + the regex DFA, both into %m
  mpos(pat) { return this.op(OP.MPOS, pat); }
  cmpstr(pat) { return this.op(OP.CMPSTR, pat); }
  findb(byte, len) { return this.op(OP.FINDB, byte & 0xff, len); }
  skipb(byte, max) { return this.op(OP.SKIPB, byte & 0xff, max); }

  // ---- verdicts / output ----
  pass() { return this.op(OP.PASS); }
  drop(rule) { return this.op(OP.DROP, rule); }
  count(rule) { return this.op(OP.COUNT, rule); }
  log(len) { return this.op(OP.LOG, 0, len); }
  ban(rule, ttl) { return this.op(OP.BAN, rule, ttl); }
  rst(rule, ttl) { return this.op(OP.RST, rule, ttl); }

  // ---- per-flow state ----
  flow() { return this.op(OP.FLOW); }
  mark(v, ttl) { return this.op(OP.MARK, v, ttl); }
  sload() { return this.op(OP.SLOAD); }
  sstore(state, ttl) { return this.op(OP.SSTORE, Number(ttl), state); } // reg = ttl, imm = state
  bump() { return this.op(OP.BUMP); }
  rpush() { return this.op(OP.RPUSH); }
  rget() { return this.op(OP.RGET); }
  rlen() { return this.op(OP.RLEN); }
  // ---- packet rewrite (reg = match pattern id; imm = fill byte / replacement pattern id) ----
  redact(pat, fill) { return this.op(OP.REDACT, pat, BigInt(fill)); }
  replace(pat, repl) { return this.op(OP.REPLACE, pat, BigInt(repl)); }
  // DNAT: rewrite dst IPv4 (host-order u32) + port into imm (ip low 32, port bits 32..47).
  dnat(ip, port) { return this.op(OP.DNAT, 0, (BigInt(ip >>> 0) & 0xffffffffn) | (BigInt(port & 0xffff) << 32n)); }
  lpm() { return this.op(OP.LPM); } // ZF = %cur is in the lpm CIDR set
  hash() { return this.op(OP.HASH); } // ZF = %cur is a key in the hashset
  bloom() { return this.op(OP.BLOOM); } // ZF = %cur is (probably) in the bloom filter
  lpm6() { return this.op(OP.LPM6); } // ZF = the IPv6 source is in the lpm6 CIDR set
  redirect(ifindex) { return this.op(OP.REDIRECT, 0, BigInt(ifindex >>> 0)); } // forward the packet out ifindex (XDP_REDIRECT)

  // ---- meta ----
  label(name) { if (this.labels.has(name)) fail(`label \`${name}\` defined twice`); this.labels.set(name, this.ops.length); return this; }
  vreg(name = "", line = 0) { const t = VREG_BASE + this.vregs.length; this.vregs.push({ name, line }); return t; }

  setNocase() { this.nocase = 1; }
  setReasm(port = 0) { this.reasm = 1; this.reasmDport = port; }
  setDecode(kind, port = 0) { this.decode = kind; this.reasm = 1; if (port) this.reasmDport = port; }
  setTransform(id, port = 0) { this.decode = 3 /* DECODE_TRANSFORM */; this.transformTable = id; this.reasm = 1; if (port) this.reasmDport = port; }

  /* Intern a rule name (or accept a numeric id) → id. */
  ruleId(text) {
    if (typeof text === "number") { if (text < 0 || text >= LIMITS.NRULES) fail(`rule id 0–${LIMITS.NRULES - 1}`); return text; }
    if (this.ruleByName.has(text)) return this.ruleByName.get(text);
    const id = this.rules.length;
    if (id >= LIMITS.NRULES) fail(`more than ${LIMITS.NRULES - 1} rules`);
    this.rules.push({ id, name: text });
    this.ruleByName.set(text, id);
    return id;
  }

  /* Declare a pattern → bit id. */
  pat(name, bytes, text = "") {
    if (this.patByName.has(name)) fail(`pattern \`${name}\` declared twice`);
    if (bytes.length === 0) fail("empty pattern");
    if (bytes.length > LIMITS.PAT_CAP) fail(`pattern longer than ${LIMITS.PAT_CAP} bytes`);
    if (this.patterns.length >= LIMITS.MAX_PATS) fail(`more than ${LIMITS.MAX_PATS} patterns`);
    const id = this.patterns.length;
    this.patterns.push({ id, name, kind: "literal", bytes, text });
    this.patByName.set(name, id);
    return id;
  }
  /* Declare a regex pattern → bit id (shares the %m bit space with literals; the
   * compiler builds these into a DFA, AC skips them). */
  repat(name, src) {
    if (this.patByName.has(name)) fail(`pattern \`${name}\` declared twice`);
    if (this.patterns.length >= LIMITS.MAX_PATS) fail(`more than ${LIMITS.MAX_PATS} patterns`);
    const id = this.patterns.length;
    this.patterns.push({ id, name, kind: "regex", src, bytes: [] });
    this.patByName.set(name, id);
    return id;
  }
  patId(name) { if (!this.patByName.has(name)) fail(`no pattern \`${name}\``); return this.patByName.get(name); }

  /* Resolve labels, allocate virtual registers, and emit the program. Errors
   * (undefined/backward label, too many live locals) are collected, not thrown. */
  finalize() {
    const errors = [];
    for (let pc = 0; pc < this.ops.length; pc++) {
      const op = this.ops[pc];
      if (!op.label) continue;
      const target = this.labels.get(op.label);
      if (target === undefined) errors.push({ line: op.line, text: `no label \`${op.label}\`` });
      else if (target <= pc) errors.push({ line: op.line, text: `\`${op.label}\` is behind the jump; jumps go forward only` });
      else op.imm = BigInt(target);
    }
    this._allocate(errors);
    const listing = this.ops.map((op, pc) => ({ pc, text: opText(op, this.patterns, this.rules), line: op.line }));
    if (this.ops.length === 0 && errors.length === 0) errors.push({ line: 0, text: "empty program" });
    const program = {
      nops: this.ops.length, npats: this.patterns.length, nocase: this.nocase, gen: 0,
      reasm: this.reasm, reasm_dport: this.reasmDport, decode: this.decode, transform_table: this.transformTable,
      ops: this.ops.map(({ code, reg, imm }) => ({ code, reg, imm })),
      pats: this.patterns.map((p) => ({ len: p.bytes.length, bytes: p.bytes })),
    };
    return { ok: errors.length === 0, errors, program, patterns: this.patterns, rules: this.rules, listing, nocase: !!this.nocase, reasm: !!this.reasm };
  }

  /* Linear-scan allocation of virtual registers onto the 8 scratch registers, by
   * live range (forward-only ISA ⇒ a vreg is live from first to last mention). */
  _allocate(errors) {
    const first = new Map(), last = new Map();
    this.ops.forEach((op, i) => {
      if (op.regSlot && op.reg >= VREG_BASE) { if (!first.has(op.reg)) first.set(op.reg, i); last.set(op.reg, i); }
    });
    const intervals = [...first.keys()].map((v) => ({ v, start: first.get(v), end: last.get(v) })).sort((a, b) => a.start - b.start || a.end - b.end);
    let free = SCRATCH.map((_, i) => i);
    const active = [], phys = new Map();
    for (const iv of intervals) {
      for (let i = active.length - 1; i >= 0; i--) if (active[i].end < iv.start) { free.push(phys.get(active[i].v)); active.splice(i, 1); }
      if (!free.length) {
        const who = this.vregs[iv.v - VREG_BASE];
        const held = active.map((a) => this.vregs[a.v - VREG_BASE].name).filter((n) => n && !n.startsWith("__"));
        errors.push({ line: who?.line ?? 0, text: `too many locals live at once: ${who?.name ? `\`${who.name}\`` : "a temporary"} needs a register but all ${SCRATCH.length} are held${held.length ? ` (by ${held.map((n) => `\`${n}\``).join(", ")})` : ""}` });
        phys.set(iv.v, 0); active.push(iv); continue;
      }
      free.sort((a, b) => a - b);
      phys.set(iv.v, free.shift());
      active.push(iv);
    }
    for (const op of this.ops) if (op.regSlot && op.reg >= VREG_BASE) op.reg = SCRATCH[phys.get(op.reg)];
  }
}

/* Disassemble one op to text, for listings and the Assembly view. */
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
    case OP.MOV_RC: case OP.MOV_CR: case OP.ADD_R: case OP.SUB_R: case OP.CMP_R:
      return `${name} %${REG_NAME[op.reg] ?? op.reg}`;
    case OP.LOAD: return `load ${op.reg & 15}${op.reg & LOAD_BE ? "be" : ""} +${op.imm}`;
    case OP.TEST: {
      const names = patterns.filter((p) => (op.imm >> BigInt(p.id)) & 1n).map((p) => p.name);
      return `test ${names.length ? names.join("|") : "0x" + op.imm.toString(16)}`;
    }
    case OP.MPOS: case OP.CMPSTR: return `${name} ${pat(op.reg)}`;
    case OP.REDACT: return `redact ${pat(op.reg)}, 0x${op.imm.toString(16)}`;
    case OP.REPLACE: return `replace ${pat(op.reg)}, ${pat(Number(op.imm))}`;
    case OP.DNAT: {
      const ip = Number(op.imm & 0xffffffffn), port = Number((op.imm >> 32n) & 0xffffn);
      return `dnat ${(ip >>> 24) & 255}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}:${port}`;
    }
    case OP.REDIRECT: return `redirect ${op.imm}`;
    case OP.FINDB: case OP.SKIPB: return `${name} 0x${op.reg.toString(16)} ${op.imm}`;
    case OP.DROP: case OP.COUNT: return `${name} ${rule(op.reg)}`;
    case OP.BAN: case OP.RST: return `${name} ${rule(op.reg)} ${op.imm}s`;
    case OP.MARK: return `mark ${op.reg} ${op.imm}s`;
    case OP.SSTORE: return op.reg ? `sstore ${op.imm}, ${op.reg}s` : `sstore ${op.imm}`;
    case OP.PASS: case OP.FLOW: case OP.SLOAD: case OP.BUMP: case OP.RPUSH: case OP.RGET: case OP.RLEN: case OP.LPM: case OP.HASH: case OP.BLOOM: case OP.LPM6: case OP.END:
      return name;
    default: return op.imm ? `${name} ${op.imm}` : name;
  }
}
