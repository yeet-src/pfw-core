/* The program Builder: an LLVM-IRBuilder-style emitter that constructs ops,
 * resolves labels, allocates scratch registers, and interns patterns and rules —
 * the single op-construction core both front-ends target. The assembler (asm)
 * parses text into Builder calls; the pfw-C compiler (clang) emits Builder calls
 * directly. Neither goes through an assembly-text round-trip; the text form is
 * only ever *output* (disassembled from the ops by `opText`, in ./optext.js).
 *
 *   const b = new Builder();
 *   b.movToCur(REG.saddr); b.cidr(net, prefix); b.je("hit"); b.pass();
 *   b.label("hit"); b.rst(b.ruleId("lo"), 0n);
 *   const { program, patterns, rules, listing, errors } = b.finalize();
 *
 * Register operands may be a physical register index or a virtual register from
 * b.vreg() (for compiler locals); finalize() maps the virtuals onto the sixteen
 * scratch registers by live range. Jumps take a label name, resolved (forward
 * only) at finalize. Methods throw BuildError on misuse; callers that parse
 * untrusted text (the assembler) catch per line.
 */
import { LIMITS, LOAD_BE, OP, REG } from "#/isa.js";
import { opText } from "#/builder/optext.js";

export { opText };

export class BuildError extends Error {}
const fail = (m) => { throw new BuildError(m); };

const VREG_BASE = 1 << 20; // reg values >= this are virtual (allocated at finalize)

/* The compiler's own temporaries are named `__<kind><n>`. When the registers
 * run out, the error says which construct each one belongs to: "held by q"
 * helps nobody when q holds one register and a `frame` walk holds five. */
const TEMP_KINDS = [
  [/^__f[eltdv]\d/, "`frame` walk"], [/^__seq\d/, "`seq(...)`"], [/^__sw\d/, "`switch`"], [/^__m\d/, "`match`"],
  [/^__cmp\d/, "comparison"], [/^__pk\d/, "`dnat`/`rate` argument"], [/^__ar\d/, "arithmetic expression"], [/^__rd\d/, "`be24(...)` read"], [/^__ca\d/, "subroutine call"], [/^__a\d/, "arithmetic expression"],
];
const tempKind = (name) => TEMP_KINDS.find(([re]) => re.test(name))?.[1] ?? "temporary";
const SCRATCH = [REG.s0, REG.s1, REG.s2, REG.s3, REG.s4, REG.s5, REG.s6, REG.s7, REG.s8, REG.s9, REG.s10, REG.s11, REG.s12, REG.s13, REG.s14, REG.s15];

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
  mulReg(reg) { return this.op(OP.MUL_R, reg, 0n, { regSlot: true }); }
  modReg(reg) { return this.op(OP.MOD_R, reg, 0n, { regSlot: true }); }

  // ---- immediate arithmetic / compare ----
  addImm(n) { return this.op(OP.ADD_I, 0, n); }
  subImm(n) { return this.op(OP.SUB_I, 0, n); }
  andImm(n) { return this.op(OP.AND_I, 0, n); }
  orImm(n) { return this.op(OP.OR_I, 0, n); }
  shlImm(n) { return this.op(OP.SHL_I, 0, n); }
  shrImm(n) { return this.op(OP.SHR_I, 0, n); }
  cmpImm(n) { return this.op(OP.CMP_I, 0, n); }
  mulImm(n) { return this.op(OP.MUL_I, 0, n); }
  modImm(n) { return this.op(OP.MOD_I, 0, n); }
  fhash() { return this.op(OP.FHASH); } // cur = the flow hash
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
  scan(len, fresh = false) { return this.op(OP.SCAN, fresh ? 1 : 0, len); } // runs AC (literals) + the regex DFA, both into %m; fresh (reg = 1) clears %m and the automaton first
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
  sload(scope = 0) { return this.op(OP.SLOAD, scope); } // reg = scope: 0 this flow, 1 the source address
  sstore(state, ttl, scope = 0) { return this.op(OP.SSTORE, Number(ttl), (BigInt(state) & 0xffffffffn) | (BigInt(scope & 1) << 32n)); } // reg = ttl, imm = state | scope<<32
  bump(scope = 0) { return this.op(OP.BUMP, scope); } // reg = scope
  rpush() { return this.op(OP.RPUSH); }
  rget() { return this.op(OP.RGET); }
  rlen() { return this.op(OP.RLEN); }
  // ---- packet rewrite (reg = match pattern id; imm = fill byte / replacement pattern id) ----
  // isRe marks `pat` a regex accept-bit (fixed-length match, len=rlen) rather than a literal pattern id.
  redact(pat, fill, isRe = false, rlen = 0) { return this.op(OP.REDACT, (pat & 0x3fff) | (isRe ? 0x8000 : 0), (BigInt(fill) & 0xffn) | (BigInt(rlen & 0x7f) << 8n)); }
  replace(pat, repl, isRe = false, rlen = 0) { return this.op(OP.REPLACE, (pat & 0x3fff) | (isRe ? 0x8000 : 0), (BigInt(repl) & 0x3fn) | (BigInt(rlen & 0x7f) << 8n)); }
  // DNAT: rewrite dst IPv4 (host-order u32) + port into imm (ip low 32, port bits 32..47).
  dnat(ip, port) { return this.op(OP.DNAT, 0, (BigInt(ip >>> 0) & 0xffffffffn) | (BigInt(port & 0xffff) << 32n)); }
  dnatCur() { return this.op(OP.DNAT, 1); } // the target is %cur: ip low 32, port bits 32..47; ip 0 steers nothing
  lpm() { return this.op(OP.LPM); } // ZF = %cur is in the lpm CIDR set
  hash() { return this.op(OP.HASH); } // ZF = %cur is a key in the hashset
  kvget(def = 0n) { return this.op(OP.KVGET, 0, BigInt(def)); } // cur = kv[cur], or `def` (and a fault) when the key is absent
  bloom() { return this.op(OP.BLOOM); } // ZF = %cur is (probably) in the bloom filter
  lpm6() { return this.op(OP.LPM6); } // ZF = the IPv6 source is in the lpm6 CIDR set
  redirect(ifindex) { return this.op(OP.REDIRECT, 0, BigInt(ifindex >>> 0)); } // forward the packet out ifindex (XDP_REDIRECT)
  rate(perSec, burst, scope = 0) { return this.op(OP.RATE, scope, (BigInt(perSec >>> 0) & 0xffffffffn) | (BigInt(burst >>> 0) << 32n)); } // ZF = over the token-bucket limit
  rateCur(scope = 0) { return this.op(OP.RATE, (scope & 1) | 2); } // the same, with rate (low 32) and burst (high 32) taken from %cur
  arg(idx, def = 0) { return this.op(OP.ARG, 0, (BigInt(idx & 0xffff) << 32n) | (BigInt(def >>> 0) & 0xffffffffn)); } // cur = args[idx] ?? def
  argc() { return this.op(OP.ARGC); } // cur = number of runtime args set
  knob(slot) { return this.op(OP.KNOB, 0, BigInt(slot)); } // cur = knobs[slot] (live host-set control)
  tload(base, size) { return this.op(OP.TLOAD, 0, (BigInt(base >>> 0) & 0xffffffffn) | (BigInt(size >>> 0) << 32n)); } // cur = table cell at index cur (0 + fault past `size`)
  knobhas(slot) { return this.op(OP.KNOBHAS, 0, BigInt(slot)); } // ZF = string knob[slot] occurs in the payload
  farg() { return this.op(OP.FARG); } // push cur as the next numeric console/printk format arg
  fargs(cap) { return this.op(OP.FARGS, 0, BigInt(cap)); } // capture a %s string from the packet at cur (up to cap bytes)
  console(fmtid) { return this.op(OP.CONSOLE, 0, BigInt(fmtid)); } // emit a console message (format id) to the host
  emit(id) { return this.op(OP.EMIT, 0, BigInt(id)); } // send the pushed numeric fargs to the host as typed event `id`
  printk(fmtid) { return this.op(OP.PRINTK, 0, BigInt(fmtid)); } // bpf_trace_printk the in-kernel format (id) with the pushed numeric fargs
  push() { return this.op(OP.PUSH); } // push cur onto the data stack
  pop() { return this.op(OP.POP); } // pop the data stack into cur
  call(l) { return this.op(OP.CALL, 0, 0n, { label: l }); } // push return pc, jump to label (subroutine)
  ret() { return this.op(OP.RET); } // return from a subroutine (pop pc)

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
      else if (target <= pc && op.code !== OP.CALL) errors.push({ line: op.line, text: `\`${op.label}\` is behind the jump; jumps go forward only` });
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

  /* Mark [from, to) as a subroutine body (the compiler calls this around each
   * `fn`). The allocator needs it: see _allocate. */
  fnRegion(from, to) { (this.fnRegions ??= []).push([from, to]); return this; }

  /* Linear-scan allocation of virtual registers onto the scratch registers, by
   * live range (forward-only ISA ⇒ a vreg is live from first to last mention).
   *
   * A live range is a span of op INDICES, and a subroutine's body sits elsewhere
   * in the program than its call site. So a caller's local that is live across a
   * `call` does not overlap the callee's locals by index, yet both are live at
   * once at run time — sharing a register lets the callee overwrite the caller.
   * Two passes keep them apart: subroutine locals that do not themselves span a
   * call are placed first; then every vreg that IS live across a call is kept
   * off every register those used. */
  _allocate(errors) {
    const first = new Map(), last = new Map();
    this.ops.forEach((op, i) => {
      if (op.regSlot && op.reg >= VREG_BASE) { if (!first.has(op.reg)) first.set(op.reg, i); last.set(op.reg, i); }
    });
    const calls = [];
    this.ops.forEach((op, i) => { if (op.code === OP.CALL) calls.push(i); });
    const regions = this.fnRegions ?? [];
    const inFn = (i) => regions.some(([a, b]) => i >= a && i < b);
    const crosses = (iv) => calls.some((c) => iv.start < c && c < iv.end);
    const intervals = [...first.keys()].map((v) => ({ v, start: first.get(v), end: last.get(v) })).sort((a, b) => a.start - b.start || a.end - b.end);
    const phys = new Map();
    const scan = (ivs, banned) => {
      let free = SCRATCH.map((_, i) => i);
      const active = [];
      for (const iv of ivs) {
        for (let i = active.length - 1; i >= 0; i--) if (active[i].end < iv.start) { free.push(phys.get(active[i].v)); active.splice(i, 1); }
        free.sort((a, b) => a - b);
        const k = free.findIndex((r) => !(iv.cross && banned.has(r)));
        if (k < 0) {
          const who = this.vregs[iv.v - VREG_BASE];
          const isTemp = (v) => !v?.name || v.name.startsWith("__");
          const holders = active.map((a) => this.vregs[a.v - VREG_BASE]);
          const locals = holders.filter((v) => !isTemp(v)).map((v) => `\`${v.name}\``);
          /* Temporaries, grouped by the construct that made them. */
          const groups = new Map();
          for (const v of holders.filter(isTemp)) {
            const key = `the ${tempKind(v?.name ?? "")}${v?.line ? ` at line ${v.line}` : ""}`;
            groups.set(key, (groups.get(key) ?? 0) + 1);
          }
          const parts = [
            ...(locals.length ? [`${locals.length} by your locals (${locals.join(", ")})`] : []),
            ...[...groups].map(([what, n]) => `${n} by ${what}`),
          ];
          const want = isTemp(who) ? `the ${tempKind(who?.name ?? "")}${who?.line ? ` at line ${who.line}` : ""}` : `\`${who.name}\``;
          const why = iv.cross && banned.size ? ` (it is live across a subroutine call, so it cannot share the ${banned.size} register(s) subroutines use)` : "";
          errors.push({ line: who?.line ?? 0, user: true, text: `too many locals live at once: ${want} needs a register, but all ${SCRATCH.length} are in use${parts.length ? `: ${parts.join(", ")}` : ""}${why}` });
          phys.set(iv.v, 0); active.push(iv); continue;
        }
        phys.set(iv.v, free.splice(k, 1)[0]);
        active.push(iv);
      }
    };
    const regionOf = (i) => regions.findIndex(([a, b]) => i >= a && i < b); // -1 = the filter body
    for (const iv of intervals) { iv.cross = crosses(iv); iv.region = regionOf(iv.start); iv.callee = iv.region >= 0 && !iv.cross; }
    scan(intervals.filter((iv) => iv.callee), new Set());
    const taken = new Set(intervals.filter((iv) => iv.callee).map((iv) => phys.get(iv.v)));
    /* Call-spanning locals of different bodies can be live together too (outer's
     * local while inner runs, the filter's while outer runs), and their index
     * ranges never overlap either — so each body's set is kept off all the
     * registers taken so far. The filter body goes last, with its ordinary
     * locals, which only compete among themselves. */
    regions.forEach((_, r) => {
      const ivs = intervals.filter((iv) => iv.region === r && iv.cross);
      scan(ivs, taken);
      for (const iv of ivs) taken.add(phys.get(iv.v));
    });
    scan(intervals.filter((iv) => iv.region < 0), taken);
    for (const op of this.ops) if (op.regSlot && op.reg >= VREG_BASE) op.reg = SCRATCH[phys.get(op.reg)];
  }
}
