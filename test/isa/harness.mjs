/* ISA conformance harness. Each case is a *vector*: a small subject program, an
 * environment, and the machine state docs/isa/ says it must leave behind —
 *
 *   t("add_i wraps mod 2^64", { asm: `${li("0xffffffffffffffff")}\nadd $2, %cur`, cur: 1 });
 *
 * State is observed ONLY through the verdict: for each expectation the harness
 * appends a probe epilogue to the subject ("rst iff %cur == E", "rst iff ZF", …)
 * and runs it once. Nothing reaches into the interpreter, so a vector is a pure
 * (bytecode, environment, verdict) triple — the same vectors can later be
 * replayed against the kernel VM, which exposes nothing but verdicts either.
 *
 * A vector:
 *   asm      assembly text for the subject (optional)
 *   ops      raw ops appended after `asm`: [code, reg = 0, imm = 0n]; `imm` may
 *            be a function of the op's own pc. For bytecode the assembler
 *            refuses to emit (backward jumps, out-of-range register indices…).
 *   frame    Uint8Array | string (latin1) — the packet bytes (default 64 zeros)
 *   payload  %payload / initial %cur (default 0)
 *   flow     per-flow state at entry;  opts: the interpreter's run options
 *   packets  run the subject over this many packets of one connection, threading
 *            the flow and source state through; expectations describe the LAST
 *            one (default 1). How deferred state writes become visible.
 *   clock    [now, …] in ns, one per packet (implies `packets`), for `rate`
 *   -- expectations (any subset; the subject must fall off its end for all but
 *      verdict/rule, since the probe runs after it) --
 *   cur      %cur at the end            regs   { name: value } for any register
 *   zf, cf, ff  the flags               verdict / rule  the subject's own verdict
 *   frameOut the packet bytes afterwards (string | Uint8Array) — redact/replace
 *   console  the console messages emitted: [{ fmtid, nums, strs }]
 *   emitted  the typed events emitted: [{ id, nums }]
 *   dnat     where the packet was steered: { ip, port } (ip a host-order u32), or null
 *            (these two are host-side observations: the kernel shows them on
 *            the wire and in the event stream, not in the verdict)
 *   rejects  a RegExp: the assembler must refuse `asm` with a matching error
 *   -- --
 *   xfail    "reason": the reference interpreter is known to diverge from the
 *            spec here. The case passes while the vector fails, and fails as
 *            soon as it starts passing, so the marker cannot go stale.
 *
 * Not a test module itself (no `.test.` suffix). */
import { assemble } from "#/asm";
import { opText } from "#/builder";
import { build } from "#/ac.js";
import { machine, V } from "#/interp.js";
import { OP, OP_NAME, REG } from "#/isa.js";

export { OP, REG, V };

const U64 = (1n << 64n) - 1n;
const PROBE_RULE = 63;
const u64 = (v) => BigInt(v) & U64;
const hex = (v) => "0x" + u64(v).toString(16);
const show = (u8) => JSON.stringify(String.fromCharCode(...u8));
const vname = (v) => Object.keys(V).find((k) => V[k] === v)?.toLowerCase() ?? String(v);

/* Latin-1 string → bytes (so "\xff" is one byte, unlike TextEncoder). */
export const bytes = (s) => Uint8Array.from(s, (ch) => ch.charCodeAt(0) & 0xff);
/* Load an immediate into %cur — the ISA has no load-immediate op. */
export const li = (n) => `and $0, %cur\nadd $${n}, %cur`;

/* Probes: ops appended at pc `n` that end in RST(PROBE_RULE) iff the condition holds. */
const probeEq = (n, want) => [
  { code: OP.CMP_I, reg: 0, imm: u64(want) },
  { code: OP.JNE, reg: 0, imm: BigInt(n + 3) },
  { code: OP.RST, reg: PROBE_RULE, imm: 0n },
  { code: OP.PASS, reg: 0, imm: 0n },
];
const probeFlag = (n, jcc) => [
  { code: jcc, reg: 0, imm: BigInt(n + 2) },
  { code: OP.PASS, reg: 0, imm: 0n },
  { code: OP.RST, reg: PROBE_RULE, imm: 0n },
];
const FLAG_JCC = { zf: OP.JE, cf: OP.JB, ff: OP.JF };

function buildSubject(v) {
  let program = { ops: [], pats: [], nocase: 0 }, patterns = [], rules = [], nocase = false;
  if (v.asm !== undefined) {
    const a = assemble(v.asm);
    const errors = a.errors.filter((e) => !(v.ops && e.text === "empty program"));
    if (errors.length) throw new Error("assemble: " + errors.map((e) => `line ${e.line}: ${e.text}`).join("; "));
    ({ program, patterns, rules, nocase } = a);
  }
  const ops = [...program.ops];
  for (const [code, reg = 0, imm = 0n] of v.ops ?? []) {
    const pc = ops.length;
    ops.push({ code, reg, imm: u64(typeof imm === "function" ? imm(pc) : imm) });
  }
  return { ops, pats: program.pats, nocase: program.nocase, patterns, rules, tables: build(patterns, nocase) };
}

/* Run the subject over the vector's packets — the last one with `epilogue`
 * appended — threading flow and source state from each packet into the next. */
function execute(subject, epilogue, v) {
  const prog = (extra) => machine({ asm: { program: { ops: [...subject.ops, ...extra], pats: subject.pats, nocase: subject.nocase } }, tables: subject.tables });
  const packets = v.clock?.length ?? v.packets ?? 1;
  const opts = structuredClone(v.opts ?? {});
  let flow = { ac: 0, mask: 0n, ...structuredClone(v.flow ?? {}) }, r, frame;
  for (let i = 0; i < packets; i++) {
    frame = typeof v.frame === "string" ? bytes(v.frame) : v.frame ? Uint8Array.from(v.frame) : new Uint8Array(64);
    if (v.clock) opts.now = BigInt(v.clock[i]);
    r = prog(i === packets - 1 ? epilogue : [])(frame, v.payload ?? 0, flow, opts);
    flow = r.flow;
    if (opts.source) opts.source = r.source;
  }
  return { ...r, frame };
}

function listing(subject) {
  return subject.ops.map((op, pc) => {
    let text;
    try { text = opText(op, subject.patterns, subject.rules); } catch { text = `${OP_NAME[op.code] ?? "op" + op.code} reg=${op.reg} imm=${hex(op.imm)}`; }
    return `    ${String(pc).padStart(3)}  ${text}`;
  }).join("\n");
}

/* Every expectation the vector fails, as text (empty = conforms). */
function check(subject, v) {
  const bad = [], n = subject.ops.length;
  const probe = (what, epilogue, want) => {
    const r = execute(subject, epilogue, v);
    const verdict = r.would ?? r.verdict; /* shadow mode reports the probe's rst as `would` */
    if (r.rule !== PROBE_RULE && verdict !== V.PASS) { bad.push(`${what}: the subject ended in its own verdict (${vname(verdict)}) before the probe ran`); return; }
    if ((verdict === V.RST) !== want) bad.push(what);
  };
  if (v.verdict !== undefined || v.rule !== undefined) {
    const r = execute(subject, [], v);
    if (v.verdict !== undefined && r.verdict !== v.verdict) bad.push(`verdict: want ${vname(v.verdict)}, got ${vname(r.verdict)}`);
    if (v.rule !== undefined && r.rule !== v.rule) bad.push(`rule: want ${v.rule}, got ${r.rule}`);
  }
  if (v.frameOut !== undefined) {
    const want = typeof v.frameOut === "string" ? bytes(v.frameOut) : v.frameOut, got = execute(subject, [], v).frame;
    if (got.length !== want.length || got.some((b, i) => b !== want[i])) bad.push(`frame: want ${show(want)}, got ${show(got)}`);
  }
  if (v.dnat !== undefined) {
    const got = JSON.stringify(execute(subject, [], v).dnat ?? null), want = JSON.stringify(v.dnat);
    if (got !== want) bad.push(`dnat: want ${want}, got ${got}`);
  }
  if (v.emitted !== undefined) {
    const shape = (list) => JSON.stringify((list ?? []).map((e) => ({ id: e.id, nums: (e.nums ?? []).map((n) => u64(n).toString()) })));
    const got = shape(execute(subject, [], v).emitted), want = shape(v.emitted);
    if (got !== want) bad.push(`emitted: want ${want}, got ${got}`);
  }
  if (v.console !== undefined) {
    const norm = (ms) => JSON.stringify(ms.map((m) => ({ fmtid: m.fmtid, nums: (m.nums ?? []).map((n) => hex(n)), strs: m.strs ?? [] })));
    const got = norm(execute(subject, [], v).consoleMsgs), want = norm(v.console);
    if (got !== want) bad.push(`console: want ${want}, got ${got}`);
  }
  if (v.cur !== undefined) probe(`%cur != ${hex(v.cur)}`, probeEq(n, v.cur), true);
  for (const [name, want] of Object.entries(v.regs ?? {})) {
    if (!(name in REG)) throw new Error(`no register %${name}`);
    probe(`%${name} != ${hex(want)}`, [{ code: OP.MOV_RC, reg: REG[name], imm: 0n }, ...probeEq(n + 1, want)], true);
  }
  for (const f of ["zf", "cf", "ff"]) {
    if (v[f] !== undefined) probe(`${f.toUpperCase()} is ${v[f] ? "clear" : "set"}, want ${v[f] ? "set" : "clear"}`, probeFlag(n, FLAG_JCC[f]), !!v[f]);
  }
  return bad;
}

/* isa(group) → t(name, vector): register one case per vector. t.covers(...ops)
 * adds a case asserting this file's subjects executed each of those opcodes
 * at least once, so a category file cannot quietly lose an instruction. */
export function isa(group) {
  const used = new Set();
  const t = (name, v) => {
    let subject, buildError;
    try { subject = buildSubject(v); for (const op of subject.ops) used.add(op.code); } catch (e) { buildError = e; }
    yeet.test(`${group}: ${name}`, () => {
      if (v.rejects) {
        if (!buildError) throw new Error(`assembled, but should be rejected (${v.rejects})`);
        if (!v.rejects.test(buildError.message)) throw new Error(`rejected for the wrong reason: ${buildError.message}`);
        return;
      }
      if (buildError) throw buildError;
      let bad;
      try { bad = check(subject, v); } catch (e) { bad = [`threw: ${e.message}`]; }
      if (v.xfail) {
        if (!bad.length) throw new Error(`now conforms — drop the xfail marker (was: ${v.xfail})`);
        return;
      }
      if (bad.length) throw new Error(`${bad.join("; ")}\n${listing(subject)}`);
    });
  };
  t.covers = (...codes) => yeet.test(`${group}: covers ${codes.length} opcodes`, () => {
    const miss = codes.filter((c) => !used.has(c)).map((c) => OP_NAME[c] ?? c);
    if (miss.length) throw new Error("no vector for: " + miss.join(", "));
  });
  return t;
}
