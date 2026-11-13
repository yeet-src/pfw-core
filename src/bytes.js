/* The compiled program as the bytes that actually go into the kernel
 * maps: the `programs` value serialized exactly as `struct pfw_prog`
 * (bpf/include/pfw.h), plus the Aho-Corasick entries for the ac_* maps.
 *
 * Layout (little-endian, x86 BPF), total 5392 bytes:
 *   u32 nops, npats, nocase, gen, reasm, _pad             @0   24 bytes
 *   struct pfw_op  ops[64]   { u32 code; u32 reg; u64 imm } @24  1024 bytes
 *   struct pfw_pat pats[64]  { u32 len; u8 bytes[64] }      @1048 4352 bytes
 */
import { build } from "#/src/ac.js";
import { compile } from "#/src/clang.js";
import { LIMITS } from "#/src/isa.js";

const OPS = LIMITS.MAX_OPS; // 64
const PATS = LIMITS.MAX_PATS; // 64
const PATCAP = LIMITS.PAT_CAP; // 64
const OP_SIZE = 16;
const PAT_SIZE = 4 + PATCAP; // 68
const OPS_AT = 32; // after nops,npats,nocase,gen,reasm,reasm_dport,decode,_pad
const PATS_AT = OPS_AT + OPS * OP_SIZE; // 1048
const TOTAL = PATS_AT + PATS * PAT_SIZE; // 5392

/** Serialize a compiled program into its `struct pfw_prog` bytes. */
export function serializeProgram(program, gen = 0) {
  const buf = new Uint8Array(TOTAL);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, program.nops >>> 0, true);
  dv.setUint32(4, program.npats >>> 0, true);
  dv.setUint32(8, program.nocase >>> 0, true);
  dv.setUint32(12, gen >>> 0, true);
  dv.setUint32(16, (program.reasm ?? 0) >>> 0, true);
  dv.setUint32(20, (program.reasm_dport ?? 0) >>> 0, true); // reasm_dport
  dv.setUint32(24, (program.decode ?? 0) >>> 0, true); // decode
  dv.setUint32(28, 0, true); // _ppad2
  for (let i = 0; i < OPS; i++) {
    const op = program.ops[i];
    const b = OPS_AT + i * OP_SIZE;
    if (!op) continue;
    dv.setUint32(b, op.code >>> 0, true);
    dv.setUint32(b + 4, op.reg >>> 0, true);
    dv.setBigUint64(b + 8, BigInt(op.imm ?? 0), true);
  }
  for (let i = 0; i < PATS; i++) {
    const p = program.pats[i];
    const b = PATS_AT + i * PAT_SIZE;
    if (!p) continue;
    dv.setUint32(b, p.len >>> 0, true);
    for (let j = 0; j < PATCAP; j++) buf[b + 4 + j] = (p.bytes[j] ?? 0) & 0xff;
  }
  return buf;
}

/* xxd-style, with repeated 16-byte rows collapsed to `*`. */
function hexdump(bytes, start = 0) {
  const lines = [];
  let starred = false;
  let prev = null;
  for (let off = 0; off < bytes.length; off += 16) {
    const row = bytes.subarray(off, off + 16);
    const key = row.join(",");
    if (key === prev && off + 16 < bytes.length) {
      if (!starred) {
        lines.push("*");
        starred = true;
      }
      continue;
    }
    starred = false;
    prev = key;
    let hex = "";
    let ascii = "";
    for (let i = 0; i < 16; i++) {
      if (i === 8) hex += " ";
      if (i < row.length) {
        hex += row[i].toString(16).padStart(2, "0") + " ";
        const c = row[i];
        ascii += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
      } else {
        hex += "   ";
      }
    }
    lines.push(`${(start + off).toString(16).padStart(4, "0")}  ${hex} |${ascii}|`);
  }
  return lines.join("\n");
}

const ch = (b) => (b >= 32 && b < 127 ? `'${String.fromCharCode(b)}'` : `0x${b.toString(16).padStart(2, "0")}`);

/* What a byte at this offset belongs to, so the dump can be coloured by
 * meaning: header, an active op, a pattern's length or content, or
 * zero padding. */
function classify(off, program) {
  if (off < OPS_AT) return "hdr";
  if (off < PATS_AT) return off < OPS_AT + program.nops * OP_SIZE ? "op" : "pad";
  const rel = off - PATS_AT;
  const slot = Math.floor(rel / PAT_SIZE);
  const fo = rel % PAT_SIZE;
  if (slot >= program.npats) return "pad";
  if (fo < 4) return "plen";
  return fo - 4 < (program.pats[slot]?.len ?? 0) ? "pbyte" : "pad";
}

/** A structured model for a coloured hexdump of the program bytes plus
 * the automaton entries. { ok, errors, header, hex:[rows], ac:[lines] }.
 * A row is { off, cells:[{h,cls}], ascii:[{c,cls}] } or { star:true }. */
export function mapModel(source) {
  const c = compile(source);
  if (!c.ok) return { ok: false, errors: c.errors, header: "", hex: [], ac: [] };

  const bytes = serializeProgram(c.program, 0);
  const hex = [];
  let prev = null;
  let starred = false;
  for (let off = 0; off < bytes.length; off += 16) {
    const row = bytes.subarray(off, off + 16);
    const key = row.join(",");
    if (key === prev && off + 16 < bytes.length) {
      if (!starred) {
        hex.push({ star: true });
        starred = true;
      }
      continue;
    }
    starred = false;
    prev = key;
    const cells = [];
    const ascii = [];
    for (let i = 0; i < 16; i++) {
      if (i < row.length) {
        const cls = classify(off + i, c.program);
        const b = row[i];
        cells.push({ h: b.toString(16).padStart(2, "0"), cls: b === 0 && cls === "pad" ? "zero" : cls });
        ascii.push(b >= 32 && b < 127 ? { c: String.fromCharCode(b), cls } : { c: ".", cls: "zero" });
      } else {
        cells.push({ h: "  ", cls: "zero" });
      }
    }
    hex.push({ off: off.toString(16).padStart(4, "0"), cells });
    hex[hex.length - 1].ascii = ascii;
  }

  const ac = [];
  const acc = build(c.patterns, c.nocase);
  ac.push({ cls: "head", text: `ac_goto — ${acc.edges.length} trie edges (state·256+byte → next)` });
  for (const [k, next] of acc.edges) ac.push({ cls: "entry", text: `  state ${k >> 8} ${ch(k & 0xff)} → ${next}` });
  ac.push({ cls: "head", text: `ac_fail — ${acc.fails.length} failure links` });
  for (const [s, f] of acc.fails) ac.push({ cls: "entry", text: `  ${s} → ${f}` });
  ac.push({ cls: "head", text: `ac_accept — ${acc.accepts.length} accept masks` });
  for (const [s, mask] of acc.accepts) {
    const names = c.patterns.filter((p) => (mask >> BigInt(p.id)) & 1n).map((p) => p.name);
    ac.push({ cls: "entry", text: `  state ${s} → 0x${mask.toString(16)} (${names.join(", ")})` });
  }
  if (!acc.edges.length) ac.push({ cls: "entry", text: "  (no patterns)" });

  return {
    ok: true,
    errors: [],
    header: `programs[gen] — struct pfw_prog, ${TOTAL} bytes · nops=${c.program.nops} npats=${c.program.npats} nocase=${c.program.nocase}`,
    hex,
    ac,
  };
}

/** The full map dump for the Bytes tab. { ok, errors, text }. */
export function mapDump(source) {
  const c = compile(source);
  if (!c.ok) return { ok: false, errors: c.errors, text: c.errors.map((e) => `; line ${e.line}: ${e.text}`).join("\n") };

  const bytes = serializeProgram(c.program, 0);
  const used = Math.min(PATS_AT + c.program.npats * PAT_SIZE, TOTAL);
  const sections = [];

  sections.push(
    `; programs[gen]  —  struct pfw_prog, ${TOTAL} bytes`,
    `; nops=${c.program.nops} npats=${c.program.npats} nocase=${c.program.nocase} gen=<stamped at apply>`,
    hexdump(bytes),
    "",
  );

  const ac = build(c.patterns, c.nocase);
  sections.push(`; ac_goto  —  ${ac.edges.length} trie edges  (state*256+byte -> next state, u16)`);
  for (const [k, next] of ac.edges) sections.push(`;   state ${k >> 8} ${ch(k & 0xff)} -> ${next}`);
  sections.push("", `; ac_fail  —  ${ac.fails.length} failure links  (state -> state, u16)`);
  for (const [s, f] of ac.fails) sections.push(`;   ${s} -> ${f}`);
  sections.push("", `; ac_accept  —  ${ac.accepts.length} accept masks  (state -> u64 pattern bits)`);
  for (const [s, mask] of ac.accepts) {
    const names = c.patterns.filter((p) => (mask >> BigInt(p.id)) & 1n).map((p) => p.name);
    sections.push(`;   state ${s} -> 0x${mask.toString(16)}  (${names.join(", ")})`);
  }
  if (!ac.edges.length) sections.push("; (no patterns)");

  return { ok: true, errors: [], text: sections.join("\n") };
}
