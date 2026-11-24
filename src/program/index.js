/* A compiled program as a runnable object. compile()/the DSL hand back one of
 * these: it carries the artifacts a loader needs (the bytecode and automaton)
 * and runs through the reference interpreter with `.exec()`.
 *
 *   const p = load(`pattern bot="GPTBot"; filter { if (scan(payload,256)&bot) return rst("x",0); return pass; }`);
 *   p.exec(bytes, { dport: 80, src: "127.0.0.1" });   // -> { verdict: "rst", rule, ruleName, flow }
 *   p.bytes();    // the `programs` map value (Uint8Array)
 *   p.tables();   // the ac_goto / ac_fail / ac_accept automaton
 *
 * `.exec(frame, opts)` takes the frame bytes plus a plain opts object (the
 * 5-tuple context and any carried per-flow state), not a fluent arg-builder: the
 * inputs are a flat, named set, so an object is clearer than chained setters and
 * trivially reusable/spreadable. The returned flow can be passed back as
 * opts.flow to simulate a multi-packet connection.
 */
import { build } from "#/ac.js";
import { serializeProgram } from "#/bytes";
import { machine, V } from "#/interp.js";
import { formatMsg } from "#/program/format.js";

export { formatMsg };

const VNAME = { [V.PASS]: "pass", [V.DROP]: "drop", [V.BAN]: "ban", [V.RST]: "rst" };
const ipToU32 = (s) => s.split(".").reduce((a, o) => ((a << 8) | (Number(o) & 0xff)) >>> 0, 0) >>> 0;

/* "2001:db8::1" -> 128-bit BigInt (handles one "::" run). */
const ip6ToBig = (s) => {
  const [head, tail] = s.split("::");
  const h = head ? head.split(":") : [], t = tail !== undefined ? (tail ? tail.split(":") : []) : null;
  const groups = t === null ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  let v = 0n;
  for (const g of groups) v = (v << 16n) | BigInt(parseInt(g || "0", 16) & 0xffff);
  return v & ((1n << 128n) - 1n);
};
/* "2001:db8::/32" -> { net, mask } as 128-bit BigInt, for `src6 in set6`. */
const cidr6NetMask = (cidr) => {
  const [ip, p = "128"] = String(cidr).split("/");
  const prefix = Number(p);
  const full = (1n << 128n) - 1n;
  const mask = prefix === 0 ? 0n : (full << BigInt(128 - prefix)) & full;
  return { net: ip6ToBig(ip) & full, mask };
};
/* "A.B.C.D/prefix" -> { net, mask } as BigInt (host order), for `src in set`. */
const cidrNetMask = (cidr) => {
  const [ip, p = "32"] = String(cidr).split("/");
  const prefix = Number(p);
  const mask = prefix === 0 ? 0n : (prefix >= 32 ? 0xffffffffn : (0xffffffffn << BigInt(32 - prefix)) & 0xffffffffn);
  return { net: BigInt(ipToU32(ip)) & 0xffffffffn, mask };
};

export class Program {
  /* `compiled` is the object compile()/compileAst() returns on success. */
  constructor(compiled) {
    if (!compiled.ok) throw new Error("cannot wrap a failed compile: " + JSON.stringify(compiled.errors));
    this.program = compiled.program;
    this.patterns = compiled.patterns;
    this.rules = compiled.rules;
    this.listing = compiled.listing;
    this.nocase = compiled.nocase;
    this.regex = compiled.regex ?? null;
    this.warnings = compiled.warnings ?? []; // { line, text }: it compiled, and may not do what was meant
    this.consoleFormats = compiled.consoleFormats ?? [];
    this.lookupTables = compiled.lookupTables ?? []; // declared `table`s: { name, base, size }
    this.sampleTags = compiled.sampleTags ?? [""]; // sample() tag names, by id (0 = untagged)
    this.emits = compiled.emits ?? [];   // emit() events: { id, name, arity }, by id
    this.knobs = compiled.knobs ?? [];   // knob name by slot (slot = index)
    this.knobDefaults = compiled.knobDefaults ?? []; // seeded initial value by slot
    this.knobStrs = compiled.knobStrs ?? []; // string-knob name by slot
    this.asm = compiled.asm;
    this._run = null;
  }

  /** The ac_goto / ac_fail / ac_accept tables for this program's patterns. */
  tables() { return (this._tables ??= build(this.patterns, this.nocase)); }

  /** The `programs` map value (Uint8Array), optionally stamped with a gen. */
  bytes(gen = 0) { return serializeProgram(this.program, gen); }

  /* The cell space as the interpreter reads it: `given` is { name: values } for
   * the declared tables, as the loader's setTable takes them. */
  _cells(given) {
    if (!this.lookupTables.length) return null;
    return (index) => {
      const t = this.lookupTables.find((x) => index >= x.base && index < x.base + x.size);
      return t ? given?.[t.name]?.[index - t.base] ?? 0 : 0;
    };
  }

  /** Run the program through the reference interpreter.
   *  frame: the bytes; opts: { payload=0, proto=6, dport=80, sport, src|saddr, dst|daddr, flow, set } */
  exec(frame, opts = {}) {
    this._run ??= machine({ asm: { program: this.program }, tables: this.tables(), regex: this.regex });
    const { payload = 0, proto = 6, dport = 80, flow = {} } = opts;
    /* A standing source ban is enforced at the kernel entry, before the program
     * runs: every later packet from that address is dropped, whatever it holds. */
    if (opts.source?.banned && !opts.shadow)
      return { verdict: "drop", code: V.DROP, rule: 0, ruleName: undefined, banned: true, flow, source: opts.source, console: [] };
    const saddr = opts.src != null ? ipToU32(opts.src) : (opts.saddr ?? 0);
    const daddr = opts.dst != null ? ipToU32(opts.dst) : (opts.daddr ?? 0); /* only flow.hash reads it */
    const set = (opts.set ?? []).map(cidrNetMask); /* `src in set` membership, host-modelled */
    const buf = frame instanceof Uint8Array ? frame : Uint8Array.from(frame ?? []);
    const r = this._run(buf, payload, { ac: 0, mask: 0n, ...flow }, { proto, dport, sport: opts.sport ?? 0, saddr, daddr, set, hashset: opts.hashset ?? [], bloom: opts.bloom ?? [],
      src6: opts.src6 != null ? ip6ToBig(opts.src6) : 0n, set6: (opts.set6 ?? []).map(cidr6NetMask),
      bucket: opts.bucket, source: opts.source ?? null, now: opts.now ?? 0n, argv: opts.argv ?? [], shadow: !!opts.shadow,
      cells: this._cells(opts.tables), kv: opts.kv ?? null,
      knobs: this.knobs.map((name, slot) => opts.knobs?.[name] ?? this.knobDefaults[slot] ?? 0),
      knobStrs: this.knobStrs.map((name) => opts.knobStrs?.[name] ?? "") });
    const consoleOut = (r.consoleMsgs ?? []).map((m) => formatMsg(this.consoleFormats[m.fmtid] ?? "", m.nums, m.strs));
    if (opts.onConsole) for (const line of consoleOut) opts.onConsole(line);
    const events = (r.emitted ?? []).map((e) => ({ name: this.emits[e.id]?.name, values: e.nums }));
    if (opts.onEmit) for (const e of events) opts.onEmit(e);
    const samples = (r.sampled ?? []).map((x) => ({ tag: this.sampleTags[x.tag] || null, data: x.data, wireLen: x.wireLen }));
    if (opts.onSample) for (const x of samples) opts.onSample(x);
    const u32ToIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
    return { events, samples, dnat: r.dnat ? { ip: u32ToIp(r.dnat.ip), port: r.dnat.port } : null, verdict: VNAME[r.verdict] ?? "pass", code: r.verdict, would: r.would != null ? VNAME[r.would] : undefined, rule: r.rule, ruleName: this.rules[r.rule]?.name, flow: r.flow, source: r.source, console: consoleOut };
  }
}

export const toProgram = (compiled) => new Program(compiled);
