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
import { serializeProgram } from "#/bytes.js";
import { machine, V } from "#/interp.js";

const VNAME = { [V.PASS]: "pass", [V.DROP]: "drop", [V.BAN]: "ban", [V.RST]: "rst" };
const ipToU32 = (s) => s.split(".").reduce((a, o) => ((a << 8) | (Number(o) & 0xff)) >>> 0, 0) >>> 0;
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
    this.asm = compiled.asm;
    this._run = null;
  }

  /** The ac_goto / ac_fail / ac_accept tables for this program's patterns. */
  tables() { return (this._tables ??= build(this.patterns, this.nocase)); }

  /** The `programs` map value (Uint8Array), optionally stamped with a gen. */
  bytes(gen = 0) { return serializeProgram(this.program, gen); }

  /** Run the program through the reference interpreter.
   *  frame: the bytes; opts: { payload=0, proto=6, dport=80, src|saddr, flow, set } */
  exec(frame, opts = {}) {
    this._run ??= machine({ asm: { program: this.program }, tables: this.tables(), regex: this.regex });
    const { payload = 0, proto = 6, dport = 80, flow = {} } = opts;
    const saddr = opts.src != null ? ipToU32(opts.src) : (opts.saddr ?? 0);
    const set = (opts.set ?? []).map(cidrNetMask); /* `src in set` membership, host-modelled */
    const buf = frame instanceof Uint8Array ? frame : Uint8Array.from(frame ?? []);
    const r = this._run(buf, payload, { ac: 0, mask: 0n, ...flow }, { proto, dport, saddr, set, hashset: opts.hashset ?? [] });
    return { verdict: VNAME[r.verdict] ?? "pass", code: r.verdict, rule: r.rule, ruleName: this.rules[r.rule]?.name, flow: r.flow };
  }
}

export const toProgram = (compiled) => new Program(compiled);
