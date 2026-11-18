/* The kernel side of the VM as an embeddable object: load the XDP interpreter,
 * swap programs into it, steer it live, read what it decided, and take it down.
 *
 *   import { PfwVm } from "pfw-core/loader";
 *   import { load } from "pfw-core";
 *
 *   const vm = new PfwVm({ iface: 2 });
 *   await vm.start();                       // attached; no program yet, so everything passes
 *   await vm.apply(load(source), { knobs: { enforce: 1 } });
 *   vm.onVerdict((e) => console.log(e.verdict, e.rule, e.src));
 *   await vm.setKnob("enforce", 0);         // live, no reload
 *   await vm.apply(load(nextSource));       // atomic swap to a new program
 *   console.log(await vm.stats());
 *   await vm.stop();                        // detached; the hook is free again
 *
 * It runs only inside the yeet runtime (it imports `yeet:bpf`), so it is its own
 * entry point and is NOT re-exported from the package root, which stays loadable
 * under plain node for compiling and simulating.
 *
 * One PfwVm owns the XDP hook of its interface(s): the kernel allows a single
 * XDP program per interface, so a second start() on the same interface — from
 * this object or any other program — fails until the first is stopped.
 */
import { ArrayMap, BloomFilter, BpfObject, DataSec, HashMap, LpmTrie, PercpuArrayMap, RingBuf } from "yeet:bpf";
import { build } from "#/ac.js";
import { compile } from "#/clang";
import { DECIDE_BOUNDS, LIMITS, VERDICT } from "#/isa.js";
import { formatMsg } from "#/program";
import { transformCells } from "#/transform.js";

/* The tail-call stages, by their slot in the `decode_jmp` program array. Every
 * one must be in place before the entry is attached. */
const STAGES = ["pfw_decode", "pfw_match", "pfw_resolve", "pfw_huff", "pfw_transform", "pfw_rewrite", "pfw_hpack"];

/* Maps the loader reads or writes, and the kind yeetd binds each as. */
const MAPS = {
  events: { kind: "ringbuf", btf_struct: "pfw_event" },
  console_ring: { kind: "ringbuf", btf_struct: "pfw_console" },
  programs: { kind: "array" }, ac_goto: { kind: "array" }, ac_fail: { kind: "array" }, ac_accept: { kind: "array" },
  re_goto: { kind: "array" }, re_accept: { kind: "array" }, tt_cells: { kind: "array" },
  knobs: { kind: "array" }, knob_strs: { kind: "array" },
  counters: { kind: "percpu_array" }, decide_hist: { kind: "percpu_array" }, stack: { kind: "percpu_array" },
  flows: { kind: "lru_hash" }, lpm: { kind: "lpm_trie" }, lpm6: { kind: "lpm_trie" },
  hashset: { kind: "hash" }, bloom: { kind: "bloom_filter" },
  "vm.bss": { kind: "data" }, decode_jmp: { kind: "prog_array" },
};

/* Counters in vm.bss worth reporting (all u64). */
const COUNTERS = ["seen", "ran", "passed", "dropped", "rsts", "bans", "enforced", "src_enforced", "shadowed", "faults", "logged",
  "ring_full", "flows_created", "scanned_bytes", "decide_ns", "nat_reversed",
  "reasm_retrans", "reasm_midjoin", "reasm_over", "reasm_slid", "reasm_held", "reasm_trunc",
  "h2_blocks", "h2_raw", "h2_unresolved", "h2_trunc", "h2_failed"];

const BATCH = 512;
const chunks = (xs, n) => { const out = []; for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n)); return out; };
const strBytes = (s, cap) => { const b = Array.from(String(s), (ch) => ch.charCodeAt(0) & 0xff).slice(0, cap); const len = b.length; while (b.length < cap) b.push(0); return { len, b }; };
const ip4 = (bytes) => Array.from(bytes ?? []).slice(0, 4).join(".");
const ip6 = (bytes) => { const b = Array.from(bytes ?? []); const g = []; for (let i = 0; i < 16; i += 2) g.push((((b[i] ?? 0) << 8) | (b[i + 1] ?? 0)).toString(16)); return g.join(":"); };
const cidr4Key = (cidr) => { const [ip, p = "32"] = String(cidr).split("/"); return { prefixlen: Number(p), data: ip.split(".").map((o) => Number(o) & 0xff) }; };
const cidr6Key = (cidr) => {
  const [ip, p = "128"] = String(cidr).split("/");
  const [head, tail] = ip.split("::");
  const h = head ? head.split(":") : [], t = tail !== undefined ? (tail ? tail.split(":") : []) : null;
  const groups = t === null ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  const data = [];
  for (const g of groups) { const n = parseInt(g || "0", 16) & 0xffff; data.push((n >> 8) & 0xff, n & 0xff); }
  return { prefixlen: Number(p), data };
};

/* Anything apply() accepts → the compile result shape. */
function compiled(program) {
  if (typeof program === "string") {
    const c = compile(program);
    if (!c.ok) throw new Error("compile: " + c.errors.map((e) => (e.line ? `line ${e.line}: ` : "") + e.text).join("; "));
    return c;
  }
  if (!program?.program?.ops) throw new TypeError("apply(program): expected a Program, a compile() result, or pfw-C source");
  return program;
}

/* `struct pfw_prog` as the value yeetd lifts into the `programs` map (field
 * order and sizes follow bpf/include/pfw.h). */
function progValue(c, stamp, argv) {
  const p = c.program;
  const { MAX_OPS, MAX_PATS, PAT_CAP, ARGC, FMTS, FMT_CAP } = LIMITS;
  const ops = p.ops.slice(0, MAX_OPS).map((o) => ({ code: o.code >>> 0, reg: o.reg >>> 0, imm: BigInt(o.imm) }));
  while (ops.length < MAX_OPS) ops.push({ code: 0, reg: 0, imm: 0n });
  const pats = p.pats.slice(0, MAX_PATS).map((q) => { const b = q.bytes.slice(0, PAT_CAP); while (b.length < PAT_CAP) b.push(0); return { len: q.len >>> 0, bytes: b }; });
  while (pats.length < MAX_PATS) pats.push({ len: 0, bytes: new Array(PAT_CAP).fill(0) });
  const args = argv.slice(0, ARGC).map((v) => BigInt(v));
  const argc = args.length;
  while (args.length < ARGC) args.push(0n);
  const fmts = [];
  for (let i = 0; i < FMTS; i++) fmts.push(strBytes((c.printkFormats ?? [])[i] ?? "", FMT_CAP - 1).b.concat([0]));
  return {
    nops: p.nops >>> 0, npats: p.npats >>> 0, nocase: p.nocase >>> 0, gen: stamp >>> 0,
    reasm: (p.reasm ?? 0) >>> 0, reasm_dport: (p.reasm_dport ?? 0) >>> 0, decode: (p.decode ?? 0) >>> 0,
    transform_table: (p.transform_table ?? 0) >>> 0, argc: argc >>> 0, args, fmts, ops, pats,
  };
}
const EMPTY = { program: { ops: [], pats: [], nops: 0, npats: 0, nocase: 0 } };

export class PfwVm {
  /**
   * @param {object} [opts]
   * @param {number|number[]} [opts.iface=1]  ifindex(es) to attach the XDP entry to
   * @param {string} [opts.object]  path to vm.bpf.o (default: this package's bin/vm.bpf.o)
   * @param {string} [opts.base]    base directory yeetd resolves the object against
   */
  constructor({ iface = 1, object, base } = {}) {
    const root = `${import.meta.dirname}/..`;
    this.ifaces = (Array.isArray(iface) ? iface : [iface]).map(Number);
    this.object = object ?? `${root}/bin/vm.bpf.o`;
    this.base = base ?? root;
    this._control = null;
    this._subs = [];
    this._verdictCbs = new Set();
    this._consoleCbs = new Set();
    this._active = 0;          // the generation packets run
    this._stamp = 0;           // pfw_prog.gen: unique per apply, so flows restart their automaton
    this._written = [{ ac_goto: [], ac_fail: [], ac_accept: [], re_goto: [], re_accept: [] }, { ac_goto: [], ac_fail: [], ac_accept: [], re_goto: [], re_accept: [] }];
    this._current = null;      // the compile result now running
    this._knobValues = {};     // host-set numeric knobs by name: survive a re-apply
    this._knobStrValues = {};  // host-set string knobs by name
  }

  /** True between a successful start() and stop(). */
  get running() { return this._control !== null; }

  /** The compile result of the program now enforcing (null before the first apply). */
  get program() { return this._current; }

  /** Load the interpreter into the kernel and attach it. Until apply(), every
   *  packet passes. Throws if already running, or if the interface's XDP hook is
   *  taken. */
  async start() {
    if (this._control) throw new Error("PfwVm.start(): already running");
    let obj = new BpfObject({ exe: this.object, base: this.base });
    for (const [name, spec] of Object.entries(MAPS)) obj = obj.bind(name, spec);
    STAGES.forEach((prog, index) => { obj = obj.attach(prog, { kind: "prog_array", map: "decode_jmp", index }); });
    obj = obj.attach("pfw_xdp", { kind: "xdp", ifindex: this.ifaces });
    const control = await obj.start();
    try {
      this._control = control;
      this._active = 0;
      this._current = null;
      for (const g of this._written) for (const k of Object.keys(g)) g[k] = [];
      /* An empty program in both generations: the entry passes when nops == 0. */
      await this._map("programs").update(0, progValue(EMPTY, 0, []));
      await this._map("programs").update(1, progValue(EMPTY, 0, []));
      await new DataSec(control, "vm.bss").patch({ active_gen: 0, shadow: 0 });
      for (const part of chunks([...transformCells()], BATCH)) await this._map("tt_cells").updateBatch(part);
      this._subs.push(await new RingBuf(control, "events").subscribe((w) => this._onEvent(w?.pfw_event ?? w)));
      this._subs.push(await new RingBuf(control, "console_ring").subscribe((w) => this._onConsole(w?.pfw_console ?? w)));
    } catch (e) {
      await this.stop();
      throw e;
    }
    return this;
  }

  /** Detach from the interface(s) and release everything in the kernel: maps,
   *  flow and source state, bans. Safe to call twice, and before start(). */
  async stop() {
    const control = this._control;
    if (!control) return;
    this._control = null;
    this._current = null;
    for (const s of this._subs.splice(0)) { try { await s?.unsubscribe?.(); } catch { /* already gone */ } }
    await control.stop();
  }

  [Symbol.asyncDispose]() { return this.stop(); }

  /**
   * Put a program into effect. It is written into the idle generation — bytecode,
   * automaton and regex tables — and only then does one write flip `active_gen`, so
   * no packet ever runs a half-written program. Connection state (flows, bans,
   * per-source counters) is kept across the swap.
   *
   * @param {Program|object|string} program  a Program, a compile() result, or pfw-C source
   * @param {object} [opts]
   * @param {Array<number|bigint>} [opts.argv]          runtime args (argv[i])
   * @param {Record<string, number|bigint>} [opts.knobs]     numeric knobs by name
   * @param {Record<string, string>} [opts.knobStrs]         string knobs by name
   * @param {boolean} [opts.shadow]                     dry-run: count and log, never block
   */
  async apply(program, opts = {}) {
    const control = this._need("apply");
    const c = compiled(program);
    const g = this._active ^ 1;
    const tables = c.tables?.() ?? build(c.patterns ?? [], c.nocase);
    const acBase = g * LIMITS.AC_STATES, reBase = g * LIMITS.RE_STATES;

    const want = { ac_goto: [], ac_fail: [], ac_accept: [], re_goto: [], re_accept: [] };
    for (const [k, next] of tables.edges) want.ac_goto.push([acBase * 256 + k, next & 0xffff]);
    for (const [s, f] of tables.fails) want.ac_fail.push([acBase + s, f & 0xffff]);
    for (const [s, m] of tables.accepts) want.ac_accept.push([acBase + s, BigInt(m)]);
    if (c.regex) {
      for (let s = 0; s < c.regex.nstates; s++) {
        const row = c.regex.trans[s];
        for (let b = 0; b < 256; b++) if (row[b]) want.re_goto.push([reBase * 256 + s * 256 + b, row[b] & 0xffff]);
        if (c.regex.accept[s]) want.re_accept.push([reBase + s, BigInt(c.regex.accept[s])]);
      }
    }
    /* The tables are sparse, so cells the generation's previous program set and
     * this one does not must be zeroed, or its automaton would leak through. */
    for (const name of Object.keys(want)) {
      const keep = new Set(want[name].map(([k]) => k));
      const zero = name.endsWith("accept") ? 0n : 0;
      const stale = this._written[g][name].filter((k) => !keep.has(k)).map((k) => [k, zero]);
      for (const part of chunks(stale.concat(want[name]), BATCH)) await this._map(name).updateBatch(part);
      this._written[g][name] = [...keep];
    }
    await this._map("programs").update(g, progValue(c, ++this._stamp, opts.argv ?? []));

    /* Knobs are one map shared by both generations and slots are assigned per
     * program, so they are written last, immediately before the flip. Values the
     * host set earlier carry over by NAME; a new program's defaults fill the rest. */
    Object.assign(this._knobValues, opts.knobs ?? {});
    Object.assign(this._knobStrValues, opts.knobStrs ?? {});
    const knobPairs = (c.knobs ?? []).map((name, slot) => [slot, BigInt(this._knobValues[name] ?? c.knobDefaults?.[slot] ?? 0)]);
    if (knobPairs.length) await this._map("knobs").updateBatch(knobPairs);
    for (const [slot, name] of (c.knobStrs ?? []).entries()) await this._map("knob_strs").update(slot, strBytes(this._knobStrValues[name] ?? "", LIMITS.KNOBSTR_CAP));

    const patch = { active_gen: g };
    if (opts.shadow !== undefined) patch.shadow = opts.shadow ? 1 : 0;
    await new DataSec(control, "vm.bss").patch(patch);
    this._active = g;
    this._current = c;
    /* A rule counter belongs to a slot, not a name, and both generations share
     * the slots: slot 2 was the last program's second rule and is now this
     * one's. What each slot held at the flip is what the new rules start from. */
    this._ruleBase = new Map();
    for (const r of c.rules ?? []) this._ruleBase.set(r.id, await this._ruleCount(r.id));
    this._appliedAt = Date.now();
    return this;
  }

  /** Stop enforcing without detaching: swap in an empty program (everything
   *  passes; standing bans still apply). */
  async clear() {
    this._need("clear");
    return this.apply(EMPTY);
  }

  /** Set a numeric knob of the running program by name. */
  async setKnob(name, value) {
    this._need("setKnob");
    this._knobValues[name] = value;
    const slot = (this._current?.knobs ?? []).indexOf(name);
    if (slot < 0) return false;                       // remembered; applied when a program declares it
    await this._map("knobs").update(slot, BigInt(value));
    return true;
  }

  /** Set a string knob (the needle `kstr("name")` searches for) by name. */
  async setKnobStr(name, value) {
    this._need("setKnobStr");
    this._knobStrValues[name] = value;
    const slot = (this._current?.knobStrs ?? []).indexOf(name);
    if (slot < 0) return false;
    await this._map("knob_strs").update(slot, strBytes(value, LIMITS.KNOBSTR_CAP));
    return true;
  }

  /** Shadow mode: verdicts are counted and logged but every packet passes. */
  async setShadow(on) { await new DataSec(this._need("setShadow"), "vm.bss").patch({ shadow: on ? 1 : 0 }); }

  /** `src in set` / `src6 in set6`: add or remove CIDRs. IPv6 is detected by ':'. */
  async addCidrs(cidrs) { this._need("addCidrs"); for (const c of [].concat(cidrs)) await (String(c).includes(":") ? new LpmTrie(this._control, "lpm6").update(cidr6Key(c), 1) : new LpmTrie(this._control, "lpm").update(cidr4Key(c), 1)); }
  async removeCidrs(cidrs) { this._need("removeCidrs"); for (const c of [].concat(cidrs)) await (String(c).includes(":") ? new LpmTrie(this._control, "lpm6").delete(cidr6Key(c)) : new LpmTrie(this._control, "lpm").delete(cidr4Key(c))); }

  /** `x in hash`: add or remove u32 members. */
  async addHash(values) { const h = new HashMap(this._need("addHash"), "hashset"); for (const v of [].concat(values)) await h.update(Number(v) >>> 0, 1); }
  async removeHash(values) { const h = new HashMap(this._need("removeHash"), "hashset"); for (const v of [].concat(values)) await h.delete(Number(v) >>> 0); }

  /** `x in bloom`: add u32 members (a Bloom filter cannot forget). */
  async addBloom(values) { const b = new BloomFilter(this._need("addBloom"), "bloom"); for (const v of [].concat(values)) await b.insert(Number(v) >>> 0); }

  /**
   * Subscribe to enforcement / log() events. The callback gets
   * `{ verdict, rule, ruleId, src, dst, sport, dport, proto, family, ifindex, mask, data, ts }`
   * — verdict and rule as names, `data` the bytes log() captured (Uint8Array).
   * Returns a function that unsubscribes. May be called before start().
   */
  onVerdict(cb) { this._verdictCbs.add(cb); return () => this._verdictCbs.delete(cb); }

  /** Subscribe to console() messages, already formatted. Returns an unsubscriber. */
  onConsole(cb) { this._consoleCbs.add(cb); return () => this._consoleCbs.delete(cb); }

  /** The global counters since start(); hits per rule name since that rule's
   *  program was applied (`applied` counts applies, so a change in it says the
   *  rule counts started over; `applied_at` is when, in ms); and the
   *  histogram of how long each packet's decision took. `decide_hist.counts[i]`
   *  is the number of decisions under `decide_hist.bounds[i]` nanoseconds (and
   *  not under the bound before it); the last count has no upper bound. */
  async stats() {
    const control = this._need("stats");
    const bss = (await new DataSec(control, "vm.bss").read()) ?? {};
    const out = { active: this._active, shadow: Number(bss.shadow ?? 0) !== 0, applied: this._stamp, applied_at: this._appliedAt ?? null, rules: {} };
    for (const k of COUNTERS) if (bss[k] !== undefined) out[k] = BigInt(bss[k]);
    for (const r of this._current?.rules ?? []) {
      const now = await this._ruleCount(r.id), base = this._ruleBase?.get(r.id) ?? 0n;
      out.rules[r.name] = now >= base ? now - base : now;
    }
    /* One slot per bucket, one count per CPU: the kernel never shares a line. */
    const hist = new PercpuArrayMap(control, "decide_hist");
    out.decide_hist = { bounds: [...DECIDE_BOUNDS], counts: [] };
    for (let i = 0; i <= DECIDE_BOUNDS.length; i++) {
      const perCpu = (await hist.lookup(i)) ?? [];
      out.decide_hist.counts.push(perCpu.reduce((a, v) => a + BigInt(v ?? 0), 0n));
    }
    return out;
  }

  /* ---- internals ---- */

  _need(what) { if (!this._control) throw new Error(`PfwVm.${what}(): not running — call start() first`); return this._control; }
  _map(name) { return new ArrayMap(this._control, name); }
  /* One rule slot's count, summed over CPUs. */
  async _ruleCount(id) {
    const perCpu = (await new PercpuArrayMap(this._control, "counters").lookup(id)) ?? [];
    return perCpu.reduce((a, v) => a + BigInt(v ?? 0), 0n);
  }

  _onEvent(e) {
    if (!this._verdictCbs.size || !e) return;
    const family = Number(e.family ?? 0), v6 = family === 10;
    const len = Math.min(Number(e.len ?? 0), LIMITS.LOG_CAP);
    const ev = {
      verdict: VERDICT[Number(e.verdict ?? 0)] ?? "pass",
      ruleId: Number(e.rule ?? 0),
      rule: this._current?.rules?.[Number(e.rule ?? 0)]?.name,
      src: v6 ? ip6(e.saddr) : ip4(e.saddr), dst: v6 ? ip6(e.daddr) : ip4(e.daddr),
      sport: Number(e.sport ?? 0), dport: Number(e.dport ?? 0), proto: Number(e.proto ?? 0), family,
      ifindex: Number(e.ifindex ?? 0), mask: BigInt(e.mask ?? 0), ts: BigInt(e.ts ?? 0),
      data: Uint8Array.from(Array.from(e.data ?? []).slice(0, len)),
    };
    for (const cb of this._verdictCbs) { try { cb(ev); } catch (err) { console.error(err?.message ?? err); } }
  }

  _onConsole(e) {
    if (!this._consoleCbs.size || !e) return;
    const nn = Math.min(Number(e.nnum ?? 0), LIMITS.FARGS), sn = Math.min(Number(e.nstr ?? 0), LIMITS.FSTR);
    const nums = Array.from({ length: nn }, (_, i) => BigInt(e.nums?.[i] ?? 0));
    const strs = Array.from({ length: sn }, (_, s) => {
      const len = Number(e.slen?.[s] ?? 0), by = e.strs?.[s] ?? [];
      let str = ""; for (let b = 0; b < len; b++) str += String.fromCharCode((by[b] ?? 0) & 0xff); return str;
    });
    const line = formatMsg(this._current?.consoleFormats?.[Number(e.fmtid ?? 0)] ?? "", nums, strs);
    for (const cb of this._consoleCbs) { try { cb(line); } catch (err) { console.error(err?.message ?? err); } }
  }
}
