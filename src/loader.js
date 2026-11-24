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
 *   await vm.route({ proto: "tcp", dport: 8443 }, load(apiSource));   // its own program for one port
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
import { DECIDE_BOUNDS, LIMITS, OP, VERDICT } from "#/isa.js";
import { Pool } from "#/pool.js";
import { formatMsg } from "#/program";
import { transformCells } from "#/transform.js";

/* The tail-call stages, by their slot in the `decode_jmp` program array. Every
 * one must be in place before the entry is attached. */
const STAGES = ["pfw_decode", "pfw_match", "pfw_resolve", "pfw_huff", "pfw_transform", "pfw_rewrite", "pfw_hpack"];

/* Maps the loader reads or writes, and the kind yeetd binds each as. */
const MAPS = {
  events: { kind: "ringbuf", btf_struct: "pfw_event" },
  console_ring: { kind: "ringbuf", btf_struct: "pfw_console" },
  emits: { kind: "ringbuf", btf_struct: "pfw_emit" },
  samples: { kind: "ringbuf", btf_struct: "pfw_sample" },
  programs: { kind: "array" }, ops: { kind: "array" }, ac_goto: { kind: "array" }, ac_fail: { kind: "array" }, ac_accept: { kind: "array" },
  re_goto: { kind: "array" }, re_accept: { kind: "array" }, tt_cells: { kind: "array" },
  knobs: { kind: "array" }, knob_strs: { kind: "array" }, tables: { kind: "array" },
  counters: { kind: "percpu_array" }, decide_hist: { kind: "percpu_array" }, rule_time: { kind: "percpu_array" }, stack: { kind: "percpu_array" },
  flows: { kind: "lru_hash" }, lpm: { kind: "lpm_trie" }, lpm6: { kind: "lpm_trie" },
  hashset: { kind: "hash" }, kv: { kind: "hash" }, bloom: { kind: "bloom_filter" },
  "vm.bss": { kind: "data" }, decode_jmp: { kind: "prog_array" }, dispatch: { kind: "hash" },
};

/* Counters in vm.bss worth reporting (all u64). */
const COUNTERS = ["seen", "ran", "passed", "dropped", "rsts", "bans", "enforced", "src_enforced", "shadowed", "faults", "logged", "sampled",
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

/* A route: the packets a program is for, as the host says it and as `dispatch`
 * keys it (struct route_key). */
const PROTO = { tcp: 6, udp: 17 };
function routeKey(match) {
  const proto = typeof match?.proto === "string" ? PROTO[match.proto.toLowerCase()] : Number(match?.proto);
  const dport = Number(match?.dport);
  if (!Number.isInteger(proto) || proto < 0 || proto > 255) throw new TypeError(`route: proto is "tcp", "udp" or a protocol number, not ${match?.proto}`);
  if (!Number.isInteger(dport) || dport < 0 || dport > 65535) throw new TypeError(`route: dport is 0–65535, not ${match?.dport}`);
  const name = `${Object.keys(PROTO).find((k) => PROTO[k] === proto) ?? proto}/${dport}`;
  return { name, key: { dport, proto, _pad: 0 } };
}

/* How long a replaced program is left whole before its tables are zeroed and
 * its ranges reused: a packet that picked it up just before the flip is still
 * running it on some CPU. A run is microseconds; this is a wide margin. */
const GRACE_MS = 50;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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
function progValue(c, stamp, argv, at = {}) {
  const p = c.program;
  const { MAX_PATS, PAT_CAP, ARGC, FMTS, FMT_CAP } = LIMITS;
  const pats = p.pats.slice(0, MAX_PATS).map((q) => { const b = q.bytes.slice(0, PAT_CAP); while (b.length < PAT_CAP) b.push(0); return { len: q.len >>> 0, bytes: b }; });
  while (pats.length < MAX_PATS) pats.push({ len: 0, bytes: new Array(PAT_CAP).fill(0) });
  const args = argv.slice(0, ARGC).map((v) => BigInt(v));
  const argc = args.length;
  while (args.length < ARGC) args.push(0n);
  /* The regex DFAs: where each starts, and which one matches each regex. */
  const { RE_GROUPS } = LIMITS;
  const starts = c.regex?.starts ?? [];
  const re_start = Array.from({ length: RE_GROUPS }, (_, g) => (starts[g] ?? 0) >>> 0);
  const re_pat_start = Array.from({ length: MAX_PATS }, (_, bit) => (c.regex?.startOf[bit] ?? 0) >>> 0);
  const fmts = [];
  for (let i = 0; i < FMTS; i++) fmts.push(strBytes((c.printkFormats ?? [])[i] ?? "", FMT_CAP - 1).b.concat([0]));
  return {
    nops: p.nops >>> 0, npats: p.npats >>> 0, nocase: p.nocase >>> 0, gen: stamp >>> 0,
    reasm: (p.reasm ?? 0) >>> 0, reasm_dport: (p.reasm_dport ?? 0) >>> 0, decode: (p.decode ?? 0) >>> 0,
    transform_table: (p.transform_table ?? 0) >>> 0, argc: argc >>> 0, re_ngroups: starts.length >>> 0,
    ops_base: (at.ops ?? 0) >>> 0, ac_base: (at.ac ?? 0) >>> 0, re_base: (at.re ?? 0) >>> 0, tbl_base: (at.tbl ?? 0) >>> 0, rule_base: (at.rule ?? 0) >>> 0, args, fmts, re_start, re_pat_start, pats,
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
    this._emitCbs = new Set();
    this._sampleCbs = new Set();
    this._tableValues = {};          // name -> BigInt[]: what the host has put in each table
    this._stamp = 0;           // pfw_prog.gen: unique per install, so flows restart their automaton
    this._reset();
    this._knobValues = {};     // host-set numeric knobs by name: survive a re-apply
    this._knobValues = {};     // host-set numeric knobs by name: survive a re-apply
    this._knobStrValues = {};  // host-set string knobs by name
  }

  /* The kernel is empty: no program installed, every pool whole. */
  _reset() {
    const { PROGS, GENS, MAX_OPS, AC_STATES, RE_STATES, TABLE_CELLS, NRULES } = LIMITS;
    this._slots = new Pool(PROGS, "program slots");
    this._pools = {
      ops: new Pool(GENS * MAX_OPS, "instructions"), ac: new Pool(GENS * AC_STATES, "automaton states"),
      re: new Pool(GENS * RE_STATES, "regex DFA states"), tbl: new Pool(GENS * TABLE_CELLS, "table cells"),
      rule: new Pool(GENS * NRULES, "rules"),
    };
    this._default = null;        // the installed program packets run when no route claims them
    this._routes = new Map();    // route name -> { key, rec }
    this._limbo = [];            // replaced programs, still whole until their grace is up
    this._byStamp = new Map();   // pfw_prog.gen -> the installed program, for its events
    this._knobSlots = new Map();     // knob name -> its slot in `knobs`, shared by every program
    this._knobStrSlots = new Map();  // string knob name -> its slot in `knob_strs`
  }

  /** True between a successful start() and stop(). */
  get running() { return this._control !== null; }

  /** The compile result of the default program (null before the first apply). */
  get program() { return this._default?.c ?? null; }

  /** The routes now installed, by name ("tcp/8443"): each one's compile result. */
  get routes() { return Object.fromEntries([...this._routes].map(([name, { rec }]) => [name, rec.c])); }

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
      this._reset();
      /* No program yet: every slot is zero, and the entry passes when nops == 0. */
      await new DataSec(control, "vm.bss").patch({ default_slot: 0, shadow: 0 });
      for (const part of chunks([...transformCells()], BATCH)) await this._map("tt_cells").updateBatch(part);
      this._subs.push(await new RingBuf(control, "events").subscribe((w) => this._onEvent(w?.pfw_event ?? w)));
      this._subs.push(await new RingBuf(control, "console_ring").subscribe((w) => this._onConsole(w?.pfw_console ?? w)));
      this._subs.push(await new RingBuf(control, "emits").subscribe((w) => this._onEmit(w?.pfw_emit ?? w)));
      this._subs.push(await new RingBuf(control, "samples").subscribe((w) => this._onSample(w?.pfw_sample ?? w)));
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
    this._reset();
    for (const s of this._subs.splice(0)) { try { await s?.unsubscribe?.(); } catch { /* already gone */ } }
    await control.stop();
  }

  [Symbol.asyncDispose]() { return this.stop(); }

  /**
   * Put a program into effect as the default: the one every packet runs that no
   * route claims. It is installed beside the one it replaces — bytecode,
   * automaton and regex tables — and only then does one write point the kernel
   * at it, so no packet ever runs a half-written program. Connection state
   * (flows, bans, per-source counters) is kept across the swap.
   *
   * @param {Program|object|string} program  a Program, a compile() result, or pfw-C source
   * @param {object} [opts]
   * @param {Array<number|bigint>} [opts.argv]          runtime args (argv[i])
   * @param {Record<string, number|bigint>} [opts.knobs]     numeric knobs by name
   * @param {Record<string, string>} [opts.knobStrs]         string knobs by name
   * @param {Record<string, Array<number|bigint>>} [opts.tables]  contents of declared tables, by name
   * @param {boolean} [opts.shadow]                     dry-run: count and log, never block
   */
  async apply(program, opts = {}) {
    const control = this._need("apply");
    const rec = await this._install(program, opts, "default");
    const patch = { default_slot: rec.slot.base };
    if (opts.shadow !== undefined) patch.shadow = opts.shadow ? 1 : 0;
    await new DataSec(control, "vm.bss").patch(patch);
    this._retire(this._default);
    this._default = rec;
    return this;
  }

  /**
   * Give the packets of one protocol and destination port a program of their
   * own, in place of the default: `route({ proto: "tcp", dport: 8443 }, program)`.
   * It has its own patterns, rules, instruction budget, `reassemble` and
   * `decode`; knobs and tables are shared with every other program by name, and
   * so are the sets and the `lookup` map. Routing the same packets again swaps
   * the program as apply() does. Takes the options apply() takes, but for
   * `shadow`, which is the whole VM's.
   */
  async route(match, program, opts = {}) {
    const control = this._need("route");
    const { name, key } = routeKey(match);
    const rec = await this._install(program, opts, name);
    await new HashMap(control, "dispatch").update(key, rec.slot.base);
    this._retire(this._routes.get(name)?.rec);
    this._routes.set(name, { key, rec });
    return this;
  }

  /** Take a route away: its packets run the default program again. Returns
   *  false if there was no such route. */
  async unroute(match) {
    const control = this._need("unroute");
    const { name, key } = routeKey(match);
    const route = this._routes.get(name);
    if (!route) return false;
    await new HashMap(control, "dispatch").delete(key);
    this._routes.delete(name);
    this._retire(route.rec);
    return true;
  }

  /* Write a program into a free slot and a free range of each pool. Nothing
   * runs it until the caller points the default, or a route, at its slot. */
  async _install(program, opts, name) {
    const c = compiled(program);
    await this._reap();
    const tables = c.tables?.() ?? build(c.patterns ?? [], c.nocase);
    const ops = c.program.ops.slice(0, LIMITS.MAX_OPS);
    const nrules = (c.rules ?? []).reduce((n, r) => Math.max(n, r.id + 1), 1);
    const ncells = (c.lookupTables ?? []).reduce((n, t) => Math.max(n, t.base + t.size), 0);

    const rec = { name, c, stamp: ++this._stamp, slot: null, ranges: {}, written: {}, ruleBase: new Map(), timeBase: new Map(), appliedAt: Date.now(), retiredAt: null };
    try {
      rec.slot = this._slots.take(1);
      const P = this._pools, R = rec.ranges;
      R.ops = P.ops.take(ops.length); R.ac = P.ac.take(tables.count ?? 0); R.re = P.re.take(c.regex?.nstates ?? 0);
      R.tbl = P.tbl.take(ncells); R.rule = P.rule.take(nrules);

      /* The automata. They are sparse — a cell nobody writes is "no edge" — which
       * is why a program's cells are zeroed when it goes (_release), and a range
       * is always clean when it is taken. */
      const want = { ac_goto: [], ac_fail: [], ac_accept: [], re_goto: [], re_accept: [] };
      for (const [k, next] of tables.edges) want.ac_goto.push([R.ac.base * 256 + k, next & 0xffff]);
      for (const [s, f] of tables.fails) want.ac_fail.push([R.ac.base + s, f & 0xffff]);
      for (const [s, m] of tables.accepts) want.ac_accept.push([R.ac.base + s, BigInt(m)]);
      if (c.regex) {
        for (let s = 0; s < c.regex.nstates; s++) {
          const row = c.regex.trans[s];
          for (let b = 0; b < 256; b++) if (row[b]) want.re_goto.push([(R.re.base + s) * 256 + b, row[b] & 0xffff]);
          if (c.regex.accept[s]) want.re_accept.push([R.re.base + s, BigInt(c.regex.accept[s])]);
        }
      }
      for (const [map, pairs] of Object.entries(want)) {
        rec.written[map] = pairs.map(([k]) => k);
        for (const part of chunks(pairs, BATCH)) await this._map(map).updateBatch(part);
      }

      /* Lookup tables: what the host has set carries over by NAME; cells nobody
       * set are 0, which is what a clean range already holds. */
      for (const [tname, values] of Object.entries(opts.tables ?? {})) this._tableValues[tname] = Array.from(values, (v) => BigInt(v));
      const cells = [];
      for (const t of c.lookupTables ?? []) {
        const have = this._tableValues[t.name] ?? [];
        for (let i = 0; i < t.size; i++) { const v = have[i] ?? 0n; if (v !== 0n) cells.push([R.tbl.base + t.base + i, v]); }
      }
      rec.written.tables = cells.map(([k]) => k);
      for (const part of chunks(cells, BATCH)) await this._map("tables").updateBatch(part);

      /* Knobs are one map every program shares, a name owning a slot for good:
       * the instructions carry the program's own numbering, and are pointed at
       * the shared slots here. Values the host set carry over by NAME; a new
       * program's defaults fill the rest. */
      Object.assign(this._knobValues, opts.knobs ?? {});
      Object.assign(this._knobStrValues, opts.knobStrs ?? {});
      const knobAt = (c.knobs ?? []).map((kname) => this._slotOf(this._knobSlots, kname, LIMITS.KNOBS, "knobs"));
      const kstrAt = (c.knobStrs ?? []).map((kname) => this._slotOf(this._knobStrSlots, kname, LIMITS.KNOBSTRS, "string knobs"));
      const knobPairs = (c.knobs ?? []).map((kname, i) => [knobAt[i], BigInt(this._knobValues[kname] ?? c.knobDefaults?.[i] ?? 0)]);
      if (knobPairs.length) await this._map("knobs").updateBatch(knobPairs);
      for (const [i, kname] of (c.knobStrs ?? []).entries()) await this._map("knob_strs").update(kstrAt[i], strBytes(this._knobStrValues[kname] ?? "", LIMITS.KNOBSTR_CAP));

      /* The instructions, then the header that says how many there are and
       * where everything is. */
      const opPairs = ops.map((o, pc) => {
        const imm = o.code === OP.KNOB ? BigInt(knobAt[Number(o.imm)] ?? 0) : o.code === OP.KNOBHAS ? BigInt(kstrAt[Number(o.imm)] ?? 0) : BigInt(o.imm);
        return [R.ops.base + pc, { code: o.code >>> 0, reg: o.reg >>> 0, imm }];
      });
      for (const part of chunks(opPairs, BATCH)) await this._map("ops").updateBatch(part);
      const at = { ops: R.ops.base, ac: R.ac.base, re: R.re.base, tbl: R.tbl.base, rule: R.rule.base };
      await this._map("programs").update(rec.slot.base, progValue(c, rec.stamp, opts.argv ?? [], at));

      /* A rule counter belongs to its slot in the pool, and the slot had an
       * owner before: what each held now is what this program's rules start from. */
      for (const r of c.rules ?? []) {
        rec.ruleBase.set(r.id, await this._ruleCount(R.rule.base + r.id));
        rec.timeBase.set(r.id, await this._ruleTime(R.rule.base + r.id));
      }
    } catch (e) {
      await this._release(rec).catch(() => {});
      throw e;
    }
    this._byStamp.set(rec.stamp, rec);
    this._byStamp.delete(rec.stamp - 64);   // events of a program that long gone have been read
    return rec;
  }

  /* A knob's slot in the map every program shares: the one its name already
   * has, or the next free one. */
  _slotOf(slots, name, cap, what) {
    if (!slots.has(name)) {
      if (slots.size >= cap) throw new Error(`more than ${cap} ${what} across the installed programs`);
      slots.set(name, slots.size);
    }
    return slots.get(name);
  }

  /* Nothing points at this program any more. It stays whole for GRACE_MS. */
  _retire(rec) {
    if (!rec) return;
    rec.retiredAt = Date.now();
    this._limbo.push(rec);
  }

  /* Free every replaced program, waiting out what is left of its grace. */
  async _reap() {
    while (this._limbo.length) {
      const rec = this._limbo[0];
      const left = rec.retiredAt + GRACE_MS - Date.now();
      if (left > 0) await sleep(left);
      this._limbo.shift();
      await this._release(rec);
    }
  }

  /* Empty a program's slot, zero the sparse cells it wrote, and give its
   * ranges back. */
  async _release(rec) {
    if (rec.slot) await this._map("programs").update(rec.slot.base, progValue(EMPTY, 0, []));
    for (const [map, keys] of Object.entries(rec.written)) {
      const zero = map === "ac_accept" || map === "re_accept" || map === "tables" ? 0n : 0;
      for (const part of chunks(keys.map((k) => [k, zero]), BATCH)) await this._map(map).updateBatch(part);
    }
    rec.written = {};
    for (const [pool, range] of Object.entries(rec.ranges)) this._pools[pool].give(range);
    rec.ranges = {};
    if (rec.slot) this._slots.give(rec.slot);
    rec.slot = null;
  }

  /* Every program something points at: the default, then the routes. */
  _live() { return [this._default, ...[...this._routes.values()].map((r) => r.rec)].filter(Boolean); }

  /** Stop enforcing by default without detaching: swap in an empty default
   *  program (packets no route claims pass; standing bans still apply). */
  async clear() {
    this._need("clear");
    return this.apply(EMPTY);
  }

  /** Set a numeric knob by name, in every program that declares it. */
  async setKnob(name, value) {
    this._need("setKnob");
    this._knobValues[name] = value;
    const slot = this._knobSlots.get(name);
    if (slot === undefined) return false;             // remembered; applied when a program declares it
    await this._map("knobs").update(slot, BigInt(value));
    return true;
  }

  /**
   * Fill a declared `table` (or part of it) of the running program, live: the
   * next packet reads the new cells. `values` are written from `offset` on.
   * The table is remembered by name, so a later apply() of a program that
   * declares it starts with these values. Cells are written in batches and a
   * packet may run between two of them: a table whose every cell is valid on
   * its own (a backend in each slot) can be rewritten under traffic; one whose
   * cells must agree with each other wants an apply().
   * Every installed program that declares the table gets them. Returns false if
   * none does.
   */
  async setTable(name, values, offset = 0) {
    this._need("setTable");
    const kept = (this._tableValues[name] ??= []);
    const list = Array.from(values, (v) => BigInt(v));
    list.forEach((v, i) => { kept[offset + i] = v; });
    let any = false;
    for (const rec of this._live()) {
      const t = (rec.c.lookupTables ?? []).find((x) => x.name === name);
      if (!t) continue;
      const base = rec.ranges.tbl.base + t.base, pairs = [];
      list.forEach((v, i) => { if (offset + i < t.size) pairs.push([base + offset + i, v]); });
      for (const part of chunks(pairs, BATCH)) await this._map("tables").updateBatch(part);
      rec.written.tables = [...new Set([...(rec.written.tables ?? []), ...pairs.map(([k]) => k)])];
      any = true;
    }
    return any;                                        // false: remembered; applied when a program declares it
  }

  /** Set a string knob (the needle `kstr("name")` searches for) by name. */
  async setKnobStr(name, value) {
    this._need("setKnobStr");
    this._knobStrValues[name] = value;
    const slot = this._knobStrSlots.get(name);
    if (slot === undefined) return false;
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

  /** `lookup(key)`: store values under 64-bit keys. `entries` is a Map, an array
   *  of [key, value] pairs, or a plain object. Shared by every program, like
   *  the sets: it is the host's data, and outlives an apply(). */
  async setKv(entries) {
    const h = new HashMap(this._need("setKv"), "kv");
    const pairs = entries instanceof Map || Array.isArray(entries) ? [...entries] : Object.entries(entries ?? {});
    for (const [k, v] of pairs) await h.update(BigInt(k), BigInt(v));
  }
  /** Remove keys from the `lookup` map; a key that is not there is not an error. */
  async deleteKv(keys) {
    const h = new HashMap(this._need("deleteKv"), "kv");
    for (const k of [].concat(keys)) { try { await h.delete(BigInt(k)); } catch { /* it was not there */ } }
  }

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

  /** Subscribe to sample() copies of frames: `{ tag, data, wireLen, ts, ifindex }`
   *  — `data` the captured bytes from the frame's first byte (a Uint8Array),
   *  `wireLen` the frame's real length, `tag` the name the program gave or null.
   *  Returns an unsubscriber. */
  onSample(cb) { this._sampleCbs.add(cb); return () => this._sampleCbs.delete(cb); }

  /** Subscribe to emit() events: `{ name, values, ts, ifindex }`, the values as
   *  BigInt in the order the program gave them. Returns an unsubscriber. */
  onEmit(cb) { this._emitCbs.add(cb); return () => this._emitCbs.delete(cb); }

  /** The global counters since start(); hits per rule name of the default
   *  program since it was applied (`applied` counts applies, so a change in it says the
   *  rule counts started over; `applied_at` is when, in ms); `timing`, the
   *  decision time by rule — `timing[name] = { runs, ns }` for the packets whose
   *  last-touched rule (a count, or the verdict's) was that one, with "-" for
   *  packets that touched none; and the
   *  histogram of how long each packet's decision took. `decide_hist.counts[i]`
   *  is the number of decisions under `decide_hist.bounds[i]` nanoseconds (and
   *  not under the bound before it); the last count has no upper bound. */
  async stats() {
    const control = this._need("stats");
    const bss = (await new DataSec(control, "vm.bss").read()) ?? {};
    const out = { active: this._default?.slot.base ?? 0, shadow: Number(bss.shadow ?? 0) !== 0, applied: this._stamp, applied_at: this._default?.appliedAt ?? null };
    for (const k of COUNTERS) if (bss[k] !== undefined) out[k] = BigInt(bss[k]);
    Object.assign(out, this._default ? await this._ruleStats(this._default) : { rules: {}, timing: {} });
    /* The same for each route, by its name. */
    out.routes = {};
    for (const [name, { rec }] of this._routes) out.routes[name] = { applied_at: rec.appliedAt, ...(await this._ruleStats(rec)) };
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

  /* One program's hits per rule name, and decision time by the rule each packet
   * ended on, both since it was installed. */
  async _ruleStats(rec) {
    const rules = {}, timing = {}, at = rec.ranges.rule.base;
    for (const r of rec.c.rules ?? []) {
      const now = await this._ruleCount(at + r.id), base = rec.ruleBase.get(r.id) ?? 0n;
      rules[r.name] = now >= base ? now - base : now;
      const t = await this._ruleTime(at + r.id), tb = rec.timeBase.get(r.id) ?? { ns: 0n, runs: 0n };
      const fresh = t.runs < tb.runs;
      timing[r.name] = { runs: fresh ? t.runs : t.runs - tb.runs, ns: fresh ? t.ns : t.ns - tb.ns };
    }
    return { rules, timing };
  }

  /* The installed program an event came from, by the stamp it carries. */
  _from(e) { return this._byStamp.get(Number(e.prog ?? 0)); }

  _need(what) { if (!this._control) throw new Error(`PfwVm.${what}(): not running — call start() first`); return this._control; }
  _map(name) { return new ArrayMap(this._control, name); }
  /* One rule slot's decision time, summed over CPUs: { ns, runs }. */
  async _ruleTime(id) {
    const perCpu = (await new PercpuArrayMap(this._control, "rule_time").lookup(id)) ?? [];
    return perCpu.reduce((a, v) => ({ ns: a.ns + BigInt(v?.ns ?? 0), runs: a.runs + BigInt(v?.runs ?? 0) }), { ns: 0n, runs: 0n });
  }
  /* One rule slot's count, summed over CPUs. */
  async _ruleCount(id) {
    const perCpu = (await new PercpuArrayMap(this._control, "counters").lookup(id)) ?? [];
    return perCpu.reduce((a, v) => a + BigInt(v ?? 0), 0n);
  }

  _onEvent(e) {
    if (!this._verdictCbs.size || !e) return;
    const family = Number(e.family ?? 0), v6 = family === 10;
    const len = Math.min(Number(e.len ?? 0), LIMITS.LOG_CAP);
    /* The kernel reports the rule's counter slot; the program's own id is that
     * less where its rules begin. */
    const rec = this._from(e), ruleId = Number(e.rule ?? 0) - (rec?.ranges.rule?.base ?? 0);
    const ev = {
      verdict: VERDICT[Number(e.verdict ?? 0)] ?? "pass",
      ruleId,
      rule: rec?.c.rules?.[ruleId]?.name,
      route: rec?.name,
      src: v6 ? ip6(e.saddr) : ip4(e.saddr), dst: v6 ? ip6(e.daddr) : ip4(e.daddr),
      sport: Number(e.sport ?? 0), dport: Number(e.dport ?? 0), proto: Number(e.proto ?? 0), family,
      ifindex: Number(e.ifindex ?? 0), mask: BigInt(e.mask ?? 0), ts: BigInt(e.ts ?? 0),
      data: Uint8Array.from(Array.from(e.data ?? []).slice(0, len)),
    };
    for (const cb of this._verdictCbs) { try { cb(ev); } catch (err) { console.error(err?.message ?? err); } }
  }

  _onSample(e) {
    if (!this._sampleCbs.size || !e) return;
    const n = Math.min(Number(e.cap_len ?? 0), LIMITS.SAMPLE_CAP);
    const ev = {
      tag: this._from(e)?.c.sampleTags?.[Number(e.tag ?? 0)] || null,
      route: this._from(e)?.name,
      data: Uint8Array.from(Array.from(e.data ?? []).slice(0, n)),
      wireLen: Number(e.wire_len ?? 0), ts: BigInt(e.ts ?? 0), ifindex: Number(e.ifindex ?? 0),
    };
    for (const cb of this._sampleCbs) { try { cb(ev); } catch (err) { console.error(err?.message ?? err); } }
  }

  _onEmit(e) {
    if (!this._emitCbs.size || !e) return;
    const id = Number(e.id ?? 0), n = Math.min(Number(e.n ?? 0), LIMITS.FARGS);
    const ev = {
      name: this._from(e)?.c.emits?.[id]?.name, id,
      route: this._from(e)?.name,
      values: Array.from({ length: n }, (_, i) => BigInt(e.vals?.[i] ?? 0)),
      ts: BigInt(e.ts ?? 0), ifindex: Number(e.ifindex ?? 0),
    };
    for (const cb of this._emitCbs) { try { cb(ev); } catch (err) { console.error(err?.message ?? err); } }
  }

  _onConsole(e) {
    if (!this._consoleCbs.size || !e) return;
    const nn = Math.min(Number(e.nnum ?? 0), LIMITS.FARGS), sn = Math.min(Number(e.nstr ?? 0), LIMITS.FSTR);
    const nums = Array.from({ length: nn }, (_, i) => BigInt(e.nums?.[i] ?? 0));
    const strs = Array.from({ length: sn }, (_, s) => {
      const len = Number(e.slen?.[s] ?? 0), by = e.strs?.[s] ?? [];
      let str = ""; for (let b = 0; b < len; b++) str += String.fromCharCode((by[b] ?? 0) & 0xff); return str;
    });
    const line = formatMsg(this._from(e)?.c.consoleFormats?.[Number(e.fmtid ?? 0)] ?? "", nums, strs);
    for (const cb of this._consoleCbs) { try { cb(line); } catch (err) { console.error(err?.message ?? err); } }
  }
}
