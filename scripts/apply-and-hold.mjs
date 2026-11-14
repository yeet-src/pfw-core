/* Load the object, apply ONE pfw-C program (compiled + written into the maps),
 * attach, and hold — so an orchestrator can send loopback traffic and observe
 * the kernel's verdict. The program arrives base64 in --src. This is a minimal
 * loader (the firewall's probe does much more); it exists for the kernel
 * differential test (test/kernel/diff.mjs), which compares the kernel's verdict
 * on real traffic to the reference interpreter's.
 *
 *   yeet run scripts/apply-and-hold.mjs --src <base64 pfw-C> [--iface N] [--hold S]
 */
import { ArrayMap, BloomFilter, BpfObject, DataSec, HashMap, LpmTrie, RingBuf } from "yeet:bpf";
import { compile } from "#/clang.js";
import { build } from "#/ac.js";
import { LIMITS } from "#/isa.js";
import { transformCells } from "#/transform.js";

const argv = yeet.args ?? {};
const iface = Number(argv.iface ?? 1);
const hold = Number(argv.hold ?? 20);
const root = `${import.meta.dirname}/..`;
// The program arrives hex-encoded (no atob/TextDecoder in this runtime); it is ASCII.
const src = argv.src ? String.fromCharCode(...argv.src.match(/../g).map((h) => parseInt(h, 16))) : "filter { return pass; }";

/* The `programs` map value as `struct pfw_prog` (field order matches pfw.h). */
function progValue(p, gen) {
  const { MAX_OPS, MAX_PATS, PAT_CAP } = LIMITS;
  const ops = p.ops.slice(0, MAX_OPS).map((o) => ({ code: o.code >>> 0, reg: o.reg >>> 0, imm: BigInt(o.imm) }));
  while (ops.length < MAX_OPS) ops.push({ code: 0, reg: 0, imm: 0n });
  const pats = p.pats.slice(0, MAX_PATS).map((q) => { const b = q.bytes.slice(0, PAT_CAP); while (b.length < PAT_CAP) b.push(0); return { len: q.len >>> 0, bytes: b }; });
  while (pats.length < MAX_PATS) pats.push({ len: 0, bytes: new Array(PAT_CAP).fill(0) });
  const args = (argv.argv ? String(argv.argv).split(",").filter((s) => s !== "") : []).map((v) => BigInt(v));
  const argvals = args.slice(0, LIMITS.ARGC); while (argvals.length < LIMITS.ARGC) argvals.push(0n);
  return { nops: p.nops >>> 0, npats: p.npats >>> 0, nocase: p.nocase >>> 0, gen: gen >>> 0, reasm: (p.reasm ?? 0) >>> 0, reasm_dport: (p.reasm_dport ?? 0) >>> 0, decode: (p.decode ?? 0) >>> 0, transform_table: (p.transform_table ?? 0) >>> 0, argc: args.length >>> 0, args: argvals, ops, pats };
}

const c = compile(src);
if (!c.ok) { console.log("COMPILE FAIL " + JSON.stringify(c.errors)); yeet.exit(1); }

const control = await new BpfObject({ exe: `${root}/bin/vm.bpf.o`, base: root })
  .bind("events", { kind: "ringbuf", btf_struct: "pfw_event" })
  .bind("programs", { kind: "array" })
  .bind("ac_goto", { kind: "array" })
  .bind("ac_fail", { kind: "array" })
  .bind("ac_accept", { kind: "array" })
  .bind("counters", { kind: "percpu_array" })
  .bind("decide_hist", { kind: "percpu_array" })
  .bind("flows", { kind: "lru_hash" })
  .bind("vm.bss", { kind: "data" })
  .bind("tt_cells", { kind: "array" })
  .bind("lpm", { kind: "lpm_trie" })
  .bind("lpm6", { kind: "lpm_trie" })
  .bind("hashset", { kind: "hash" })
  .bind("bloom", { kind: "bloom_filter" })
  .bind("re_goto", { kind: "array" })
  .bind("re_accept", { kind: "array" })
  .bind("decode_jmp", { kind: "prog_array" })
  .attach("pfw_decode", { kind: "prog_array", map: "decode_jmp", index: 0 })
  .attach("pfw_match", { kind: "prog_array", map: "decode_jmp", index: 1 })
  .attach("pfw_resolve", { kind: "prog_array", map: "decode_jmp", index: 2 })
  .attach("pfw_huff", { kind: "prog_array", map: "decode_jmp", index: 3 })
  .attach("pfw_transform", { kind: "prog_array", map: "decode_jmp", index: 4 })
    .attach("pfw_rewrite", { kind: "prog_array", map: "decode_jmp", index: 5 })
  .attach("pfw_xdp", { kind: "xdp", ifindex: [iface] })
  .start();

/* Load the transform tables (static) and apply the program into generation 0. */
const ttCells = new ArrayMap(control, "tt_cells");
for (const [k, v] of transformCells()) await ttCells.update(k, v);

const tables = build(c.patterns, c.nocase);
const acGoto = new ArrayMap(control, "ac_goto"), acFail = new ArrayMap(control, "ac_fail"), acAccept = new ArrayMap(control, "ac_accept");
for (const [k, next] of tables.edges) await acGoto.update(0 * LIMITS.AC_STATES * 256 + k, next & 0xffff);
for (const [s, f] of tables.fails) await acFail.update(s, f & 0xffff);
for (const [s, m] of tables.accepts) await acAccept.update(s, BigInt(m));
await new ArrayMap(control, "programs").update(0, progValue(c.program, 1));

/* Load the regex DFA (if the program has `regex` patterns): complete transition
 * table + per-state accept mask, both gen 0. */
if (c.regex) {
  const reGoto = new ArrayMap(control, "re_goto"), reAccept = new ArrayMap(control, "re_accept");
  for (let s = 0; s < c.regex.nstates; s++) {
    const row = c.regex.trans[s];
    for (let b = 0; b < 256; b++) if (row[b]) await reGoto.update(0 * LIMITS.RE_STATES * 256 + s * 256 + b, row[b] & 0xffff);
    if (c.regex.accept[s]) await reAccept.update(0 * LIMITS.RE_STATES + s, BigInt(c.regex.accept[s]));
  }
}

/* Populate the `x in hash` exact set from --hashset "80,443,8080". */
if (argv.hashset) {
  const h = new HashMap(control, "hashset");
  for (const v of String(argv.hashset).split(",").filter(Boolean)) await h.update((Number(v) >>> 0), 1);
}

/* Populate the `x in bloom` filter from --bloom "1,2,3". */
if (argv.bloom) {
  const bf = new BloomFilter(control, "bloom");
  for (const v of String(argv.bloom).split(",").filter(Boolean)) await bf.insert(Number(v) >>> 0);
}

/* Populate the `src in set` CIDR trie from --set "10.0.0.0/8,192.168.1.0/24". */
if (argv.set) {
  const trie = new LpmTrie(control, "lpm");
  for (const cidr of String(argv.set).split(",").filter(Boolean)) {
    const [ip, p = "32"] = cidr.split("/");
    const data = ip.split(".").map((o) => Number(o) & 0xff);
    await trie.update({ prefixlen: Number(p), data }, 1);
  }
}

/* Populate the `src6 in set6` IPv6 trie from --set6 "2001:db8::/32,::1/128". */
if (argv.set6) {
  const trie = new LpmTrie(control, "lpm6");
  const toBytes = (ip) => {
    const [head, tail] = ip.split("::");
    const h = head ? head.split(":") : [], t = tail !== undefined ? (tail ? tail.split(":") : []) : null;
    const groups = t === null ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
    const b = [];
    for (const g of groups) { const n = parseInt(g || "0", 16) & 0xffff; b.push((n >> 8) & 0xff, n & 0xff); }
    return b;
  };
  for (const cidr of String(argv.set6).split(",").filter(Boolean)) {
    const [ip, p = "128"] = cidr.split("/");
    await trie.update({ prefixlen: Number(p), data: toBytes(ip) }, 1);
  }
}
await new DataSec(control, "vm.bss").patch({ active: 0 });

/* Stream each enforcement event's verdict (2=drop,3=ban,4=rst — the pfw_verdict
 * enum, same numbers the reference uses) so the orchestrator reads the kernel's
 * actual decision rather than guessing from the socket. */
const sub = await new RingBuf(control, "events").subscribe((w) => {
  const e = w?.pfw_event ?? w;
  console.log(`EVENT ${Number(e.verdict ?? 0)}`);
});

console.log(`READY nops=${c.program.nops} decode=${c.program.decode ?? 0} reasm=${c.program.reasm ?? 0}`);
for (let i = 0; i < hold; i++) await new Promise((r) => setTimeout(r, 1000));
await sub.stop?.();
await control.stop();
console.log("detached");
