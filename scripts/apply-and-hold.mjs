/* Load the object, apply ONE pfw-C program (compiled + written into the maps),
 * attach, and hold — so an orchestrator can send loopback traffic and observe
 * the kernel's verdict. The program arrives base64 in --src. This is a minimal
 * loader (the firewall's probe does much more); it exists for the kernel
 * differential test (test/kernel/diff.mjs), which compares the kernel's verdict
 * on real traffic to the reference interpreter's.
 *
 *   yeet run scripts/apply-and-hold.mjs --src <base64 pfw-C> [--iface N] [--hold S]
 */
import { ArrayMap, BpfObject, DataSec, RingBuf } from "yeet:bpf";
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
  return { nops: p.nops >>> 0, npats: p.npats >>> 0, nocase: p.nocase >>> 0, gen: gen >>> 0, reasm: (p.reasm ?? 0) >>> 0, reasm_dport: (p.reasm_dport ?? 0) >>> 0, decode: (p.decode ?? 0) >>> 0, transform_table: (p.transform_table ?? 0) >>> 0, ops, pats };
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
  .bind("decode_jmp", { kind: "prog_array" })
  .attach("pfw_decode", { kind: "prog_array", map: "decode_jmp", index: 0 })
  .attach("pfw_match", { kind: "prog_array", map: "decode_jmp", index: 1 })
  .attach("pfw_resolve", { kind: "prog_array", map: "decode_jmp", index: 2 })
  .attach("pfw_huff", { kind: "prog_array", map: "decode_jmp", index: 3 })
  .attach("pfw_transform", { kind: "prog_array", map: "decode_jmp", index: 4 })
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
