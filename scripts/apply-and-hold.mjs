/* Load the object, apply ONE pfw-C program, attach, and hold — so an orchestrator
 * can send loopback traffic and observe the kernel's verdict. A thin CLI over
 * the embeddable loader (src/loader.js, `pfw-core/loader`); every kernel test
 * drives the VM through it, so they exercise the loader too.
 *
 *   yeet run scripts/apply-and-hold.mjs --src <hex pfw-C> [--iface N] [--hold S]
 *     [--argv 1,2] [--shadow 1] [--set CIDRs] [--set6 CIDRs] [--hashset 80,443]
 *     [--bloom 1,2] [--knobs name=val,...] [--kstr name=needle,...] [--dump 1]
 *     [--stats 1]
 *
 * Prints READY once enforcing, `EVENT <verdict>[ <json bytes>]` per verdict/log
 * event (2=drop 3=ban 4=rst — the pfw_verdict enum), `CONSOLE <line>` per
 * console() message, `STATS <json counters>` once a second through the hold
 * (--stats 1: the last one is how they stood when it ended), and `detached`
 * after stop().
 */
import { PfwVm } from "#/loader.js";
import { compile } from "#/clang";

const argv = yeet.args ?? {};
const list = (v) => (v === undefined ? [] : String(v).split(",").filter((s) => s !== ""));
const pairs = (v) => Object.fromEntries(list(v).map((kv) => { const [name, ...rest] = kv.split("="); return [name, rest.join("=")]; }));
// The program arrives hex-encoded (no atob/TextDecoder in this runtime); it is ASCII.
const src = argv.src ? String.fromCharCode(...argv.src.match(/../g).map((h) => parseInt(h, 16))) : "filter { decide pass; }";

const c = compile(src);
if (!c.ok) { console.log("COMPILE FAIL " + JSON.stringify(c.errors)); yeet.exit(1); }
for (const w of c.warnings) console.log(`WARN line ${w.line}: ${w.text}`);

const VCODE = { pass: 1, drop: 2, ban: 3, rst: 4 };
const vm = new PfwVm({ iface: Number(argv.iface ?? 1) });
vm.onVerdict((e) => {
  /* --dump 1 also prints the bytes log() captured (JSON-escaped), so a test can
   * read what the program was looking at — e.g. a decoded HTTP/2 header view. */
  const data = argv.dump ? " " + JSON.stringify(String.fromCharCode(...e.data)) : "";
  console.log(`EVENT ${VCODE[e.verdict] ?? 0}${data}`);
});
vm.onConsole((line) => console.log(`CONSOLE ${line}`));

await vm.start();
await vm.addCidrs([...list(argv.set), ...list(argv.set6)]);
await vm.addHash(list(argv.hashset));
await vm.addBloom(list(argv.bloom));
await vm.apply(c, {
  argv: list(argv.argv).map((v) => BigInt(v)),
  knobs: Object.fromEntries(Object.entries(pairs(argv.knobs)).map(([k, v]) => [k, BigInt(v || "0")])),
  knobStrs: pairs(argv.kstr),
  shadow: Number(argv.shadow ?? 0) !== 0,
});

console.log(`READY nops=${c.program.nops} decode=${c.program.decode ?? 0} reasm=${c.program.reasm ?? 0}`);
/* --stats 1 prints the counters once a second, so a test can read what the
 * kernel counted and not only what it did. */
const J = (o) => JSON.stringify(o, (_, v) => (typeof v === "bigint" ? Number(v) : v));
for (let i = 0; i < Number(argv.hold ?? 20); i++) {
  await new Promise((r) => setTimeout(r, 1000));
  if (argv.stats) { const s = await vm.stats(); delete s.decide_hist; delete s.timing; console.log(`STATS ${J(s)}`); }
}
await vm.stop();
console.log("detached");
