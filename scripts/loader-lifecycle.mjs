/* Walk a PfwVm through its whole lifecycle on one interface, printing a PHASE
 * line as each state is reached and holding it for a few seconds, so an
 * orchestrator (test/kernel/loader.mjs) can send traffic in each phase.
 *
 *   yeet run scripts/loader-lifecycle.mjs --port N [--iface 1] [--hold 4]
 */
import { PfwVm } from "#/loader.js";
import { load } from "#/index.js";

const argv = yeet.args ?? {};
const port = Number(argv.port), hold = Number(argv.hold ?? 4);
const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));
const phase = async (name, extra = "") => { console.log(`PHASE ${name}${extra ? " " + extra : ""}`); await sleep(hold); };
const J = (o) => JSON.stringify(o, (_, v) => (typeof v === "bigint" ? Number(v) : v));

const A = load(`pattern alpha = "ALPHA"; filter { if (proto != 17) decide pass; if (dport != ${port}) decide pass;
  if (scan(payload, 64) & alpha) { log(8); decide drop("block_alpha"); } decide pass; }`);
const B = load(`pattern bravo = "BRAVO"; filter { if (proto != 17) decide pass; if (dport != ${port}) decide pass;
  if (knob("enforce") ?? 1 == 0) decide pass;
  if (scan(payload, 64) & bravo) { log(8); decide drop("block_bravo"); } decide pass; }`);

const vm = new PfwVm({ iface: Number(argv.iface ?? 1) });
const seen = [];
vm.onVerdict((e) => seen.push(`${e.verdict}:${e.rule}:${e.dport}:${String.fromCharCode(...e.data)}`));

let threw = "";
try { await vm.apply(A); } catch (e) { threw = e.message; }
console.log(`NOTRUNNING ${threw.includes("not running")}`);

await vm.start();
let twice = "";
try { await vm.start(); } catch (e) { twice = e.message; }
console.log(`STARTTWICE ${twice.includes("already running")}`);
await phase("started");                    // attached, no program: everything passes

await vm.apply(A);
await phase("A");                          // ALPHA dropped, BRAVO passes
console.log(`STATS_A ${J((await vm.stats()).rules)} EVENTS ${J(seen)}`);
{
  /* Every packet the program ran on is in exactly one histogram bucket. */
  const s = await vm.stats(), h = s.decide_hist;
  console.log(`HIST ${J({ buckets: h.counts.length, bounds: h.bounds.length, sum: h.counts.reduce((a, v) => a + v, 0n), ran: s.ran })}`);
}

await vm.apply(B);
await phase("B");                          // swapped: ALPHA passes again, BRAVO dropped

await vm.setKnob("enforce", 0);
await phase("B_knob_off");                 // live knob: nothing dropped

await vm.setKnob("enforce", 1);
await vm.apply(A);                         // back into the generation A used before
await phase("A_again");

await vm.clear();
await phase("cleared");                    // still attached, nothing enforced

await vm.stop();
await vm.stop();                           // twice is harmless
console.log(`RUNNING_AFTER_STOP ${vm.running}`);
await phase("stopped");                    // detached

await vm.start();                          // the hook is free again; state starts clean
await vm.apply(B);
await phase("restarted_B");
await vm.stop();
console.log("DONE");
