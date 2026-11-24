/* Walk a PfwVm through routing: a default program and a program of its own for
 * one port, swapped and taken away again. Prints a PHASE line as each state is
 * reached and holds it, so an orchestrator (test/kernel/route.mjs) can send
 * traffic in each phase.
 *
 *   yeet run scripts/route-lifecycle.mjs --port N --port2 M [--iface 1] [--hold 3]
 */
import { PfwVm } from "#/loader.js";
import { load } from "#/index.js";

const argv = yeet.args ?? {};
const port2 = Number(argv.port2), hold = Number(argv.hold ?? 3);
const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));
const phase = async (name) => { console.log(`PHASE ${name}`); await sleep(hold); };
const J = (o) => JSON.stringify(o, (_, v) => (typeof v === "bigint" ? Number(v) : v));

/* Neither program looks at the port: which packets it sees is the route's doing. */
const DEFAULT = load(`pattern alpha = "ALPHA"; filter { if (proto != 17) decide pass;
  if (scan(payload, 64) & alpha) { log(8); decide drop("no_alpha"); } decide pass; }`);
const BRAVO = load(`pattern bravo = "BRAVO"; filter {
  if (knob("enforce") ?? 1 == 0) decide pass;
  if (scan(payload, 64) & bravo) { log(8); console("bravo on %d", dport); decide drop("no_bravo"); } decide pass; }`);
const BOTH = load(`pattern alpha = "ALPHA", bravo = "BRAVO"; filter {
  if (any(scan(payload, 64), alpha, bravo)) decide drop("neither"); decide pass; }`);

const vm = new PfwVm({ iface: Number(argv.iface ?? 1) });
const seen = [], said = [];
vm.onVerdict((e) => seen.push(`${e.verdict}:${e.rule}:${e.route}:${e.dport}`));
vm.onConsole((line) => said.push(line));
const route = { proto: "udp", dport: port2 };

await vm.start();
await vm.apply(DEFAULT);
await phase("default_only");               // both ports: ALPHA dropped

await vm.route(route, BRAVO);
await phase("routed");                     // port2 runs BRAVO's program instead: BRAVO dropped, ALPHA passes
{
  const s = await vm.stats();
  console.log(`STATS_ROUTED ${J({ default: s.rules, routes: s.routes, names: Object.keys(vm.routes) })} EVENTS ${J(seen)} SAID ${J(said)}`);
}

await vm.setKnob("enforce", 0);
await phase("routed_knob_off");            // a knob reaches the routed program by name

await vm.setKnob("enforce", 1);
await vm.route(route, BOTH);
await phase("rerouted");                   // the route's program swapped: port2 drops both

await vm.apply(BRAVO);
await phase("default_swapped");            // the default swapped under a standing route

console.log(`UNROUTE ${await vm.unroute(route)} AGAIN ${await vm.unroute(route)}`);
await phase("unrouted");                   // port2 is back on the default (now BRAVO's program)

let bad = "";
try { await vm.route({ proto: "tcp", dport: 70000 }, BRAVO); } catch (e) { bad = e.message; }
console.log(`BADROUTE ${bad.includes("dport")}`);

await vm.stop();
console.log("DONE");
