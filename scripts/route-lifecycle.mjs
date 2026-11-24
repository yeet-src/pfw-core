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

/* A program every packet runs first. It drops CHARLIE wherever it is headed;
 * everything else goes on to the program it was always going to. */
const FIRST = load(`pattern charlie = "CHARLIE"; filter {
  if (proto != 17) decide pass;
  if (scan(payload, 64) & charlie) { log(8); decide drop("no_charlie"); } decide pass; }`);
await vm.apply(DEFAULT);
await vm.route(route, BRAVO);
seen.length = 0;
await vm.first(FIRST);
await phase("first");                      // CHARLIE dropped on both ports; ALPHA and BRAVO as routed
{
  const s = await vm.stats();
  console.log(`STATS_FIRST ${J({ first: s.first[0]?.rules, default: s.rules, routed: s.routes[`udp/${port2}`]?.rules })} EVENTS ${J(seen)}`);
}
/* A chain: a second stage, which drops DELTA, after the first. */
const SECOND = load(`pattern delta = "DELTA"; filter {
  if (proto != 17) decide pass;
  if (scan(payload, 64) & delta) decide drop("no_delta"); decide pass; }`);
await vm.first([FIRST, SECOND]);
await phase("chain");                      // CHARLIE and DELTA dropped on both ports, each by its stage
{
  const s = await vm.stats();
  console.log(`STATS_CHAIN ${J(s.first.map((f) => [f.name, f.rules]))}`);
}
await vm.first(null);
await phase("first_gone");                 // CHARLIE passes again; the rest unchanged

/* Routes by more than a port. The port route on port2 stands throughout. */
const lo = Number(argv.iface ?? 1), port = Number(argv.port);
await vm.route({ iface: lo, proto: "udp" }, BOTH);
await phase("iface");                      // every UDP packet on the interface — but a port route is more specific
console.log(`UNROUTE_IFACE ${await vm.unroute({ iface: lo, proto: "udp" })}`);

await vm.route({ dst: "127.0.0.0/8", proto: "udp", dport: port }, BOTH);
await phase("dst_port");                   // a prefix and a port: only the first port
await vm.unroute({ dst: "127.0.0.0/8", proto: "udp", dport: port });

await vm.route({ dst: "127.0.0.1" }, BOTH);
await phase("dst");                        // a prefix beats a port route: both ports
console.log(`ROUTES ${J(Object.keys(vm.routes).sort())}`);
await vm.unroute({ dst: "127.0.0.1" });
await phase("dst_gone");                   // back to the port route and the default

/* A knob two programs declare with different defaults, and the host has not
 * set: the one installed second does not change the value under the first. */
const G_ROUTE = load(`pattern bravo = "BRAVO"; filter { if (knob("gate") ?? 1 == 0) decide pass;
  if (scan(payload, 64) & bravo) decide drop("g_bravo"); decide pass; }`);
const G_DEFAULT = load(`pattern alpha = "ALPHA"; filter { if (proto != 17) decide pass; if (knob("gate") ?? 0 == 0) decide pass;
  if (scan(payload, 64) & alpha) decide drop("g_alpha"); decide pass; }`);
await vm.route(route, G_ROUTE);
await vm.apply(G_DEFAULT);
await phase("knob_default");               // gate is still 1: both programs enforce

/* Swaps in a row do not wait out the last one's grace. */
{
  const t = Date.now();
  for (let i = 0; i < 4; i++) await vm.apply(G_DEFAULT);
  console.log(`APPLY4_MS ${Date.now() - t}`);
}

let many = "";
try { await vm.first(new Array(9).fill(FIRST)); } catch (e) { many = e.message; }
console.log(`FIRST_MANY ${many.includes("at most")}`);

let stateful = "";
try { await vm.first(load(`reassemble 80; filter { decide pass; }`)); } catch (e) { stateful = e.message; }
console.log(`FIRST_REASM ${stateful.includes("reassemble")}`);

let bad = "";
try { await vm.route({ proto: "tcp", dport: 70000 }, BRAVO); } catch (e) { bad = e.message; }
let bare = "", none = "";
try { await vm.route({ dport: 80 }, BRAVO); } catch (e) { bare = e.message; }
try { await vm.route({}, BRAVO); } catch (e) { none = e.message; }
console.log(`BADROUTE ${bad.includes("dport")} ${bare.includes("needs its proto")} ${none.includes("at least one")}`);

/* Prefix routes that also name an interface, or a protocol and no port. */
await vm.route({ dst: "127.0.0.0/8", proto: "udp" }, BOTH);
await phase("dst_proto");                  // every UDP packet to the prefix: both ports
await vm.unroute({ dst: "127.0.0.0/8", proto: "udp" });
await vm.route({ dst: "127.0.0.0/8", iface: lo }, BOTH);
await phase("dst_iface");                  // the prefix on one interface: both ports again
console.log(`ROUTES2 ${J(Object.keys(vm.routes).sort())}`);
await vm.unroute({ dst: "127.0.0.0/8", iface: lo });

/* Per-connection state in a stage, apart from the dispatched program's. Both
 * count the packets of a connection: the stage lets two through, and the
 * program it hands them to drops the first it sees. Were the count shared, the
 * first packet would be the one to arrive. */
await vm.unroute(route);
await vm.apply(load(`filter { if (proto != 17) decide pass; let n = flow.count; if (n == 1) decide drop("own_first"); decide pass; }`));
await vm.first(load(`filter { if (proto != 17) decide pass; let n = flow.count; if (n > 2) decide drop("stage_third"); decide pass; }`));
await phase("stage_state");
{
  const s = await vm.stats();
  console.log(`STATS_STAGE ${J({ stage: s.first[0]?.rules, own: s.rules })}`);
}
await vm.first(null);

/* A source ban outlives the program that made it, and holds with no program. */
await vm.apply(load(`pattern alpha = "ALPHA"; filter { if (proto != 17) decide pass;
  if (scan(payload, 64) & alpha) decide ban("banned", 12); decide pass; }`));
await phase("ban");                        // ALPHA bans the sender: nothing more from it arrives, on any port
await vm.clear();
await phase("ban_cleared");                // no default program now, and the ban still stands

await vm.stop();
console.log("DONE");
