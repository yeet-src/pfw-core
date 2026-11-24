/* Kernel test of program routing (`PfwVm.route`): two programs installed at
 * once, each seeing only the packets it is for.
 *
 *   apply()    the default program, for every packet no route claims
 *   route()    a program of its own for one protocol and port; routing the
 *              same packets again swaps it, as apply() swaps the default
 *   unroute()  the port is the default's again
 *   first()    a program every packet runs before its own: it drops, or passes
 *              the packet on to the program it was dispatched to
 *   knobs      reach every program that declares them, by name
 *   stats(), onVerdict, onConsole report per program: a rule, a format and a
 *              count belong to the program that owns them
 *
 * scripts/route-lifecycle.mjs walks the phases and holds each; this sends the
 * same two datagrams to two ports per phase and checks which arrive. Needs
 * yeetd + loopback; `npm run test:route` (node). */
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59731, PORT2 = 59732;

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

const got = [];
const listen = (port) => new Promise((r) => { const s = dgram.createSocket("udp4"); s.on("message", (m) => got.push(`${port}:${m}`)); s.bind(port, "127.0.0.1", () => r(s)); });
const servers = [await listen(PORT), await listen(PORT2)];
const cli = dgram.createSocket("udp4");
const send = (msg, port) => new Promise((r) => cli.send(msg, port, "127.0.0.1", r));

/* What each phase must deliver of ALPHA and BRAVO, on the default's port and on
 * the routed one. */
const EXPECT = {
  default_only: { [PORT]: ["BRAVO"], [PORT2]: ["BRAVO"] },
  routed: { [PORT]: ["BRAVO"], [PORT2]: ["ALPHA"] },
  routed_knob_off: { [PORT]: ["BRAVO"], [PORT2]: ["ALPHA", "BRAVO"] },
  rerouted: { [PORT]: ["BRAVO"], [PORT2]: [] },
  default_swapped: { [PORT]: ["ALPHA"], [PORT2]: [] },
  unrouted: { [PORT]: ["ALPHA"], [PORT2]: ["ALPHA"] },
  first: { [PORT]: ["BRAVO"], [PORT2]: ["ALPHA"] },
  chain: { [PORT]: ["BRAVO"], [PORT2]: ["ALPHA"] },
  first_gone: { [PORT]: ["BRAVO", "CHARLIE"], [PORT2]: ["ALPHA", "CHARLIE"] },
  iface: { [PORT]: [], [PORT2]: ["ALPHA"] },
  dst_port: { [PORT]: [], [PORT2]: ["ALPHA"] },
  dst: { [PORT]: [], [PORT2]: [] },
  dst_gone: { [PORT]: ["BRAVO"], [PORT2]: ["ALPHA"] },
  knob_default: { [PORT]: ["BRAVO"], [PORT2]: ["ALPHA"] },
  ban: { [PORT]: [], [PORT2]: [] },
  ban_cleared: { [PORT]: [], [PORT2]: [] },
};
/* The phases that send a third word, for the first program to catch. */
const WORDS = { first: ["ALPHA", "BRAVO", "CHARLIE"], chain: ["ALPHA", "BRAVO", "CHARLIE", "DELTA"], first_gone: ["ALPHA", "BRAVO", "CHARLIE"] };
const LABEL = {
  default_only: "apply(): one program, both ports — ALPHA dropped on each",
  routed: "route(udp/port2): that port runs its own program — BRAVO dropped there, ALPHA not",
  routed_knob_off: "setKnob reaches the routed program by name: it stops dropping",
  rerouted: "route() again swaps the route's program: port2 drops both, the default is untouched",
  default_swapped: "apply() swaps the default under a standing route: only the other port changes",
  unrouted: "unroute(): port2 is the default's again",
  first: "first(): CHARLIE is dropped on both ports before either program sees it; the rest goes on as routed",
  chain: "first([a, b]): a chain — CHARLIE dropped by the first stage, DELTA by the second, the rest goes on",
  first_gone: "first(null): CHARLIE passes again, the routed programs are as they were",
  iface: "route({ iface, proto }): every UDP packet on the interface, but for the port a more specific route has",
  dst_port: "route({ dst, proto, dport }): a destination prefix and a port — only that port",
  dst: "route({ dst }): a destination prefix beats a port route — both ports",
  dst_gone: "unroute({ dst }): back to the port route and the default",
  knob_default: "a knob two programs default differently keeps the value the first one gave it",
  ban: "a ban is the source's: after ALPHA nothing from it arrives, whichever program the port has",
  ban_cleared: "clear(): no default program, and the standing ban still holds",
};

console.log("kernel routing — two programs, one VM, on loopback\n");
const lines = [], seenPhases = new Set(), pending = [];
const child = spawn("yeet", ["run", "scripts/route-lifecycle.mjs", "--port", String(PORT), "--port2", String(PORT2), "--hold", "3"], { cwd: ROOT });
let out = "", buf = "";
const onLine = (line) => {
  lines.push(line);
  const m = line.match(/^PHASE (\S+)/);
  if (!m) return;
  const name = m[1];
  seenPhases.add(name);
  pending.push((async () => {
    await sleep(500);
    const mark = got.length;
    for (const port of [PORT, PORT2]) for (const word of WORDS[name] ?? ["ALPHA", "BRAVO"]) await send(`${word}-${name}`, port);
    await sleep(700);
    const arrived = { [PORT]: [], [PORT2]: [] };
    for (const g of got.slice(mark)) { const [port, msg] = g.split(":"); arrived[port].push(msg.split("-")[0]); }
    for (const port of [PORT, PORT2]) arrived[port].sort();
    check(LABEL[name] ?? name, JSON.stringify(arrived) === JSON.stringify(EXPECT[name]), `delivered ${JSON.stringify(arrived)}`);
  })());
};
child.stdout.on("data", (d) => { out += d; buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { onLine(buf.slice(0, i)); buf = buf.slice(i + 1); } });
child.stderr.on("data", (d) => { out += d; });
await new Promise((r) => child.on("exit", r));
await Promise.all(pending);
for (const s of servers) s.close();
cli.close();

const line = (p) => lines.find((l) => l.startsWith(p)) ?? "";
check("every phase ran", Object.keys(EXPECT).every((p) => seenPhases.has(p)) && lines.includes("DONE"), out.includes("resource busy") ? "XDP hook busy" : [...seenPhases].join(",") + " " + out.slice(-300));
const routed = line("STATS_ROUTED");
const name = `udp/${PORT2}`;
/* By then the default has dropped ALPHA on both ports, and once more on its own
 * port after the route took the other; the routed program has dropped one BRAVO. */
check("stats() counts each program's rules under its own names", /"default":\{[^}]*"no_alpha":3/.test(routed) && new RegExp(`"${name}":\\{[^]*"no_bravo":1`).test(routed), routed.slice(0, 220));
check("vm.routes lists the route by name", routed.includes(`"names":["${name}"]`));
check("onVerdict names the rule and the route it came from", routed.includes(`drop:no_bravo:${name}:${PORT2}`) && routed.includes(`drop:no_alpha:default:${PORT}`), routed.slice(routed.indexOf("EVENTS"), routed.indexOf("EVENTS") + 200));
check("onConsole formats with the routed program's own format", routed.includes(`"bravo on ${PORT2}"`), routed.slice(routed.indexOf("SAID")));
check("unroute() reports whether there was a route", line("UNROUTE") === "UNROUTE true AGAIN false", line("UNROUTE"));
check("a route that cannot exist is refused: a bad port, a port with no protocol, a prefix with half a port", line("BADROUTE") === "BADROUTE true true true", line("BADROUTE"));
const chain = line("STATS_CHAIN");
check("each stage of a chain counts its own drops, under its own name", chain.includes(`["first",{"-":0,"no_charlie":2}]`) && chain.includes(`["first.1",{"-":0,"no_delta":2}]`), chain);
check("a chain longer than a packet can run is refused", line("FIRST_MANY") === "FIRST_MANY true");
check("unroute() of an interface route", line("UNROUTE_IFACE") === "UNROUTE_IFACE true");
check("vm.routes names a prefix route by its prefix", line("ROUTES") === `ROUTES ["127.0.0.1/32","udp/${PORT2}"]`, line("ROUTES"));
/* Four applies of a small program, some 30 ms each. Before the grace was made
 * lazy each also waited 50 ms for the one before it: over 200 ms in all. */
const apply4 = Number(line("APPLY4_MS").split(" ")[1]);
check("swaps in a row do not wait out each other's grace", apply4 > 0 && apply4 < 180, line("APPLY4_MS"));
const first = line("STATS_FIRST");
/* One CHARLIE to each port, both stopped by the first program; one ALPHA and
 * one BRAVO reached the program of the port they were sent to and were dropped
 * there, so each of the three programs counted its own. */
check("the first program and the dispatched ones each count their own drops", /"first":\{[^}]*"no_charlie":2/.test(first) && /"default":\{[^}]*"no_alpha":1/.test(first) && /"routed":\{[^}]*"no_bravo":1/.test(first), first.slice(0, 200));
check("...and their events say which program", first.includes(`drop:no_charlie:first:${PORT}`) && first.includes(`drop:no_charlie:first:${PORT2}`) && first.includes(`drop:no_bravo:udp/${PORT2}:${PORT2}`), first.slice(first.indexOf("EVENTS")));
check("a first program that would reassemble is refused", line("FIRST_REASM") === "FIRST_REASM true");

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
