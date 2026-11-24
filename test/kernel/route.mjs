/* Kernel test of program routing (`PfwVm.route`): two programs installed at
 * once, each seeing only the packets it is for.
 *
 *   apply()    the default program, for every packet no route claims
 *   route()    a program of its own for one protocol and port; routing the
 *              same packets again swaps it, as apply() swaps the default
 *   unroute()  the port is the default's again
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
};
const LABEL = {
  default_only: "apply(): one program, both ports — ALPHA dropped on each",
  routed: "route(udp/port2): that port runs its own program — BRAVO dropped there, ALPHA not",
  routed_knob_off: "setKnob reaches the routed program by name: it stops dropping",
  rerouted: "route() again swaps the route's program: port2 drops both, the default is untouched",
  default_swapped: "apply() swaps the default under a standing route: only the other port changes",
  unrouted: "unroute(): port2 is the default's again",
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
    for (const port of [PORT, PORT2]) { await send(`ALPHA-${name}`, port); await send(`BRAVO-${name}`, port); }
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
check("a route that cannot exist is refused", line("BADROUTE") === "BADROUTE true");

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
