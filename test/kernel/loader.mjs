/* Kernel test of the embeddable loader (`pfw-core/loader`, class PfwVm): its
 * whole lifecycle against live loopback traffic.
 *
 *   start()  attaches with no program — everything passes
 *   apply()  enforces; a second apply() swaps atomically and leaves nothing of
 *            the first program's automaton behind (in either generation)
 *   setKnob  steers the running program without a reload
 *   clear()  stops enforcing but stays attached
 *   stop()   detaches (twice is harmless); start() works again afterwards
 *   stats()/onVerdict report what happened by rule NAME
 *
 * scripts/loader-lifecycle.mjs walks the phases and holds each; this sends two
 * datagrams per phase and checks which arrive. Needs yeetd + loopback;
 * `npm run test:loader` (node). */
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59721;

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

const got = [];
const srv = dgram.createSocket("udp4");
srv.on("message", (m) => got.push(m.toString()));
await new Promise((r) => srv.bind(PORT, "127.0.0.1", r));
const cli = dgram.createSocket("udp4");
const send = (msg) => new Promise((r) => cli.send(msg, PORT, "127.0.0.1", r));

/* What each phase must deliver of ["ALPHA", "BRAVO"]. */
const EXPECT = {
  started: ["ALPHA", "BRAVO"], A: ["BRAVO"], B: ["ALPHA"], B_knob_off: ["ALPHA", "BRAVO"],
  A_again: ["BRAVO"], cleared: ["ALPHA", "BRAVO"], stopped: ["ALPHA", "BRAVO"], restarted_B: ["ALPHA"],
};
const LABEL = {
  started: "start(): attached with no program, everything passes",
  A: "apply(A): ALPHA is dropped, BRAVO passes",
  B: "apply(B): swapped — ALPHA passes again (no stale automaton), BRAVO is dropped",
  B_knob_off: "setKnob(\"enforce\", 0): the running program stops dropping, no reload",
  A_again: "apply(A) into the generation it used before: ALPHA dropped, BRAVO passes",
  cleared: "clear(): still attached, nothing enforced",
  stopped: "stop(): detached, everything passes",
  restarted_B: "start() again after stop(): the hook was released, B enforces",
};

console.log("kernel loader — PfwVm lifecycle on loopback\n");
const lines = [];
const seenPhases = new Set();
const pending = [];
const child = spawn("yeet", ["run", "scripts/loader-lifecycle.mjs", "--port", String(PORT), "--hold", "3"], { cwd: ROOT });
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
    await send(`ALPHA-${name}`); await send(`BRAVO-${name}`);
    await sleep(700);
    const arrived = got.slice(mark).map((g) => g.split("-")[0]).sort();
    check(LABEL[name] ?? name, JSON.stringify(arrived) === JSON.stringify(EXPECT[name]), `delivered ${JSON.stringify(arrived)}`);
  })());
};
child.stdout.on("data", (d) => { out += d; buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { onLine(buf.slice(0, i)); buf = buf.slice(i + 1); } });
child.stderr.on("data", (d) => { out += d; });
await new Promise((r) => child.on("exit", r));
await Promise.all(pending);
srv.close(); cli.close();

const line = (p) => lines.find((l) => l.startsWith(p)) ?? "";
check("every phase ran", Object.keys(EXPECT).every((p) => seenPhases.has(p)) && lines.includes("DONE"), out.includes("resource busy") ? "XDP hook busy" : [...seenPhases].join(","));
check("apply() before start() is refused", line("NOTRUNNING") === "NOTRUNNING true");
check("start() twice is refused", line("STARTTWICE") === "STARTTWICE true");
check("stop() twice is harmless and leaves it not running", line("RUNNING_AFTER_STOP") === "RUNNING_AFTER_STOP false");
const statsA = line("STATS_A");
check("stats() counts the drop under its rule name", /"block_alpha":1/.test(statsA), statsA.slice(0, 120));
check("onVerdict delivers verdict, rule name, port and the logged bytes", statsA.includes(`drop:block_alpha:${PORT}:ALPHA-A`), statsA.slice(-80));

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
