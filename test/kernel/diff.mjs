/* Kernel differential: for a set of (program, payload) cases, run the payload
 * through BOTH the reference interpreter AND the real kernel (load the object,
 * apply the program, send the payload over loopback, observe the verdict), and
 * assert they agree. This is the check yeet can't do in-process — there is no
 * BPF_PROG_TEST_RUN — so it uses live traffic: ECONNRESET == the kernel sent a
 * RST, a served/clean close == PASS. Needs yeetd and loopback; run with
 * `npm run test:kernel` (node). Non-reasm, payload/header programs only, so one
 * packet settles the verdict and the interpreter frame == the TCP payload.
 */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { compile } from "#/clang";
import { build } from "#/ac.js";
import { machine, V } from "#/interp.js";
import { LIMITS } from "#/isa.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59596;
const ip = (s) => s.split(".").reduce((a, o) => ((a << 8) | Number(o)) >>> 0, 0) >>> 0;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

/* Reference verdict: run the program over the payload with loopback's 5-tuple. */
function reference(source, payload) {
  const c = compile(source);
  if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors));
  const run = machine({ asm: c, tables: build(c.patterns, c.nocase) });
  const r = run(Uint8Array.from(payload), 0, { ac: 0, mask: 0n }, { proto: 6, dport: PORT, saddr: ip("127.0.0.1") });
  return r.verdict;
}

/* Just send the payload (and close); the verdict is read from the loader's
 * event stream, not from this socket (RST on a SYN never surfaces as
 * ECONNRESET). */
function send(payload) {
  return new Promise((resolve) => {
    const sock = net.connect(PORT, "127.0.0.1");
    const done = () => { try { sock.destroy(); } catch {} resolve(); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => { sock.write(Buffer.from(payload)); setTimeout(done, 300); });
    sock.on("data", done);
    sock.on("error", done);
  });
}

/* Run `fn(events)` with a loader holding `source`. `events` is the growing list
 * of kernel verdict numbers printed by the loader. */
async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"], { cwd: ROOT });
  const events = [];
  let out = "";
  const onData = (d) => {
    out += d;
    for (const m of String(d).matchAll(/EVENT (\d+)/g)) events.push(Number(m[1]));
  };
  child.stdout.on("data", onData);
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 120 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(events); } finally { child.kill("SIGINT"); await sleep(400); }
}

/* The kernel verdict for one send = the enforcement event it produced (rst beats
 * drop beats ban in the unlikely event of several), or PASS if it produced none. */
function verdictFrom(newEvents) {
  if (newEvents.includes(V.RST)) return V.RST;
  if (newEvents.includes(V.DROP)) return V.DROP;
  if (newEvents.includes(V.BAN)) return V.BAN;
  return V.PASS;
}

/* Additions that nearly fill a program: three instructions each, sixteen to a
 * `repeat` (which unrolls at most 1024 times), and room left for the rest. */
const LONG = 16 * Math.min(1024, Math.floor((LIMITS.MAX_OPS - 64) / 48));
const vname = (v) => ({ [V.PASS]: "pass", [V.DROP]: "drop", [V.BAN]: "ban", [V.RST]: "rst" }[v] ?? v);
const enc = (s) => Buffer.from(s, "latin1");

// The kernel only emits an event (how we read its verdict) when a rule logs, so
// enforcement arms carry a log(); it is a no-op in the reference interpreter, so
// verdicts are unchanged. PASS arms don't log -> no event -> observed as PASS.
const CASES = [
  { name: "scan match → rst", source: `pattern bot = "GPTBot";\nfilter { if (dport != ${PORT}) decide pass; if (scan(payload, 256) & bot) { log(16); decide rst("bot", 0); } decide pass; }`,
    sends: [["matching", enc("hi GPTBot here")], ["clean", enc("just a normal request")]] },
  { name: "cidr loopback → rst", source: `filter { if (proto != 6) decide pass; if (dport != ${PORT}) decide pass; if (src in "127.0.0.0/8") { log(16); decide rst("lo", 0); } decide pass; }`,
    sends: [["from 127/8", enc("anything")]] },
  { name: "cidr 10/8 (no match) → pass", source: `filter { if (dport != ${PORT}) decide pass; if (src in "10.0.0.0/8") { log(16); decide rst("rfc1918", 0); } decide pass; }`,
    sends: [["from 127, not 10/8", enc("anything")]] },
  { name: "scan match → drop", source: `pattern bot = "GPTBot";\nfilter { if (dport != ${PORT}) decide pass; if (scan(payload, 256) & bot) { log(16); decide drop("bot"); } decide pass; }`,
    sends: [["matching", enc("x GPTBot x")], ["clean", enc("nothing here")]] },
  { name: "nocase scan → rst", source: `nocase;\npattern bot = "GPTBot";\nfilter { if (dport != ${PORT}) decide pass; if (scan(payload, 256) & bot) { log(16); decide rst("bot", 0); } decide pass; }`,
    sends: [["lowercase gptbot", enc("x gptbot x")], ["MiXeD GpTbOt", enc("y GpTbOt y")], ["no bot", enc("plain text")]] },
  { name: "dport guard → pass", source: `pattern bot = "GPTBot";\nfilter { if (dport != 1) decide pass; if (scan(payload, 256) & bot) { log(16); decide rst("bot", 0); } decide pass; }`,
    sends: [["wrong-port rule", enc("GPTBot but rule targets :1")]] },
  // A program that nearly fills the instruction budget, whose verdict depends
  // on every instruction having run.
  { name: "a long program → rst", source: `filter { if (dport != ${PORT}) decide pass; let x = 0; repeat (${LONG / 16}) { repeat (16) { x = x + 1; } } if (x == ${LONG}) { log(16); decide rst("long", 0); } decide pass; }`,
    sends: [["every instruction runs", enc("anything")]] },
  // One segment, the signature 3000 bytes in: past the 2048 a scan once covered.
  { name: "a signature deep in the packet → rst", source: `pattern sig = "GPTBot";\nfilter { if (dport != ${PORT}) decide pass; if (scan(payload, 4096) & sig) { log(16); decide rst("deep", 0); } decide pass; }`,
    sends: [["3000 bytes in", enc("x".repeat(3000) + "GPTBot")], ["not there", enc("x".repeat(3000) + "GPTBo")]] },
  // Thirty locals, all live until the sum: more than the sixteen scratch
  // registers there once were, so some sit on %s16 and up.
  { name: "thirty live locals → rst", source: `filter { if (dport != ${PORT}) decide pass; ${Array.from({ length: 30 }, (_, i) => `let v${i} = ${i + 1};`).join(" ")} let sum = ${Array.from({ length: 30 }, (_, i) => `v${i}`).join(" + ")}; if (sum == 465) { log(16); decide rst("locals", 0); } decide pass; }`,
    sends: [["every local keeps its value", enc("anything")]] },
  // A 200-byte signature: over the 64 bytes a pattern once held.
  { name: "a 200-byte pattern → rst", source: `pattern long = "${"ab".repeat(99)}yz";\nfilter { if (dport != ${PORT}) decide pass; if (scan(payload, 1024) & long) { log(16); decide rst("long_pat", 0); } decide pass; }`,
    sends: [["the whole signature", enc("--" + "ab".repeat(99) + "yz--")], ["its last byte wrong", enc("--" + "ab".repeat(99) + "yy--")]] },
];

let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel differential — reference vs real kernel on :${PORT}\n`);
try {
  for (const c of CASES) {
    await withProgram(c.source, async (events) => {
      for (const [label, payload] of c.sends) {
        const ref = reference(c.source, payload);
        // Drain stragglers (a dropped packet keeps being retransmitted) so the
        // window only holds events caused by THIS send.
        await sleep(700);
        const before = events.length;
        await send(payload);
        await sleep(700);
        const obs = verdictFrom(events.slice(before));
        n++;
        const ok = obs === ref;
        if (!ok) fail++;
        console.log(`  ${ok ? "ok  " : "FAIL"} ${c.name} / ${label}: reference=${vname(ref)} kernel=${vname(obs)}`);
      }
    });
  }
} finally { server.close(); }
console.log(`\n${n - fail}/${n} agree`);
process.exit(fail ? 1 : 0);
