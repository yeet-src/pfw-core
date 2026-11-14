/* Kernel knob test: the live control plane. The SAME loaded bytecode behaves
 * differently depending on the host-set knob, written into the `knobs` map:
 *
 *   filter { if (dport != PORT) decide pass;
 *            if (knob("block") == 1) { log(16); decide rst("blk", 0); }
 *            decide pass; }
 *
 *   - loaded with no knobs       -> knob("block")=0 -> :PORT passes (no event)
 *   - loaded with --knobs block=1 -> :PORT is reset (RST event)
 *
 * Proves the host can drive a running program by writing a named control value.
 * Needs yeetd + loopback; `npm run test:knob`. */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59741;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, knobs, fn) {
  const args = ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"];
  if (knobs) args.push("--knobs", knobs);
  const child = spawn("yeet", args, { cwd: ROOT });
  const events = [];
  let out = "";
  child.stdout.on("data", (d) => { out += d; for (const m of String(d).matchAll(/EVENT (\d+)/g)) events.push(Number(m[1])); });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 120 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(events); } finally { child.kill("SIGINT"); await sleep(400); }
}

function connect() {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "127.0.0.1", port: PORT });
    const done = () => { try { sock.destroy(); } catch {} resolve(); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => { sock.write("x"); setTimeout(done, 300); });
    sock.on("data", done); sock.on("error", done);
  });
}

const source = `filter { if (dport != ${PORT}) decide pass; if (knob("block") == 1) { log(16); decide rst("blk", 0); } decide pass; }`;
const CASES = [
  ["no knobs -> block=0 -> pass", null, V.PASS],
  ["--knobs block=1 -> rst", "block=1", V.RST],
];

const vname = (v) => ({ [V.PASS]: "pass", [V.RST]: "rst" }[v] ?? v);
let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel knob — host-set control drives the same bytecode on :${PORT}\n`);
try {
  for (const [name, knobs, want] of CASES) {
    await withProgram(source, knobs, async (events) => {
      await sleep(500);
      const before = events.length;
      await connect();
      await sleep(500);
      const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
      n++; const ok = obs === want; if (!ok) fail++;
      console.log(`  ${ok ? "ok  " : "FAIL"} ${name}: kernel=${vname(obs)}`);
    });
  }
} finally { server.close(); }
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
