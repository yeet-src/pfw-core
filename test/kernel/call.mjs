/* Kernel call/ret test: a subroutine makes the decision on real traffic. call
 * pushes the return pc on the data stack and jumps to the routine; the routine
 * sets a register and the implicit ret returns; the caller acts on it. A reset
 * proves the call ran the routine AND ret returned to the caller in the kernel.
 * Needs yeetd + loopback; `npm run test:call`. */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59721;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"], { cwd: ROOT });
  const events = [];
  let out = "";
  child.stdout.on("data", (d) => { out += d; for (const m of String(d).matchAll(/EVENT (\d+)/g)) events.push(Number(m[1])); });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
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

// a routine computes the verdict flag into %bp; the caller acts on it
const source = `fn pick() { bp = 0; if (dport == ${PORT}) bp = 1; } filter { pick(); if (bp == 1) { log(16); decide rst("sub", 0); } decide pass; }`;

let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel call/ret — subroutine decides on :${PORT}\n`);
try {
  await withProgram(source, async (events) => {
    await sleep(500);
    const before = events.length;
    await connect();
    await sleep(500);
    const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
    n++; const ok = obs === V.RST; if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} call pick(); ret; act on %bp -> ${ok ? "rst" : "pass"}`);
  });
} finally { server.close(); }
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
