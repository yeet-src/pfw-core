/* Kernel stack test: push/pop backed by the per-CPU stack map, exercised on real
 * traffic. The program pushes the dport, pops it back, and resets the connection
 * when the round-tripped value matches PORT — so a reset proves push+pop moved the
 * value through the map in the kernel. Needs yeetd + loopback; `npm run test:stack`. */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59711;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"], { cwd: ROOT });
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

const CASES = [
  ["push dport; pop == PORT -> rst", `filter { if (dport != ${PORT}) return pass; push(dport); let x = pop(); if (x == ${PORT}) { log(16); return rst("stk", 0); } return pass; }`, V.RST],
  ["LIFO: push a,b; pop,pop restores a last -> pass guard", `filter { if (dport != ${PORT}) return pass; push(dport); push(proto); let b = pop(); let a = pop(); if (a == ${PORT}) { log(16); return rst("lifo", 0); } return pass; }`, V.RST],
];

const vname = (v) => ({ [V.PASS]: "pass", [V.RST]: "rst" }[v] ?? v);
let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel stack — push/pop via the stack map on :${PORT}\n`);
try {
  for (const [name, source, want] of CASES) {
    await withProgram(source, async (events) => {
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
