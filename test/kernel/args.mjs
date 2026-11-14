/* Kernel args test: a subroutine takes an argument (a0) and returns a value (rv),
 * deciding the verdict on real traffic. A reset proves the args calling convention
 * works in the kernel: the caller loaded %a0, called, and read %rv back.
 * Needs yeetd + loopback; `npm run test:args`. */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59731;
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

const source = `fn is_port(p) { rv = 0; if (p == ${PORT}) rv = 1; } filter { if (is_port(dport)) { log(16); decide rst("arg", 0); } decide pass; }`;

let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel args — subroutine takes a0, returns rv, on :${PORT}\n`);
try {
  await withProgram(source, async (events) => {
    await sleep(500);
    const before = events.length;
    await connect();
    await sleep(500);
    const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
    n++; const ok = obs === V.RST; if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} is_port(dport) arg in / rv out -> ${ok ? "rst" : "pass"}`);
  });
} finally { server.close(); }
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
