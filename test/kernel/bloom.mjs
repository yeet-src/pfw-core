/* Kernel bloom test: load a `dport in bloom` program plus a set of ports into
 * the bloom filter, send loopback traffic, and read the verdict — RST when the
 * destination port is in the set, PASS otherwise. Proves probabilistic membership in
 * the kernel. Needs yeetd + loopback; `npm run test:bloom` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, hashset, port, fn) {
  const args = ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"];
  if (hashset) args.push("--bloom", hashset);
  const child = spawn("yeet", args, { cwd: ROOT });
  const events = [];
  let out = "";
  child.stdout.on("data", (d) => { out += d; for (const m of String(d).matchAll(/EVENT (\d+)/g)) events.push(Number(m[1])); });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(events); } finally { child.kill("SIGINT"); await sleep(400); }
}

function hit(port) {
  return new Promise((resolve) => {
    const sock = net.connect(port, "127.0.0.1");
    const done = () => { try { sock.destroy(); } catch {} resolve(); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => { sock.write("x"); setTimeout(done, 300); });
    sock.on("data", done); sock.on("error", done);
  });
}

const vname = (v) => ({ [V.PASS]: "pass", [V.RST]: "rst" }[v] ?? v);
let fail = 0, n = 0;
// Two listeners: one on a port in the set, one not; the program resets ports in the set.
const PORT_IN = 59631, PORT_OUT = 59632;
const source = `filter { if (dport in bloom) { log(16); decide rst("bloom_port", 0); } decide pass; }`;
const servers = [PORT_IN, PORT_OUT].map((p) => { const s = net.createServer((c) => { c.on("data", () => c.write("ok")); c.on("error", () => {}); }); return new Promise((r) => s.listen(p, "127.0.0.1", () => r(s))); });
const srv = await Promise.all(servers);
console.log("kernel hash — bloom port membership\n");
try {
  await withProgram(source, String(PORT_IN), PORT_IN, async (events) => {
    for (const [name, port, want] of [["present port -> rst", PORT_IN, V.RST], ["absent port -> pass", PORT_OUT, V.PASS]]) {
      await sleep(700);
      const before = events.length;
      await hit(port);
      await sleep(700);
      const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
      n++;
      const ok = obs === want;
      if (!ok) fail++;
      console.log(`  ${ok ? "ok  " : "FAIL"} ${name}: kernel=${vname(obs)}`);
    }
  });
} finally { srv.forEach((s) => s.close()); }
console.log(`\n${n - fail}/${n} agree`);
process.exit(fail ? 1 : 0);
