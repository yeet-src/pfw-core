/* Kernel IPv6 test: load a `src6 in set6` program plus a set of v6 CIDRs into the
 * lpm6 trie, send loopback traffic from ::1, and read the verdict — RST when the
 * v6 source is in the set, PASS otherwise. Proves IPv6 longest-prefix membership
 * (the op reads the v6 source straight from the packet). Needs yeetd + IPv6
 * loopback; `npm run test:lpm6` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59641;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, set6, fn) {
  const args = ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"];
  if (set6) args.push("--set6", set6);
  const child = spawn("yeet", args, { cwd: ROOT });
  const events = [];
  let out = "";
  child.stdout.on("data", (d) => { out += d; for (const m of String(d).matchAll(/EVENT (\d+)/g)) events.push(Number(m[1])); });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 120 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(events); } finally { child.kill("SIGINT"); await sleep(400); }
}

function send() {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "::1", port: PORT });
    const done = () => { try { sock.destroy(); } catch {} resolve(); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => { sock.write("x"); setTimeout(done, 300); });
    sock.on("data", done); sock.on("error", done);
  });
}

const source = `filter { if (dport != ${PORT}) decide pass; if (src6 in set6) { log(16); decide rst("v6_blocked", 0); } decide pass; }`;
const CASES = [
  ["::1 in ::1/128 -> rst", "::1/128", V.RST],
  ["::1 in ::/0 -> rst", "::/0", V.RST],
  ["::1 not in 2001:db8::/32 -> pass", "2001:db8::/32", V.PASS],
];

const vname = (v) => ({ [V.PASS]: "pass", [V.RST]: "rst" }[v] ?? v);
let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "::1", r));
console.log(`kernel IPv6 — src6 in set6 (lpm6) on [::1]:${PORT}\n`);
try {
  for (const [name, set6, want] of CASES) {
    await withProgram(source, set6, async (events) => {
      await sleep(700);
      const before = events.length;
      await send();
      await sleep(700);
      const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
      n++;
      const ok = obs === want;
      if (!ok) fail++;
      console.log(`  ${ok ? "ok  " : "FAIL"} ${name}: kernel=${vname(obs)}`);
    });
  }
} finally { server.close(); }
console.log(`\n${n - fail}/${n} agree`);
process.exit(fail ? 1 : 0);
