/* Kernel LPM test: load a `src in set` program plus a CIDR set into the lpm_trie,
 * send loopback traffic (src 127.0.0.1), and read the verdict from the loader's
 * event stream — RST when the source is in the set, PASS when it is not. Proves
 * the trie is populated and matched longest-prefix in the kernel. Needs yeetd +
 * loopback; `npm run test:lpm` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59606;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, set, fn) {
  const args = ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"];
  if (set) args.push("--set", set);
  const child = spawn("yeet", args, { cwd: ROOT });
  const events = [];
  let out = "";
  child.stdout.on("data", (d) => { out += d; for (const m of String(d).matchAll(/EVENT (\d+)/g)) events.push(Number(m[1])); });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(events); } finally { child.kill("SIGINT"); await sleep(400); }
}

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

// `src in set` -> rst (logs so the verdict surfaces as an event); else pass.
const source = `filter { if (dport != ${PORT}) decide pass; if (src in set) { log(16); decide rst("in_set", 0); } decide pass; }`;
const CASES = [
  { name: "127.0.0.1 in 127.0.0.0/8 -> rst", set: "127.0.0.0/8", want: V.RST },
  { name: "127.0.0.1 in 127.0.0.1/32 -> rst", set: "127.0.0.1/32", want: V.RST },
  { name: "127.0.0.1 not in 10.0.0.0/8 -> pass", set: "10.0.0.0/8", want: V.PASS },
  { name: "127.0.0.1 not in 127.0.0.2/32 -> pass", set: "127.0.0.2/32", want: V.PASS },
];

const vname = (v) => ({ [V.PASS]: "pass", [V.RST]: "rst", [V.DROP]: "drop", [V.BAN]: "ban" }[v] ?? v);
let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel LPM — src in set, lpm_trie on :${PORT}\n`);
try {
  for (const c of CASES) {
    await withProgram(source, c.set, async (events) => {
      await sleep(700);
      const before = events.length;
      await send("probe");
      await sleep(700);
      const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
      n++;
      const ok = obs === c.want;
      if (!ok) fail++;
      console.log(`  ${ok ? "ok  " : "FAIL"} ${c.name}: kernel=${vname(obs)}`);
    });
  }
} finally { server.close(); }
console.log(`\n${n - fail}/${n} agree`);
process.exit(fail ? 1 : 0);
