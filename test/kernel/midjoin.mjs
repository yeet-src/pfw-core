/* Kernel test: a connection that was open before the program was.
 *
 * `reassemble` follows a stream from its SYN. A connection whose SYN it never
 * saw — open when the first policy loaded, or dropped from the flow table —
 * used to be reset on its next segment, so loading a policy cut off every
 * keep-alive connection on the port. It is followed from the segment it is
 * picked up at instead:
 *
 *   - a clean request on the old connection is served, and the connection lives
 *   - an attack on it afterwards is still caught
 *   - the pickup is counted (reasm_midjoin), so it is not silent
 *
 * Needs yeetd + loopback; `npm run test:midjoin` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59751;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

const PROG = `reassemble ${PORT}; pattern bad = "ATTACK";
filter { if (dport != ${PORT}) decide pass; if (scan(payload, 4096) & bad) decide rst("attack", 0); decide pass; }`;

const server = net.createServer((s) => { s.on("data", (d) => s.write(`ok:${d.length}`)); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel mid-stream pickup — a connection older than the program, on :${PORT}\n`);

/* The connection, opened and used with no program in the kernel. */
const sock = net.connect(PORT, "127.0.0.1");
let got = "", reset = false;
sock.on("data", (d) => { got += d; });
sock.on("error", () => { reset = true; });
sock.on("close", () => { reset = true; });
await new Promise((r) => sock.on("connect", r));
const ask = async (payload) => { const mark = got.length; sock.write(payload); await sleep(700); return got.slice(mark); };

try {
  check("before any program: the connection works", (await ask("hello")) === "ok:5");

  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(PROG), "--iface", "1", "--hold", "20", "--stats", "1"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try {
    const reply = await ask("a clean request");
    check("a reassembling program loads: the open connection is not reset", !reset && reply === "ok:15", `reset=${reset} reply=${JSON.stringify(reply)}`);
    check("...and goes on being served", (await ask("another")) === "ok:7" && !reset, `reset=${reset}`);

    const after = await ask("x ATTACK y");
    check("an attack on it afterwards is caught", reset && after === "", `reset=${reset} reply=${JSON.stringify(after)}`);

    await sleep(1200);
    const stats = JSON.parse(out.split("\n").filter((l) => l.startsWith("STATS ")).at(-1).slice(6));
    check("the pickup is counted", stats.reasm_midjoin === 1 && stats.rules.attack === 1, `reasm_midjoin=${stats.reasm_midjoin} rules.attack=${stats.rules.attack}`);
  } finally { child.kill("SIGINT"); await sleep(400); }
} finally { try { sock.resetAndDestroy(); } catch {} server.close(); }

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
