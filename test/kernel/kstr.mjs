/* Kernel string-knob test: a live host-set string matched against the payload at
 * XDP. The host writes the needle into the `knob_strs` map; the program resets
 * connections whose payload contains it:
 *
 *   filter { if (dport != PORT) decide pass;
 *            if (kstr("tok")) { log(16); decide rst("m", 0); } decide pass; }
 *
 *   - --kstr tok=SECRET, payload has SECRET  -> RST
 *   - --kstr tok=SECRET, payload lacks it    -> pass
 *   - no --kstr (needle empty)               -> pass
 *
 * Proves a runtime string (not a compile-time pattern) can be set by the host and
 * matched live. Needs yeetd + loopback; `npm run test:kstr`. */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59751;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, kstr, fn) {
  const args = ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"];
  if (kstr) args.push("--kstr", kstr);
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
    const sock = net.connect({ host: "127.0.0.1", port: PORT });
    const done = () => { try { sock.destroy(); } catch {} resolve(); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => { sock.write(payload); setTimeout(done, 300); });
    sock.on("data", done); sock.on("error", done);
  });
}

const source = `filter { if (dport != ${PORT}) decide pass; if (kstr("tok")) { log(16); decide rst("m", 0); } decide pass; }`;
const CASES = [
  ["--kstr tok=SECRET, payload has it -> rst", "tok=SECRET", "GET /?q=SECRET here", V.RST],
  ["--kstr tok=SECRET, payload lacks it -> pass", "tok=SECRET", "GET /?q=nothing here", V.PASS],
  ["no --kstr -> pass", null, "GET /?q=SECRET here", V.PASS],
];

const vname = (v) => ({ [V.PASS]: "pass", [V.RST]: "rst" }[v] ?? v);
let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel kstr — live host-set string matched on the wire on :${PORT}\n`);
try {
  for (const [name, kstr, payload, want] of CASES) {
    await withProgram(source, kstr, async (events) => {
      await sleep(500);
      const before = events.length;
      await send(payload);
      await sleep(500);
      const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
      n++; const ok = obs === want; if (!ok) fail++;
      console.log(`  ${ok ? "ok  " : "FAIL"} ${name}: kernel=${vname(obs)}`);
    });
  }
} finally { server.close(); }
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
