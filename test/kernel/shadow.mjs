/* Kernel shadow-mode test: the SAME program and bytecode, with the host-set
 * shadow flag flipped. The program resets every connection to PORT:
 *
 *   filter { if (dport != PORT) decide pass; log(16); decide rst("blk", 0); }
 *
 *   - live  (no --shadow)  -> the SYN is reset, the connection never completes,
 *                             the server sees no client and sends no echo.
 *   - shadow (--shadow 1)  -> the verdict is counted/logged but the packet passes,
 *                             so the connection completes and the server echoes.
 *
 * We observe the real traffic effect (did the client get an echo), which is what
 * distinguishes an actual reset from a shadow one. Needs yeetd + loopback;
 * `npm run test:shadow` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59681;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, shadow, fn) {
  const args = ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"];
  if (shadow) args.push("--shadow", "1");
  const child = spawn("yeet", args, { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(400); }
}

/* Connect, send a byte, resolve with the echo received ("" if reset/blocked). */
function echo() {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "127.0.0.1", port: PORT });
    let got = "";
    const done = () => { try { sock.destroy(); } catch {} resolve(got); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => sock.write("ping"));
    sock.on("data", (d) => { got += d.toString("latin1"); done(); });
    sock.on("error", done);
  });
}

const source = `filter { if (dport != ${PORT}) decide pass; log(16); decide rst("blk", 0); }`;
let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel shadow — same bytecode, enforcement toggled by --shadow on :${PORT}\n`);
try {
  await withProgram(source, false, async () => {
    await sleep(500); const got = await echo();
    n++; const ok = got === ""; if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} live: connection reset, no echo (got ${JSON.stringify(got)})`);
  });
  await withProgram(source, true, async () => {
    await sleep(500); const got = await echo();
    n++; const ok = got === "ok"; if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} shadow: connection passes, echo received (got ${JSON.stringify(got)})`);
  });
} finally { server.close(); }
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
