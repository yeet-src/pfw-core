/* Kernel console test: a program prints printf-style messages to the host over
 * the event ring; the loader formats them (numeric args by value, %s copied from
 * the packet) and prints `CONSOLE <text>`. We send a known request and assert the
 * formatted lines, proving console() + %s work on real traffic. Needs yeetd +
 * loopback; `npm run test:console` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59691;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"], { cwd: ROOT });
  const lines = [];
  let out = "";
  child.stdout.on("data", (d) => { out += d; for (const m of String(d).matchAll(/CONSOLE (.*)/g)) lines.push(m[1]); });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 120 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(lines); } finally { child.kill("SIGINT"); await sleep(400); }
}

function send(payload) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "127.0.0.1", port: PORT });
    const done = () => { try { sock.destroy(); } catch {} resolve(); };
    sock.setTimeout(1000, done);
    sock.on("connect", () => { sock.write(payload); setTimeout(done, 250); });
    sock.on("data", done); sock.on("error", done);
  });
}

// print the destination port and the first bytes of the request
const source = `filter { if (dport != ${PORT}) return pass; if (len == 0) return pass; console("req to :%d says %s", dport, payload); return pass; }`;

let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => {}); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel console — printf to the host over the ring on :${PORT}\n`);
try {
  await withProgram(source, async (lines) => {
    await sleep(400);
    await send("HELLO-WORLD");
    await sleep(500);
    const want = `req to :${PORT} says HELLO-WORLD`;
    const got = lines.find((l) => l.includes("HELLO-WORLD")) ?? "";
    n++; let ok = got === want; if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} console %d + %s: ${JSON.stringify(got)}${ok ? "" : ` want ${JSON.stringify(want)}`}`);

    // a long payload proves the 256-byte %s capture (not the old 32)
    const big = "Z".repeat(200);
    await send(big);
    await sleep(500);
    const wantBig = `req to :${PORT} says ${big}`;
    const gotBig = lines.find((l) => l.includes("Z".repeat(200))) ?? (lines.find((l) => l.includes("ZZZ")) ?? "");
    n++; ok = gotBig === wantBig; if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} console %s 200 bytes: ${ok ? "full string captured" : JSON.stringify(gotBig.slice(0, 60)) + "..."}`);
  });
} finally { server.close(); }
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
