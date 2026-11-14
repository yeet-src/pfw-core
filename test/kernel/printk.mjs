/* Kernel printk test: a program with printk() loads (the verifier accepts
 * bpf_trace_printk with a runtime format pointer from the program), attaches, and
 * forwards traffic normally — printk is a side-channel to the kernel trace pipe
 * and must not affect the verdict.
 *
 * The trace output itself lands in /sys/kernel/debug/tracing/trace_pipe, which
 * needs root to read, so this test asserts load + unaffected forwarding rather
 * than capturing the lines. To SEE them: `sudo cat /sys/kernel/debug/tracing/
 * trace_pipe` while this runs. Needs yeetd + loopback; `npm run test:printk`. */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59701;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 120 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(400); }
}

function echo(payload) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "127.0.0.1", port: PORT });
    let got = "";
    const done = () => { try { sock.destroy(); } catch {} resolve(got); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => sock.write(payload));
    sock.on("data", (d) => { got += d.toString("latin1"); done(); });
    sock.on("error", done);
  });
}

// trace the port + length of each request, then pass it through unchanged
const source = `filter { if (dport != ${PORT}) return pass; if (len == 0) return pass; printk("pfw: req to %d len %d", dport, len); return pass; }`;

let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel printk — loads + forwards unaffected on :${PORT}\n`);
console.log("  (to see the trace: sudo cat /sys/kernel/debug/tracing/trace_pipe)\n");
try {
  await withProgram(source, async () => {
    await sleep(400);
    const got = await echo("trace me");
    n++; const ok = got === "ok"; if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} printk program loaded; traffic forwarded (echo ${JSON.stringify(got)})`);
  });
} finally { server.close(); }
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
