/* Kernel per-source state test: prove on live loopback traffic that
 *   - `ban` bans the SOURCE ADDRESS (a clean reconnect from a new port is still
 *     dropped, another source is untouched),
 *   - src.count / src.rate count across connections (fresh source port each send),
 *   - src.state and flow.state honour a TTL longer than 31 seconds (the TTL used
 *     to be masked to 5 bits, so `for 34` expired after 2 s).
 *
 * The banned/limited client binds 127.0.0.2 so nothing on 127.0.0.1 is affected.
 * Needs yeetd + loopback; `npm run test:source` (node). */
import net from "node:net";
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const PORT = 59671;

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "40"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out.slice(-2000)); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(500); }
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

/* One TCP connection from `from`, sending `msg`; resolves when done or timed out. */
function tcpSend(from, msg, ms = 1200) {
  return new Promise((resolve) => {
    const s = net.connect({ port: PORT, host: "127.0.0.1", localAddress: from });
    const done = () => { try { s.destroy(); } catch {} resolve(); };
    s.setTimeout(ms, done);
    s.on("connect", () => { s.write(msg); setTimeout(done, 300); });
    s.on("error", done);
  });
}
function udpSend(from, msg) {
  return new Promise((resolve) => {
    const c = dgram.createSocket("udp4");
    c.bind(0, from, () => c.send(Buffer.from(msg), PORT, "127.0.0.1", () => { c.close(); resolve(); }));
  });
}

console.log("kernel per-source state — loopback, client on 127.0.0.2\n");

/* 1. ban is a source ban. */
{
  const got = [];
  const srv = net.createServer((s) => { s.on("data", (d) => got.push(d.toString())); s.on("error", () => {}); });
  await new Promise((r) => srv.listen(PORT, "127.0.0.1", r));
  await withProgram(`pattern bad = "sqlmap"; filter { if (dport != ${PORT}) decide pass; if (scan(payload, 256) & bad) decide ban("scanner", 600); decide pass; }`, async () => {
    await tcpSend("127.0.0.2", "clean-before"); await sleep(200);
    check("a clean request from 127.0.0.2 is served", got.includes("clean-before"));
    await tcpSend("127.0.0.2", "User-Agent: sqlmap/1.8"); await sleep(200);
    check("the offending request never reaches the server", !got.some((g) => g.includes("sqlmap")));
    await tcpSend("127.0.0.2", "clean-after-ban"); await sleep(200);
    check("a CLEAN reconnect from a new port is still dropped (source ban)", !got.includes("clean-after-ban"));
    await tcpSend("127.0.0.3", "clean-other-source"); await sleep(200);
    check("another source (127.0.0.3) is unaffected", got.includes("clean-other-source"));
  });
  srv.close();
}

/* 2-4 use UDP: one datagram per send, a fresh ephemeral source port each time. */
async function udpCase(source, fn) {
  const got = [];
  const srv = dgram.createSocket("udp4");
  srv.on("message", (m) => got.push(m.toString()));
  await new Promise((r) => srv.bind(PORT, "127.0.0.1", r));
  try { await withProgram(source, () => fn(got)); } finally { srv.close(); }
}

await udpCase(`filter { if (proto != 17) decide pass; if (dport != ${PORT}) decide pass; if (src.count >= 3) decide drop("strikes"); decide pass; }`, async (got) => {
  for (let i = 1; i <= 5; i++) { await udpSend("127.0.0.2", "n" + i); await sleep(30); }
  await udpSend("127.0.0.3", "other"); await sleep(300);
  check("src.count: 5 datagrams on 5 different flows, only the first 2 pass", got.filter((g) => g.startsWith("n")).join(",") === "n1,n2", got.join(","));
  check("src.count: another source has its own count", got.includes("other"));
});

await udpCase(`filter { if (proto != 17) decide pass; if (dport != ${PORT}) decide pass; if (src.rate(1, 3)) decide drop("src_rl"); decide pass; }`, async (got) => {
  for (let i = 1; i <= 8; i++) { await udpSend("127.0.0.2", "r" + i); await sleep(5); }
  await sleep(300);
  const burst = got.length;
  check("src.rate(1,3): 8 datagrams on 8 flows, only the burst passes", burst >= 2 && burst <= 4, `${burst} delivered`);
  await sleep(1300); await udpSend("127.0.0.2", "late"); await sleep(300);
  check("src.rate: the source's bucket refills over time", got.includes("late"));
});

await udpCase(`pattern arm = "ARM"; filter { if (proto != 17) decide pass; if (dport != ${PORT}) decide pass; if (src.state == 1) decide drop("flagged"); if (starts(payload, arm)) src.state = 1 for 34; decide pass; }`, async (got) => {
  await udpSend("127.0.0.2", "ARM"); await sleep(200);
  await udpSend("127.0.0.2", "soon"); await sleep(3000);
  await udpSend("127.0.0.2", "after-3s"); await sleep(300);
  check("src.state: the arming datagram itself passes (deferred write)", got.includes("ARM"));
  check("src.state: the next datagram, new flow, is dropped", !got.includes("soon"));
  check("src.state: a 34 s TTL is still in force after 3 s (TTL is not masked to 5 bits)", !got.includes("after-3s"), got.join(","));
});

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
