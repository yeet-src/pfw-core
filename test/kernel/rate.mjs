/* Kernel rate-limit test: prove OP_RATE is a real per-flow token bucket on live
 * traffic — it enforces a burst cap and refills over wall-clock time (not just a
 * cumulative packet count).
 *
 * UDP from a FIXED source port, so every datagram shares one 5-tuple -> one flow
 * -> one bucket. The program drops when `rate(...)` says the flow is over the
 * limit; the server records which datagrams actually arrived.
 *
 *   filter { if (proto != 17) decide pass; if (dport != P) decide pass;
 *            if (rate(R, B)) decide drop("rl"); decide pass; }
 *
 * Case 1 (burst cap): rate(1, 3), fire 8 back-to-back -> only the burst (~3)
 *   arrive, not all 8. A no-limit control [rate(1e6, 1e6)] delivers all 8.
 * Case 2 (time refill): rate(1, 1), burst of 1. Send #1 (through), #2 at once
 *   (dropped, bucket empty), wait > 1s (refills 1 token at 1/s), send #3
 *   (through). The server sees #1 and #3 but not #2 — proving the bucket is
 *   time-based.  Needs yeetd + loopback; `npm run test:rate` (node). */
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const PORT = 59651, SRC = 59652;

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(400); }
}

/* A UDP server on 127.0.0.1:PORT that records every payload it receives, and a
 * client bound to a fixed source port so all sends share one flow. */
function harness() {
  const got = [];
  const srv = dgram.createSocket("udp4");
  srv.on("message", (m) => got.push(m.toString("latin1")));
  srv.on("error", () => {});
  const cli = dgram.createSocket("udp4");
  const ready = new Promise((res) => srv.bind(PORT, "127.0.0.1", () => cli.bind(SRC, "127.0.0.1", res)));
  const send = (msg) => new Promise((res) => cli.send(Buffer.from(msg), PORT, "127.0.0.1", () => res()));
  const close = () => { try { cli.close(); } catch {} try { srv.close(); } catch {} };
  return { got, ready, send, close };
}

const prog = (r, b) => `filter { if (proto != 17) decide pass; if (dport != ${PORT}) decide pass; if (rate(${r}, ${b})) decide drop("rl"); decide pass; }`;

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

console.log("kernel rate limit — per-flow token bucket on loopback\n");

/* Case 1: burst cap enforced. */
await withProgram(prog(1, 3), async () => {
  const h = harness(); await h.ready; await sleep(200);
  for (let i = 0; i < 8; i++) { await h.send("burst-" + i); await sleep(2); }
  await sleep(400); h.close();
  check("rate(1,3): 8 fired, only the burst gets through", h.got.length >= 2 && h.got.length <= 4, `${h.got.length} delivered`);
});

/* Control: a huge bucket limits nothing. */
await withProgram(prog(1000000, 1000000), async () => {
  const h = harness(); await h.ready; await sleep(200);
  for (let i = 0; i < 8; i++) { await h.send("free-" + i); await sleep(2); }
  await sleep(400); h.close();
  check("no-limit control: all 8 delivered", h.got.length === 8, `${h.got.length} delivered`);
});

/* Case 2: the bucket refills over wall-clock time. */
await withProgram(prog(1, 1), async () => {
  const h = harness(); await h.ready; await sleep(200);
  await h.send("first");            // bucket starts full (1) -> through
  await h.send("second-immediate"); // empty now -> dropped
  await sleep(1300);                // refill 1 token at 1/s
  await h.send("third-after-wait"); // through again
  await sleep(400); h.close();
  check("rate(1,1): first + post-wait delivered, immediate-second dropped",
    h.got.includes("first") && h.got.includes("third-after-wait") && !h.got.includes("second-immediate"),
    JSON.stringify(h.got));
});

console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
