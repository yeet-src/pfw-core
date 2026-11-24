/* Kernel counters test: what a blocked packet is counted as, on live loopback.
 *
 * A reset used to bump `bans` as well as `rsts`, so a host that added the
 * three up to say how much it had blocked counted every reset twice, and
 * showed bans where no address had been banned. This proves, against the real
 * kernel:
 *   - a `rst` verdict counts in `rsts` (or `dropped`) and never in `bans`,
 *   - a connection reset because it was first seen mid-stream does not either,
 *   - a `ban` verdict still counts in `bans`,
 *   - `dropped + rsts` is the number of packets blocked.
 * Needs yeetd + loopback; `npm run test:counters` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const PORT = 59694;
const SIG = "EVILPAYLOAD";

/* Apply `source`, run `fn`, and resolve with the counters the VM reported on
 * its way out (apply-and-hold --stats 1 prints them before it detaches). */
async function countersAfter(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "6", "--stats", "1"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 150 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out.slice(-2000)); }
  await fn();
  for (let i = 0; i < 150 && !/detached/.test(out); i++) await sleep(100);
  const line = out.split("\n").find((l) => l.startsWith("STATS "));
  if (!line) throw new Error("no STATS line:\n" + out.slice(-2000));
  return JSON.parse(line.slice(6));
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

const srv = net.createServer((s) => { s.on("data", () => {}); s.on("error", () => {}); });
await new Promise((r) => srv.listen(PORT, "127.0.0.1", r));

/* One connection that sends `text` and waits to see whether it is cut. */
async function say(text) {
  let reset = false;
  const s = net.connect({ port: PORT, host: "127.0.0.1" });
  s.setNoDelay(true);
  s.on("error", (e) => { if (e.code === "ECONNRESET" || e.code === "EPIPE") reset = true; });
  await new Promise((r) => { s.once("connect", r); s.once("error", r); });
  s.write(text);
  await sleep(300);
  if (!s.destroyed) s.write("more");
  await sleep(300);
  const cut = s.destroyed || reset;
  s.destroy();
  await sleep(50);
  return cut;
}

const policy = (verdict, reassemble) => `${reassemble ? `reassemble ${PORT};` : ""}
pattern sig = "${SIG}";
filter {
  if (dport != ${PORT}) decide pass;
  if (scan(payload, 2048) & sig) decide ${verdict};
  decide pass;
}`;
const num = (v) => Number(v ?? 0);

console.log(`kernel counters — what a blocked packet is counted as, on :${PORT}\n`);
try {
  for (const reassemble of [false, true]) {
    const mode = reassemble ? "reassembled" : "per packet";
    const c = await countersAfter(policy('rst("sig", 0)', reassemble), async () => {
      for (let i = 0; i < 3; i++) check(`${mode}: a connection carrying the signature is cut`, await say(`GET /${SIG} HTTP/1.1\r\n\r\n`));
      for (let i = 0; i < 2; i++) check(`${mode}: a clean connection is not`, !(await say("GET / HTTP/1.1\r\n\r\n")));
    });
    check(`${mode}: resets are counted`, num(c.rsts) + num(c.dropped) >= 3, `rsts=${c.rsts} dropped=${c.dropped}`);
    check(`${mode}: a reset is not counted as a ban`, num(c.bans) === 0, `bans=${c.bans}`);
    check(`${mode}: the rule was hit`, num(c.rules?.sig) >= 3, `sig=${c.rules?.sig}`);
  }

  /* A connection opened before a reassembling program arrives is first seen
   * mid-stream and reset, fail closed. Nothing is banned there either. */
  {
    const early = net.connect({ port: PORT, host: "127.0.0.1" });
    early.on("error", () => {});
    await new Promise((r) => early.once("connect", r));
    early.write("hello");
    await sleep(100);
    const c = await countersAfter(policy('rst("sig", 0)', true), async () => { early.write("more"); await sleep(600); });
    early.destroy();
    check("a connection first seen mid-stream is reset", num(c.rsts) + num(c.dropped) >= 1, `rsts=${c.rsts} dropped=${c.dropped}`);
    check("...and that is not counted as a ban", num(c.bans) === 0, `bans=${c.bans}`);
  }

  {
    const c = await countersAfter(policy('ban("sig", 5)', false), async () => { await say(`GET /${SIG} HTTP/1.1\r\n\r\n`); });
    check("a ban verdict is counted as a ban", num(c.bans) >= 1, `bans=${c.bans}`);
    check("...and its packet as dropped, so dropped + rsts is what was blocked", num(c.dropped) >= num(c.bans), `dropped=${c.dropped} bans=${c.bans}`);
    await sleep(5500);                       // let the ban on 127.0.0.1 lapse before anything else runs
  }
} finally { srv.close(); }

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
