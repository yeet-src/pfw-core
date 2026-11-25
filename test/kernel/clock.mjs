/* Kernel clock test: `now`, the packet's arrival time in ktime nanoseconds, on
 * live loopback traffic. The reference interpreter has no real clock, so this is
 * a kernel-only behavioural check (like `frame at (l3)`): time is read in the
 * kernel and the gap between packets is computed there from the per-flow ring.
 *
 *   now > 0      every packet has a nonzero arrival time -> all dropped
 *   gap gate     a packet whose gap from the previous on its flow is at least
 *                150 ms is dropped; back-to-back packets pass. The ring holds
 *                each packet's `now` low 32 bits (the ring is u32), and the gap
 *                is `(now - ring.get(1)) & 0xffffffff` — exact mod 2^32, so good
 *                for any gap under ~4.3 s.
 *
 * Needs yeetd + loopback; `npm run test:clock` (node). */
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const PORT = 59771;

const GUARD = `if (proto != 17) decide pass; if (dport != ${PORT}) decide pass;`;
const GAP_NS = 150_000_000; // 150 ms, in nanoseconds

/* Every packet has a nonzero arrival time. */
const NONZERO = `filter { ${GUARD} if (now > 0) decide drop("has_now"); decide pass; }`;

/* Drop a packet at least GAP_NS after the previous on its flow. The ring (u32)
 * holds each packet's `now` low 32 bits; ring.get(1) is the previous one, and
 * the masked difference is the gap mod 2^32. */
const GAP_GATE = `filter { ${GUARD}
  let t = now & 0xffffffff;
  ring.push(t);
  if (ring.len >= 2) { let prev = ring.get(1); let gap = (t - prev) & 0xffffffff; if (gap >= ${GAP_NS}) decide drop("slow"); }
  decide pass; }`;

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "40"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY|COMPILE FAIL/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out.slice(-2000)); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(500); }
}

/* One UDP flow (one socket, so a shared 5-tuple) to PORT. */
function flow() {
  const c = dgram.createSocket("udp4");
  const ready = new Promise((r) => c.bind(0, "127.0.0.1", r));
  return {
    send: async (msg) => { await ready; await new Promise((r) => c.send(Buffer.from(msg, "latin1"), PORT, "127.0.0.1", r)); await sleep(40); },
    close: () => c.close(),
  };
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

/* Run `fn(got)` with a server on PORT collecting what arrives and `source` held. */
async function udpCase(title, source, fn) {
  console.log(`\n${title}`);
  const got = [];
  const srv = dgram.createSocket("udp4");
  srv.on("message", (m) => got.push(m.toString("latin1")));
  await new Promise((r) => srv.bind(PORT, "127.0.0.1", r));
  try { await withProgram(source, () => fn(got)); } finally { srv.close(); }
}

console.log(`kernel clock — now (ktime ns) on loopback :${PORT}`);

await udpCase("now > 0", NONZERO, async (got) => {
  const a = flow();
  await a.send("x"); await a.send("y"); await sleep(300);
  check("every packet has a nonzero arrival time -> dropped", got.length === 0, got.join(","));
  a.close();
});

await udpCase("gap gate (150 ms)", GAP_GATE, async (got) => {
  const a = flow();
  await a.send("first");             // ring.len < 2 -> passes
  await a.send("fast");              // tens of ms after -> small gap -> passes
  await sleep(400);
  await a.send("slow");              // 400 ms after -> gap >= 150 ms -> dropped
  await sleep(300);
  check("the first packet passes (no previous)", got.includes("first"), got.join(","));
  check("a back-to-back packet passes (small gap)", got.includes("fast"), got.join(","));
  check("a packet 400 ms later is dropped (gap >= 150 ms)", !got.includes("slow"), got.join(","));
  a.close();
});

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
