/* Kernel test of what the counters count: decisions, not packets.
 *
 * A rule's count is the times it decided. What a decision goes on to stop —
 * the retransmissions of a dropped connection, the later packets of a marked
 * one — is counted apart, under the same rule. And a reset is not a ban.
 *
 *   rst      three attack requests are three decisions, three resets, no ban
 *   drop     one attack on a stream is one decision however often TCP
 *            retransmits the segment; the retransmissions are `enforced_rules`
 *   shadow   two attack requests are two "would block", not one per packet of
 *            the two connections; the packets are `shadow_enforced`
 *
 * The loader prints its stats once a second (--stats 1); this reads the last
 * line of each run. Needs yeetd + loopback; `npm run test:counts` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59741;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

/* Run `fn` with a loader holding `source`; returns the last stats it printed. */
async function withProgram(source, extra, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "30", "--stats", "1", ...extra], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 120 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try {
    await fn();
    await sleep(1500);                       // a stats line from after the traffic
    const lines = out.split("\n").filter((l) => l.startsWith("STATS "));
    return JSON.parse(lines.at(-1).slice(6));
  } finally { child.kill("SIGINT"); await sleep(400); }
}

/* One connection, one request. Resolves with what came back ("" if nothing). */
function request(payload, wait = 600) {
  return new Promise((resolve) => {
    const sock = net.connect(PORT, "127.0.0.1");
    let got = "";
    /* Reset, not close: a closed socket with unacknowledged data is retransmitted
     * by the kernel for minutes, into whatever program runs next. */
    const done = () => { try { sock.resetAndDestroy(); } catch {} resolve(got); };
    sock.on("connect", () => { sock.write(payload); setTimeout(done, wait); });
    sock.on("data", (d) => { got += d; });
    sock.on("error", done);
  });
}

const RST = `pattern bad = "ATTACK"; filter { if (dport != ${PORT}) decide pass; if (scan(payload, 256) & bad) decide rst("attack", 0); decide pass; }`;
const DROP = `reassemble ${PORT}; pattern bad = "ATTACK"; filter { if (dport != ${PORT}) decide pass; if (scan(payload, 4096) & bad) decide drop("attack"); decide pass; }`;

const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel counters — decisions, not packets, on :${PORT}\n`);
try {
  let s = await withProgram(RST, [], async () => { for (let i = 0; i < 3; i++) await request("x ATTACK y"); });
  check("three attack requests are three decisions", s.rules.attack === 3, `rules.attack=${s.rules.attack}`);
  check("...three resets, and no ban: a reset is not a ban", s.rsts === 3 && s.bans === 0, `rsts=${s.rsts} bans=${s.bans}`);

  let served = 0;
  s = await withProgram(RST, ["--shadow", "1"], async () => { for (let i = 0; i < 2; i++) if ((await request("x ATTACK y")) === "ok") served++; });
  check("shadow mode serves the requests it would have blocked", served === 2, `served=${served}`);
  check("...and counts two would-block decisions, not one per packet", s.shadowed === 2 && s.rules.attack === 2, `shadowed=${s.shadowed} rules.attack=${s.rules.attack}`);
  check("...with the packets of those connections apart", s.shadow_enforced >= 2 && s.bans === 0, `shadow_enforced=${s.shadow_enforced} bans=${s.bans}`);
  s = await withProgram(DROP, [], async () => { await request("x ATTACK y", 2800); });
  check("one dropped request is one decision, however often TCP retransmits it", s.rules.attack === 1, `rules.attack=${s.rules.attack}`);
  check("...and the retransmissions are counted apart, under the same rule", s.enforced_rules.attack >= 2 && s.enforced >= 2, `enforced_rules.attack=${s.enforced_rules.attack} enforced=${s.enforced}`);

} finally { server.close(); }

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
