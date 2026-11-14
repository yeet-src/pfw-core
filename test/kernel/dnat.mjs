/* Kernel DNAT test: load a dnat program, send a UDP datagram to one
 * address:port, and assert it is delivered to the REWRITTEN destination. Proves
 * the destination rewrite (IPv4 + port) routes through the stack after XDP. UDP
 * (one-way datagram) so there is no return path needing reverse NAT. Needs yeetd
 * + loopback; `npm run test:dnat` (node). */
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
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

/* Bind a UDP server at dstAddr:dstPort, send `msg` to sendAddr:sendPort, resolve
 * with what the server received (or "" after a timeout). */
function udpDeliver(sendAddr, sendPort, dstAddr, dstPort, msg) {
  return new Promise((resolve) => {
    const srv = dgram.createSocket("udp4");
    let got = "";
    srv.on("message", (m) => { got = m.toString("latin1"); });
    srv.on("error", () => {});
    srv.bind(dstPort, dstAddr, () => {
      const cli = dgram.createSocket("udp4");
      cli.send(Buffer.from(msg), sendPort, sendAddr, () => {});
      setTimeout(() => { try { cli.close(); } catch {} try { srv.close(); } catch {} resolve(got); }, 600);
    });
  });
}

const A = 59601, B = 59602;
const CASES = [
  { name: "DNAT ip+port 127.0.0.1:A -> 127.0.0.2:B",
    source: `filter { if (proto != 17) return pass; if (dport != ${A}) return pass; dnat("127.0.0.2", ${B}); return pass; }`,
    send: ["127.0.0.1", A], dst: ["127.0.0.2", B], msg: "hello dnat" },
  { name: "DNAT port-only 127.0.0.1:A -> 127.0.0.1:B",
    source: `filter { if (proto != 17) return pass; if (dport != ${A}) return pass; dnat("127.0.0.1", ${B}); return pass; }`,
    send: ["127.0.0.1", A], dst: ["127.0.0.1", B], msg: "port only" },
];

let fail = 0, n = 0;
console.log("kernel DNAT — destination rewrite + reroute, UDP on loopback\n");
for (const c of CASES) {
  await withProgram(c.source, async () => {
    await sleep(300);
    const got = await udpDeliver(c.send[0], c.send[1], c.dst[0], c.dst[1], c.msg);
    n++;
    const ok = got === c.msg;
    if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} ${c.name}: delivered ${JSON.stringify(got)}${ok ? "" : ` want ${JSON.stringify(c.msg)}`}`);
  });
}
console.log(`\n${n - fail}/${n} rerouted correctly`);
process.exit(fail ? 1 : 0);
