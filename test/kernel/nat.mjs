/* Kernel NAT test: `dnat` on a TCP connection, both directions.
 *
 * A one-way destination rewrite is enough for a datagram, but TCP needs the
 * reply translated back, or the client never completes the handshake (the
 * SYN-ACK arrives from a port it did not dial). This drives a real diversion:
 *
 *   - a "real" server on :A and a "honeypot" on :B, both on 127.0.0.1
 *   - a client on 127.0.0.2 that only ever dials :A
 *   - a program that flags a source on a tool signature (src.state) and from
 *     then on dnat()s every packet of that source's connections to :B
 *
 * The flagged client's NEXT connection must be answered by the honeypot, over a
 * working TCP connection, while it still believes it is talking to :A — which
 * only happens if the SYN was diverted AND the replies were un-NATed.
 * Needs yeetd + loopback; `npm run test:nat` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const A = 59681, B = 59682;

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "40"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 150 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out.slice(-2000)); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(500); }
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

/* A server that answers every chunk with `name:<chunk>` and records what it saw. */
function server(port, name) {
  const got = [];
  const srv = net.createServer((s) => { s.on("data", (d) => { got.push(d.toString()); s.write(`${name}:${d}`); }); s.on("error", () => {}); });
  return new Promise((r) => srv.listen(port, "127.0.0.1", () => r({ got, close: () => srv.close() })));
}

/* Dial :A from `from`, send `msg`, resolve with { reply, remotePort } (reply "" on reset/timeout). */
function ask(from, msg, ms = 1500) {
  return new Promise((resolve) => {
    const s = net.connect({ port: A, host: "127.0.0.1", localAddress: from });
    let reply = "", remotePort = 0;
    const done = () => { try { s.destroy(); } catch {} resolve({ reply, remotePort }); };
    s.setTimeout(ms, done);
    s.on("connect", () => { remotePort = s.remotePort; s.write(msg); });
    s.on("data", (d) => { reply += d; setTimeout(done, 100); });
    s.on("error", done);
    s.on("close", done);
  });
}

const PROG = `
pattern tool = "sqlmap";
filter {
  if (proto != 6) decide pass;
  if (dport != ${A}) decide pass;
  if (src.state == 1) { dnat("127.0.0.1", ${B}); decide pass; }   // flagged: divert from the SYN on
  if (scan(payload, 256) & tool) { src.state = 1 for 600; decide rst("tool", 0); }
  decide pass;
}`;

console.log(`kernel NAT — a TCP connection diverted :${A} -> :${B}, replies translated back\n`);
const real = await server(A, "real"), pot = await server(B, "honeypot");
try {
  await withProgram(PROG, async () => {
    let r = await ask("127.0.0.2", "hello-1");
    check("before flagging: served by the real server", r.reply === "real:hello-1", JSON.stringify(r.reply));
    r = await ask("127.0.0.2", "User-Agent: sqlmap");
    check("the tool signature is reset, not served", r.reply === "" && !real.got.some((g) => g.includes("sqlmap")));
    await sleep(200);
    r = await ask("127.0.0.2", "hello-2");
    check("flagged source's next connection is answered by the honeypot", r.reply === "honeypot:hello-2", JSON.stringify(r.reply));
    check("...over a connection the client still sees as :" + A, r.remotePort === A, String(r.remotePort));
    check("...and the real server never saw it", !real.got.includes("hello-2"));
    r = await ask("127.0.0.2", "x".repeat(3000));
    check("a 3 kB request is carried both ways through the NAT", r.reply.startsWith("honeypot:xxx"), `${r.reply.length} bytes back`);
    r = await ask("127.0.0.3", "hello-3");
    check("another source still reaches the real server", r.reply === "real:hello-3", JSON.stringify(r.reply));
  });
} finally { real.close(); pot.close(); }

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
