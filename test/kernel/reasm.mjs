/* Kernel reassembly test: the sliding window, on live loopback TCP.
 *
 * `reassemble` used to anchor a 2048-byte buffer at the start of the connection
 * and RESET the connection as soon as the stream outgrew it — so a keep-alive
 * connection or an upload was cut off at 2 kB. The window now slides, keeping
 * the last 64 bytes across each move. This proves, against the real kernel:
 *   - a long clean stream is carried whole (no reset),
 *   - a signature far past 2 kB is still caught,
 *   - a signature split across two segments is caught,
 *   - a signature that straddles the exact point where the window slides is caught,
 *   - a single segment larger than the window does not kill the connection, and
 *     the stream is still followed afterwards.
 * Each write is its own segment (TCP_NODELAY + a pause).
 * Needs yeetd + loopback; `npm run test:reasm` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const PORT = 59691;
const SIG = "EVILPAYLOAD";

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "60"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 150 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out.slice(-2000)); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(500); }
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

/* The server keeps everything each connection sent, keyed by its first 4 bytes. */
const seen = new Map();
const srv = net.createServer((s) => {
  let buf = "";
  s.on("data", (d) => { buf += d.toString("latin1"); seen.set(buf.slice(0, 4), buf); });
  s.on("error", () => {});
});
await new Promise((r) => srv.listen(PORT, "127.0.0.1", r));

/* Open one connection and send `chunks` as separate segments. Resolves with
 * { reset, received } — received is what the server got from this connection. */
async function stream(tag, chunks) {
  let reset = false;
  const s = net.connect({ port: PORT, host: "127.0.0.1" });
  s.setNoDelay(true);
  s.on("error", (e) => { if (e.code === "ECONNRESET" || e.code === "EPIPE") reset = true; });
  await new Promise((r) => { s.once("connect", r); s.once("error", r); });
  let first = true;
  for (const c of chunks) {
    if (s.destroyed) break;
    s.write(first ? tag + c : c); first = false;
    await sleep(25);
  }
  await sleep(700);        // a dropped/reset segment would be retransmitted in here
  const stillOpen = !s.destroyed && !reset;
  s.destroy();
  await sleep(50);
  return { reset: !stillOpen, received: seen.get(tag) ?? "" };
}

const fill = (len, ch = "a") => ch.repeat(len);
const PROG = `reassemble ${PORT};
pattern sig = "${SIG}";
filter {
  if (dport != ${PORT}) decide pass;
  if (scan(payload, 2048) & sig) decide rst("sig", 0);
  decide pass;
}`;

console.log(`kernel reassembly — sliding window on :${PORT}\n`);
try {
  await withProgram(PROG, async () => {
    let r = await stream("T1__", Array.from({ length: 20 }, () => fill(500)));
    check("10 kB of clean stream on one connection is carried whole, not reset", !r.reset && r.received.length === 4 + 10000, `reset=${r.reset} received=${r.received.length}`);

    r = await stream("T2__", [...Array.from({ length: 12 }, () => fill(500)), "x" + SIG + "y", "tail"]);
    check("a signature 6 kB into the stream is caught", r.reset && !r.received.includes(SIG) && !r.received.includes("tail"), `reset=${r.reset} received=${r.received.length}`);

    r = await stream("T3__", [...Array.from({ length: 10 }, () => fill(500)), "x" + SIG.slice(0, 5), SIG.slice(5) + "y", "tail"]);
    check("a signature split across two segments, 5 kB in, is caught", r.reset && !r.received.includes("tail"), `reset=${r.reset} received=${r.received.length}`);

    // Fill the window to exactly 2048 bytes, ending on the first half of the
    // signature; the next segment cannot fit, so the window slides right there.
    const head = 4 + 2000, pad = 2048 - head - 5;
    r = await stream("T4__", [fill(500), fill(500), fill(500), fill(500), fill(pad, "b") + SIG.slice(0, 5), SIG.slice(5) + "y", "tail"]);
    check("a signature straddling the point where the window slides is caught", r.reset && !r.received.includes("tail"), `reset=${r.reset} received=${r.received.length}`);

    r = await stream("T5__", [fill(5000), fill(300), "tail"]);
    check("one segment larger than the window does not kill the connection", !r.reset && r.received.endsWith("tail"), `reset=${r.reset} received=${r.received.length}`);

    r = await stream("T6__", [fill(5000), fill(300), "x" + SIG + "y", "tail"]);
    check("...and the stream is still followed after it", r.reset && !r.received.includes("tail"), `reset=${r.reset} received=${r.received.length}`);
  });

  /* `drop` on a stream. TCP retransmits the dropped segment; meanwhile later
   * segments slide the window past its bytes, so a per-packet drop would judge
   * the retransmission clean and deliver the signature. */
  await withProgram(PROG.replace('decide rst("sig", 0)', 'decide drop("sig")'), async () => {
    const r = await stream("T7__", [fill(500), "x" + SIG + "y", ...Array.from({ length: 8 }, () => fill(500)), "tail"]);
    await sleep(2500);                       // several retransmission timeouts
    const got = seen.get("T7__") ?? "";
    check("a dropped segment stays dropped when TCP retransmits it (the connection is blackholed)", !got.includes(SIG) && !got.includes("tail"), `received=${got.length}`);
  });
} finally { srv.close(); }

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
