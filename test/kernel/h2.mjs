/* Kernel HTTP/2 decode test: `decode h2` against REAL clients on live loopback.
 *
 * The decoder used to handle only raw-string, static-table header blocks in the
 * first 2 kB of a connection, and reset on anything else — which is every real
 * client (they Huffman-code strings and use the dynamic table). This drives the
 * rewritten decoder with curl (nghttp2) and Node's http2 client (h2c, prior
 * knowledge) and checks, against the real kernel:
 *   - the decoded view of a stock curl request, read back verbatim,
 *   - a Huffman-coded header value is matched,
 *   - a header sent as a DYNAMIC-TABLE reference is matched,
 *   - a connection stays decodable across many requests (far past the window),
 *   - a large request body (DATA frames larger than the window) is skipped
 *     without losing sync,
 *   - PADDED / PRIORITY / CONTINUATION header sequences are decoded,
 *   - RST_STREAM frames are visible (rapid reset), and
 *   - HTTP/1.1 on the same port is matched as a plain stream.
 * Needs yeetd + loopback + curl; `npm run test:h2` (node). */
import net from "node:net";
import http2 from "node:http2";
import { spawn, execFile } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const PORT = 59701, PORT1 = 59702;

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "90", "--dump", "1"], { cwd: ROOT });
  let out = "";
  const events = [];
  child.stdout.on("data", (d) => {
    out += d;
    for (const m of String(d).matchAll(/EVENT (\d+) (".*")/g)) { try { events.push({ verdict: Number(m[1]), view: JSON.parse(m[2]) }); } catch {} }
  });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out.slice(-2000)); }
  try { return await fn(events); } finally { child.kill("SIGINT"); await sleep(500); }
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

/* An h2c server that records every request path it actually received. */
const served = [];
const server = http2.createServer((req, res) => {
  let len = 0;
  req.on("data", (d) => { len += d.length; });
  req.on("end", () => { served.push(req.url); res.writeHead(200); res.end(`ok:${req.url}:${len}`); });
  req.on("error", () => {});
});
server.on("sessionError", () => {}); server.on("error", () => {});
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));

const curl = (args) => new Promise((resolve) => {
  execFile("curl", ["-s", "--http2-prior-knowledge", "-m", "3", ...args], (err, stdout) => resolve({ ok: !err, body: stdout }));
});

/* One request on an existing session: resolves { status, body } or { error }. */
function request(session, headers, body) {
  return new Promise((resolve) => {
    let status = 0, data = "", done = false;
    const fin = (v) => { if (!done) { done = true; resolve(v); } };
    let req;
    try { req = session.request(headers, { endStream: !body }); } catch (e) { return fin({ error: String(e.code ?? e) }); }
    req.on("response", (h) => { status = h[":status"]; });
    req.on("data", (d) => { data += d; });
    req.on("end", () => fin({ status, body: data }));
    req.on("error", (e) => fin({ error: String(e.code ?? e) }));
    req.setTimeout(3000, () => { req.close(); fin({ error: "timeout" }); });
    if (body) req.end(body);
  });
}
function connect() {
  const s = http2.connect(`http://127.0.0.1:${PORT}`);
  s.on("error", () => {});
  return s;
}

const PROG = `nocase;
decode h2 ${PORT};
pattern ua_bot = "user-agent: gptbot", admin = ":path: /admin", guest = "x-role: guest";
pattern rst = ":frame: rst_stream", any_hdr = ":method: ";
filter {
  mask m = scan(payload, 4096);
  if (any(m, ua_bot)) { log(250); decide rst("h2_bot", 0); }
  if (all(m, admin, guest)) { log(250); decide rst("h2_guest_admin", 0); }
  if (any(m, rst)) { if (rate(5, 10)) decide rst("rapid_reset", 0); }
  if (any(m, any_hdr)) log(250);
  decide pass;
}`;

console.log(`kernel HTTP/2 decode — real clients on :${PORT}\n`);
try {
  await withProgram(PROG, async (events) => {
    /* A. stock curl: served, and its decoded view read back from the kernel. */
    let r = await curl([`http://127.0.0.1:${PORT}/hello?x=1`]);
    await sleep(300);
    const view = events.map((e) => e.view).find((v) => v.includes(":path: /hello")) ?? "";
    check("curl (nghttp2, Huffman-coded headers) is served", r.ok && r.body === "ok:/hello?x=1:0", JSON.stringify(r.body));
    check("its decoded view has the pseudo-headers", view.includes(":method: GET\n") && view.includes(":path: /hello?x=1\n") && view.includes(":scheme: http\n"), JSON.stringify(view));
    check("...and the Huffman-coded user-agent and accept, as text", /user-agent: curl\/[\d.]+\n/.test(view) && view.includes("accept: */*\n"), JSON.stringify(view));

    /* B. a Huffman-coded value is matched. */
    r = await curl(["-A", "GPTBot/1.2", `http://127.0.0.1:${PORT}/bot`]);
    check("curl with a blocked user-agent is reset", !r.ok && !served.includes("/bot"));

    /* C. the dynamic table: the second request carries x-role as an index. */
    let s = connect();
    r = await request(s, { ":path": "/ok", "x-role": "guest" });
    check("request 1 (x-role: guest on /ok) is served", r.status === 200, JSON.stringify(r));
    r = await request(s, { ":path": "/admin", "x-role": "guest" });
    check("request 2 (/admin, x-role now a dynamic-table reference) is reset", !!r.error && !served.includes("/admin"), JSON.stringify(r));
    s.destroy();
    s = connect();
    r = await request(s, { ":path": "/admin", "x-role": "staff" });
    check("control: /admin with another role is served", r.status === 200, JSON.stringify(r));
    s.destroy();

    /* D. a long-lived connection stays in sync, far past the 4 kB window. */
    s = connect();
    let okCount = 0;
    const cookie = "session=" + "c".repeat(500);
    for (let i = 0; i < 40; i++) { const q = await request(s, { ":path": `/page/${i}`, cookie, "x-n": String(i) }); if (q.status === 200) okCount++; }
    check("40 requests on one connection (about 25 kB of frames) are all served", okCount === 40, `${okCount}/40`);
    r = await request(s, { ":path": "/late", "user-agent": "GPTBot" });
    check("...and the 41st, with a blocked user-agent, is still caught", !!r.error && !served.includes("/late"), JSON.stringify(r));
    s.destroy();

    /* E. a 60 kB body in 16 kB DATA frames, sent in MSS-sized segments (as a
     * real NIC delivers them; one loopback write would arrive as a single 64 kB
     * segment). Each DATA frame's body is far larger than the window, so it is
     * skipped as it arrives — and the headers after it must still decode. */
    const lit = (name, value) => Buffer.concat([Buffer.from([0x10, name.length]), Buffer.from(name), Buffer.from([value.length]), Buffer.from(value)]); // never-indexed, raw strings
    const frame = (type, flags, stream, payload) => { const h = Buffer.alloc(9); h.writeUIntBE(payload.length, 0, 3); h[3] = type; h[4] = flags; h.writeUInt32BE(stream, 5); return Buffer.concat([h, payload]); };
    const PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    const headers = (stream, flags, method, path, ua) => frame(1, 0x04 | flags, stream, Buffer.concat([lit(":method", method), lit(":scheme", "http"), lit(":path", path), lit(":authority", "127.0.0.1"), lit("user-agent", ua)]));
    const upload = async (afterPath, afterUa, piece = 1400) => {
      const body = Buffer.alloc(60000, 0x41), parts = [PREFACE, frame(4, 0, 0, Buffer.alloc(0)), headers(1, 0, "POST", "/upload", "uploader")];
      for (let o = 0; o < body.length; o += 16384) parts.push(frame(0, o + 16384 >= body.length ? 0x01 : 0, 1, body.subarray(o, o + 16384)));
      parts.push(headers(3, 0x01, "GET", afterPath, afterUa));
      const all = Buffer.concat(parts);
      const c = net.connect(PORT, "127.0.0.1"); let reset = false;
      c.setNoDelay(true);
      c.on("error", () => { reset = true; });
      await new Promise((r) => { c.once("connect", r); c.once("error", r); });
      for (let o = 0; o < all.length && !c.destroyed; o += piece) { c.write(all.subarray(o, o + piece)); await sleep(1); }
      await sleep(700);
      c.destroy();
      return reset;
    };
    served.length = 0;
    let cut = await upload("/after-upload-ok", "Mozilla/5.0");
    check("a 60 kB body in 16 kB DATA frames passes, and the next request is served", !cut && served.includes("/upload") && served.includes("/after-upload-ok"), `reset=${cut} served=${served.join(",")}`);
    cut = await upload("/after-upload-bot", "GPTBot");
    check("...and a blocked request after the body is still decoded and caught", cut && !served.includes("/after-upload-bot"), `reset=${cut}`);

    /* The same, written at once: loopback carries it as segments of up to 64 kB,
     * each many windows long, and each is decoded a piece at a time. */
    served.length = 0;
    cut = await upload("/big-write-ok", "Mozilla/5.0", 1 << 20);
    check("the same body in one large write passes too, and the next request is served", !cut && served.includes("/upload") && served.includes("/big-write-ok"), `reset=${cut} served=${served.join(",")}`);
    cut = await upload("/big-write-bot", "GPTBot", 1 << 20);
    check("...and a blocked request after it is still decoded and caught", cut && !served.includes("/big-write-bot"), `reset=${cut}`);

    /* F. hand-built frames: PADDED + PRIORITY HEADERS continued in a CONTINUATION. */
    const crafted = (path, ua) => {
      const block = Buffer.concat([lit(":method", "GET"), lit(":scheme", "http"), lit(":path", path), lit(":authority", "127.0.0.1"), lit("user-agent", ua)]);
      const cut = block.length - 4;                      // split inside the user-agent value
      const head = Buffer.concat([Buffer.from([3]), Buffer.from([0, 0, 0, 0, 15]), block.subarray(0, cut), Buffer.alloc(3)]); // pad len, priority, fragment, padding
      return Buffer.concat([PREFACE, frame(4, 0, 0, Buffer.alloc(0)),
        frame(1, 0x08 | 0x20 | 0x01, 1, head), frame(9, 0x04, 1, block.subarray(cut))]); // HEADERS: PADDED|PRIORITY|END_STREAM, then CONTINUATION: END_HEADERS
    };
    const raw = (bytes) => new Promise((resolve) => {
      const c = net.connect(PORT, "127.0.0.1"); let reset = false;
      c.on("error", () => { reset = true; });
      c.on("connect", () => c.write(bytes));
      setTimeout(() => { c.destroy(); resolve(reset); }, 700);
    });
    let wasReset = await raw(crafted("/crafted-ok", "Mozilla/5.0"));
    check("PADDED + PRIORITY + CONTINUATION headers decode (clean request served)", !wasReset && served.includes("/crafted-ok"));
    wasReset = await raw(crafted("/crafted-bot", "GPTBot"));
    check("...and a blocked value split across HEADERS/CONTINUATION is caught", wasReset && !served.includes("/crafted-bot"));

    /* G. RST_STREAM frames are visible: a rapid-reset burst trips the limiter. */
    s = connect();
    r = await request(s, { ":path": "/warm" });
    for (let i = 0; i < 3; i++) { const q = s.request({ ":path": "/slow" }); q.on("error", () => {}); q.close(http2.constants.NGHTTP2_CANCEL); await sleep(60); }
    r = await request(s, { ":path": "/still-fine" });
    check("a few cancelled streams do not trip the limiter", r.status === 200, JSON.stringify(r));
    for (let i = 0; i < 60 && !s.destroyed; i++) { try { const q = s.request({ ":path": "/slow" }); q.on("error", () => {}); q.close(http2.constants.NGHTTP2_CANCEL); } catch {} await sleep(4); }
    r = await request(s, { ":path": "/after-burst" });
    check("a burst of 60 open+cancel pairs is cut off (rapid reset)", !!r.error && !served.includes("/after-burst"), JSON.stringify(r));
    s.destroy();
  });

  /* H. HTTP/1.1 on a `decode h2` port is matched as a plain stream. */
  const got = [];
  const h1 = net.createServer((c) => { c.on("data", (d) => { got.push(d.toString()); c.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); }); c.on("error", () => {}); });
  await new Promise((r) => h1.listen(PORT1, "127.0.0.1", r));
  await withProgram(`nocase; decode h2 ${PORT1}; pattern ua_bot = "user-agent: gptbot"; filter { if (scan(payload, 4096) & ua_bot) decide rst("h1_bot", 0); decide pass; }`, async () => {
    const h1req = (ua) => new Promise((resolve) => {
      const c = net.connect(PORT1, "127.0.0.1"); let reply = "";
      c.on("connect", () => c.write(`GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: ${ua}\r\n\r\n`));
      c.on("data", (d) => { reply += d; }); c.on("error", () => {});
      setTimeout(() => { c.destroy(); resolve(reply); }, 600);
    });
    let reply = await h1req("curl/8.0");
    check("HTTP/1.1 on the h2 port: a clean request is served", reply.includes("200 OK"));
    reply = await h1req("GPTBot");
    check("HTTP/1.1 on the h2 port: a blocked user-agent is caught", reply === "" && !got.some((g) => g.includes("GPTBot")));
  });
  h1.close();
} finally { server.close(); }

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
