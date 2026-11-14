/* Kernel test of the shipped example programs themselves — the files under
 * examples/, loaded unmodified except for the ports/addresses a test host needs
 * — driven with real clients on live loopback. An example that compiles but
 * does not do what its header says fails here.
 *
 *   h2_guard.pfc     curl over h2c: a crawler user-agent is banned by source,
 *                    the same word in a PATH is not, another source is fine
 *   http2_rbac.pfc   curl over h2c: method x path x token policy
 *   rapid_reset.pfc  Node http2: a burst of open+cancel is cut, normal use is not
 *   honeypot.pfc     a flagged source's next TCP connection lands on the decoy
 *   dlp_redact.pfc   secrets in a request are scrubbed before the server reads them
 *   reroute.pfc      a datagram is rewritten and redirected to another listener
 *
 * Clients that get banned bind 127.0.0.2+ so 127.0.0.1 is never banned.
 * Needs yeetd + loopback + curl; `npm run test:examples-kernel` (node). */
import net from "node:net";
import dgram from "node:dgram";
import http2 from "node:http2";
import { readFileSync } from "node:fs";
import { spawn, execFile } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const H2 = 59711, A = 59712, B = 59713, UA = 59714, UB = 59715;

/* Load an example and apply the host-specific substitutions, each of which must hit. */
function example(name, subs) {
  let src = readFileSync(`${ROOT}examples/${name}.pfc`, "utf8");
  for (const [from, to] of subs) {
    if (!src.includes(from)) throw new Error(`${name}.pfc: expected to find \`${from}\``);
    src = src.replaceAll(from, to);
  }
  return src;
}

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "90"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 150 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out.slice(-2000)); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(600); }
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

/* ---- an h2c server, and curl as the client -------------------------------- */
const served = [];
const h2srv = http2.createServer((req, res) => { req.resume(); req.on("end", () => { served.push(`${req.method} ${req.url}`); res.writeHead(200); res.end("ok"); }); req.on("error", () => {}); });
h2srv.on("sessionError", () => {}); h2srv.on("error", () => {});
await new Promise((r) => h2srv.listen(H2, "127.0.0.1", r));
const curl = (from, path, args = []) => new Promise((resolve) => {
  execFile("curl", ["-s", "--http2-prior-knowledge", "-m", "2", "--interface", from, ...args, `http://127.0.0.1:${H2}${path}`], (err, stdout) => resolve(!err && stdout === "ok"));
});

console.log("kernel — the shipped examples, real clients\n");
try {
  console.log("h2_guard.pfc");
  await withProgram(example("h2_guard", [["decode h2 8080", `decode h2 ${H2}`]]), async () => {
    check("stock curl is served", await curl("127.0.0.2", "/hello"));
    check("a crawler name in the PATH is not a crawler", await curl("127.0.0.2", "/blog/gptbot-news"));
    check("a browser-shaped user-agent is served", await curl("127.0.0.2", "/", ["-A", "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"]));
    check("a crawler user-agent (Huffman-coded on the wire) is refused", !(await curl("127.0.0.2", "/crawl", ["-A", "Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"])) && !served.includes("GET /crawl"));
    check("...and its source is now banned: a clean request is refused too", !(await curl("127.0.0.2", "/again")));
    check("another source is unaffected", await curl("127.0.0.3", "/other"));
  });

  console.log("http2_rbac.pfc");
  await withProgram(example("http2_rbac", [["decode h2 8080", `decode h2 ${H2}`]]), async () => {
    served.length = 0;
    check("GET /public is served", await curl("127.0.0.2", "/public"));
    check("GET /admin/users is served (reads are allowed)", await curl("127.0.0.2", "/admin/users"));
    check("POST /admin/users is refused", !(await curl("127.0.0.2", "/admin/users", ["-X", "POST"])) && !served.includes("POST /admin/users"));
    check("/internal from outside 10/8 is refused", !(await curl("127.0.0.2", "/internal/metrics")) && !served.includes("GET /internal/metrics"));
    check("POST /api/ without a token is refused", !(await curl("127.0.0.2", "/api/items", ["-X", "POST"])) && !served.includes("POST /api/items"));
    check("POST /api/ with a Bearer token is served", await curl("127.0.0.2", "/api/items", ["-X", "POST", "-H", "Authorization: Bearer abc.def"]));
    check("GET /api/ without a token is served (only writes need one)", await curl("127.0.0.2", "/api/items"));
  });

  console.log("rapid_reset.pfc");
  await withProgram(example("rapid_reset", [["decode h2 8080", `decode h2 ${H2}`]]), async () => {
    const connect = () => { const s = http2.connect(`http://127.0.0.1:${H2}`, { localAddress: "127.0.0.2" }); s.on("error", () => {}); return s; };
    const get = (s, path) => new Promise((resolve) => {
      let status = 0, done = false; const fin = (v) => { if (!done) { done = true; resolve(v); } };
      let q; try { q = s.request({ ":path": path }); } catch { return fin(0); }
      q.on("response", (h) => { status = h[":status"]; }); q.on("data", () => {}); q.on("end", () => fin(status)); q.on("error", () => fin(0));
      q.setTimeout(2500, () => { q.close(); fin(0); });
    });
    const cancel = (s) => { try { const q = s.request({ ":path": "/slow" }); q.on("error", () => {}); q.close(http2.constants.NGHTTP2_CANCEL); } catch {} };
    let s = connect(), ok = 0;
    for (let i = 0; i < 15; i++) if ((await get(s, `/p${i}`)) === 200) ok++;
    check("15 ordinary requests on one connection are served", ok === 15, `${ok}/15`);
    for (let i = 0; i < 6; i++) { cancel(s); await sleep(80); }
    check("a handful of cancelled streams (what a browser does) is tolerated", (await get(s, "/still-ok")) === 200);
    for (let i = 0; i < 200 && !s.destroyed; i++) { cancel(s); await sleep(3); }
    check("a rapid-reset burst (200 open+cancel) gets the connection cut", (await get(s, "/after-burst")) !== 200);
    s.destroy();
  });
} finally { h2srv.close(); }

/* ---- honeypot: two plain TCP servers -------------------------------------- */
const tcp = (port, name) => new Promise((r) => { const srv = net.createServer((c) => { c.on("data", () => c.write(name)); c.on("error", () => {}); }); srv.listen(port, "127.0.0.1", () => r(srv)); });
const ask = (from, req) => new Promise((resolve) => {
  const c = net.connect({ port: A, host: "127.0.0.1", localAddress: from }); let reply = "", done = false;
  const fin = () => { if (!done) { done = true; try { c.destroy(); } catch {} resolve(reply); } };
  c.setTimeout(1500, fin); c.on("connect", () => c.write(req)); c.on("data", (d) => { reply += d; setTimeout(fin, 80); }); c.on("error", fin); c.on("close", fin);
});
const http1 = (path, ua = "curl/8.23.0") => `GET ${path} HTTP/1.1\r\nHost: shop.example\r\nUser-Agent: ${ua}\r\nAccept: */*\r\n\r\n`;
console.log("honeypot.pfc");
const real = await tcp(A, "REAL"), pot = await tcp(B, "HONEYPOT");
try {
  await withProgram(example("honeypot", [["dport != 80", `dport != ${A}`], ['dnat("10.99.0.2", 8080)', `dnat("127.0.0.1", ${B})`]]), async () => {
    check("a clean request reaches the real service", (await ask("127.0.0.2", http1("/"))) === "REAL");
    check("a scanning tool's request is reset", (await ask("127.0.0.2", http1("/", "sqlmap/1.8.2#stable"))) === "");
    await sleep(150);
    check("...and that source's NEXT connection is answered by the honeypot", (await ask("127.0.0.2", http1("/"))) === "HONEYPOT");
    let replies = [];
    for (let i = 0; i < 3; i++) { replies.push(await ask("127.0.0.3", http1("/.env"))); await sleep(100); }
    check("three soft probes from another source are each reset", replies.every((r) => r === ""), JSON.stringify(replies));
    check("...and after the third it too is diverted", (await ask("127.0.0.3", http1("/"))) === "HONEYPOT");
    check("an uninvolved source still reaches the real service", (await ask("127.0.0.4", http1("/"))) === "REAL");
  });
} finally { real.close(); pot.close(); }

/* ---- dlp_redact: secrets scrubbed on the wire ------------------------------ */
console.log("dlp_redact.pfc");
{
  let got = "";
  const srv = net.createServer((c) => { c.on("data", (d) => { got += d; }); c.on("error", () => {}); });
  await new Promise((r) => srv.listen(A, "127.0.0.1", r));
  try {
    await withProgram(example("dlp_redact", [["dport != 8080 && sport != 8080", `dport != ${A} && sport != ${A}`]]), async () => {
      const body = "ssn=123-45-6789&card=4111-1111-1111-1111&tok=ghp_" + "a1B2".repeat(9) + "&zip=12345-6789";
      await new Promise((resolve) => { const c = net.connect(A, "127.0.0.1", () => { c.write(body); setTimeout(() => { c.destroy(); resolve(); }, 400); }); c.on("error", resolve); });
      const want = "ssn=***********&card=XXXXXXXXXXXXXXXXXXX&tok=ghp_" + "X".repeat(36) + "&zip=12345-6789";
      check("the server receives the SSN, card and token scrubbed, and nothing else touched", got === want, JSON.stringify(got));
    });
  } finally { srv.close(); }
}

/* ---- reroute: a datagram steered to another listener ---------------------- */
console.log("reroute.pfc");
{
  const got = { real: [], quarantine: [] };
  const mk = (port, key) => new Promise((r) => { const s = dgram.createSocket("udp4"); s.on("message", (m) => got[key].push(m.toString())); s.bind(port, "127.0.0.1", () => r(s)); });
  const realU = await mk(UA, "real"), quarU = await mk(UB, "quarantine");
  try {
    await withProgram(example("reroute", [["dport != 514", `dport != ${UA}`], ['dnat("10.99.0.2", 5514)', `dnat("127.0.0.1", ${UB})`], ["redirect(5)", "redirect(1)"]]), async () => {
      const c = dgram.createSocket("udp4");
      await new Promise((r) => c.bind(0, "127.0.0.2", r));
      await new Promise((r) => c.send("<13>untrusted syslog line", UA, "127.0.0.1", r));
      await sleep(400); c.close();
      check("syslog from an untrusted sender lands on the quarantine collector, not the real one", got.quarantine.length === 1 && got.real.length === 0, JSON.stringify(got));
    });
  } finally { realU.close(); quarU.close(); }
}

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
