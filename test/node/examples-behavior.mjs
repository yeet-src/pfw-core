/* Behaviour tests for the showcase programs in examples/ (and regressions for
 * the contrib/ programs that were found broken). The compile test next door only
 * proves a program parses; this one runs each program through the reference
 * interpreter and asserts the verdict AND the rule that fired, on:
 *
 *   - at least one realistic attack / positive input per program, and
 *   - at least one realistic benign input per program that must pass, and
 *   - a cross-check: EVERY benign input, on its natural 5-tuple, through EVERY
 *     showcase program, must pass and must leave the packet bytes untouched.
 *     That is the check that catches a signature list misfiring on `Accept: * / *`
 *     or on a multipart boundary.
 *
 * A node script, not a yeet test: it reads the programs and fixtures from disk.
 *
 * What the host model is, so the inputs are read correctly: `Program.exec` runs
 * over exactly the bytes it is given. It does not model TCP reassembly or the
 * `decode` front-ends, and it has no L2 framing — `l3` and `l4` are both offset
 * 0. So a payload program gets the payload; a program that reads the TCP header
 * (syn_flood) gets a frame that starts at the TCP header; one that reads the IP
 * header (os_fingerprint) gets a raw IPv4 packet.
 *
 * Fixtures (test/fixtures/*.hex) are real captures, not hand-written:
 *   clienthello-*.hex   the first bytes an `openssl s_client` (3.6.5) / `curl`
 *                       (8.23.0) sent to a throwaway node:net listener on
 *                       loopback: default, `-tls1_2`, `-tls1 -cipher
 *                       ALL:@SECLEVEL=0`, and `-servername c2.evil.example`.
 *   dns-query-*.hex     the datagram node's resolver (c-ares) sent to a
 *                       node:dgram listener for the given name.
 * The TCP/IP headers are built here (capturing a SYN needs root), with the
 * option layout and initial values the named stacks really use. The Heartbleed
 * request is the 8 bytes every public exploit sends.
 *
 * The five programs listed in OWNER are being reworked separately and are only
 * compile-checked for now. */
import { readFileSync, readdirSync } from "node:fs";
import { compile } from "#/clang";
import { toProgram } from "#/program";
import { LIMITS } from "#/isa.js";

const OWNER = new Set(["rapid_reset", "h2_guard", "http2_rbac", "honeypot", "reroute"]);
const root = new URL("../../", import.meta.url);
const S = 1_000_000_000n;

/* ---- tiny harness -------------------------------------------------------- */
let failed = 0, passed = 0;
const covered = new Map(); // program -> { positive, benign }
const note = (prog, kind) => { const c = covered.get(prog) ?? { positive: 0, benign: 0 }; c[kind]++; covered.set(prog, c); };
const ok = (cond, label, detail = "") => { if (cond) passed++; else { failed++; console.log(`FAIL ${label}${detail ? " — " + detail : ""}`); } };
const progs = new Map();
const P = (name, dir = "examples") => {
  const key = `${dir}/${name}`;
  if (!progs.has(key)) {
    const c = compile(readFileSync(new URL(`${key}.pfc`, root), "utf8"));
    if (!c.ok) throw new Error(`${key}: ${JSON.stringify(c.errors)}`);
    progs.set(key, toProgram(c));
  }
  return progs.get(key);
};
const enc = (s) => new TextEncoder().encode(s);
const dec = (u) => Buffer.from(u).toString("latin1");
const fixture = (f) => Uint8Array.from(Buffer.from(readFileSync(new URL(`test/fixtures/${f}.hex`, root), "utf8").replace(/\s+/g, ""), "hex"));
const cat = (...parts) => Uint8Array.from(parts.flatMap((p) => [...p]));
const show = (r) => (r.banned ? "banned" : `${r.verdict}${r.ruleName && r.ruleName !== "-" ? `(${r.ruleName})` : ""}`);
const fresh = () => ({ flow: {}, source: {}, bucket: {}, now: 0n });

/* Run `name` once and assert verdict (+ rule when given). Returns the result. */
function expect(name, label, frame, opts, verdict, rule, kind, dir = "examples") {
  const buf = Uint8Array.from(frame);
  const r = P(name, dir).exec(buf, { ...fresh(), ...opts });
  if (r.ruleName === "-") r.ruleName = undefined;   // rule 0 is "no rule"
  const got = `${r.verdict}${r.ruleName ? `(${r.ruleName})` : ""}`;
  const want = `${verdict}${rule ? `(${rule})` : ""}`;
  ok(r.verdict === verdict && (rule === undefined || r.ruleName === rule), `${dir}/${name}: ${label}`, `got ${got}, want ${want}`);
  if (kind && dir === "examples") note(name, kind);
  r.bytes = buf;
  return r;
}
const attack = (name, label, frame, opts, verdict, rule, dir) => expect(name, label, frame, opts, verdict, rule, "positive", dir);
const benign = (name, label, frame, opts = {}, rule, dir) => expect(name, label, frame, opts, "pass", rule, "benign", dir);

/* ---- realistic inputs ---------------------------------------------------- */
const CURL_GET = "GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/8.23.0\r\nAccept: */*\r\n\r\n";
const FIREFOX_GET =
  "GET /search?q=red+shoes&next=%2Faccount%2Forders&utm_source=newsletter HTTP/1.1\r\n" +
  "Host: shop.example.com\r\n" +
  "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0\r\n" +
  "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
  "Accept-Language: en-US,en;q=0.5\r\n" +
  "Accept-Encoding: gzip, deflate, br, zstd\r\n" +
  "Referer: https://shop.example.com/category/shoes?page=2\r\n" +
  "Connection: keep-alive\r\n" +
  "Cookie: session=8f2b1c9e4d7a4f0b9c3e5a6d7f801234; _ga=GA1.2.1193847562.1731542400; theme=dark; cart=%5B%7B%22id%22%3A42%7D%5D\r\n" +
  "Upgrade-Insecure-Requests: 1\r\n" +
  "Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-User: ?1\r\n" +
  "Priority: u=0, i\r\n\r\n";
const BOUNDARY = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
const MULTIPART_BODY =
  `--${BOUNDARY}\r\nContent-Disposition: form-data; name="title"\r\n\r\nHoliday photos -- the 'red' or 'blue' album\r\n` +
  `--${BOUNDARY}\r\nContent-Disposition: form-data; name="notes"\r\n\r\nSee ../README for the layout; select a cover, then join the union of both sets.\r\n` +
  `--${BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="style.css"\r\nContent-Type: text/css\r\n\r\n` +
  `/* theme */\nbody { background: url(../img/bg.png); }\n.a { color: #333; }\n\r\n` +
  `--${BOUNDARY}--\r\n`;
const MULTIPART_POST =
  "POST /upload HTTP/1.1\r\nHost: shop.example.com\r\n" +
  "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n" +
  `Content-Type: multipart/form-data; boundary=${BOUNDARY}\r\nContent-Length: ${MULTIPART_BODY.length}\r\n` +
  "Origin: https://shop.example.com\r\nAccept: */*\r\nCookie: session=8f2b1c9e4d7a4f0b9c3e5a6d7f801234\r\n\r\n" + MULTIPART_BODY;
const JSON_BODY = JSON.stringify({
  order: { id: 48213, customer: { name: "Ada Lovelace", email: "ada@example.com", tags: ["vip", "beta"] },
    items: [{ sku: "SH-42", qty: 2, options: { size: 42, colour: "red" } }, { sku: "LC-01", qty: 1, options: {} }],
    notes: "leave with the neighbour {flat 3} if out" },
});
const post = (path, type, body, extra = "") =>
  `POST ${path} HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: python-requests/2.32.3\r\nAccept: */*\r\n${extra}Content-Type: ${type}\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
const JSON_POST = post("/v1/orders", "application/json", JSON_BODY);
const HTTP_200 =
  "HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: Sat, 14 Nov 2026 09:12:44 GMT\r\nContent-Type: application/json\r\nContent-Length: 87\r\n\r\n" +
  '{"id":48213,"status":"paid","phone":"+1-415-555-0100","updated":"2026-11-14T09:12:44Z"}';

const HELLO = fixture("clienthello-openssl"), HELLO_CURL = fixture("clienthello-curl");
const HELLO_TLS12 = fixture("clienthello-openssl-tls12"), HELLO_TLS10 = fixture("clienthello-openssl-tls10");
const HELLO_C2 = fixture("clienthello-openssl-sni-c2");
const DNS_A = fixture("dns-query-a"), DNS_TXT = fixture("dns-query-txt");
const DNS_TUNNEL = fixture("dns-query-tunnel"), DNS_MANY = fixture("dns-query-manylabels");

/* A TCP header as the named stack sends it. flags: 0x02 SYN, 0x10 ACK, 0x18 PSH|ACK. */
const be16 = (v) => [(v >> 8) & 0xff, v & 0xff];
const SYN_OPTS = [2, 4, 5, 180, 4, 2, 8, 10, 0x9a, 0x3c, 0x51, 0x07, 0, 0, 0, 0, 1, 3, 3, 7]; // MSS 1460, SACK-perm, TS, NOP, WS 7
const tcpHeader = ({ sport = 51514, dport = 8080, flags = 0x18, win = 502, opts = [] }) =>
  Uint8Array.from([...be16(sport), ...be16(dport), 0x3b, 0x9a, 0xca, 0x01, 0, 0, 0, 0, ((20 + opts.length) / 4) << 4, flags, ...be16(win), 0, 0, 0, 0, ...opts]);
const ipv4 = ({ ttl = 64, src = [192, 0, 2, 10], dst = [198, 51, 100, 7] }, l4) =>
  cat([0x45, 0, ...be16(20 + l4.length), 0x1c, 0x46, 0x40, 0, ttl, 6, 0, 0, ...src, ...dst], l4);
const SYN = { linux: { ttl: 64, win: 64240 }, windows: { ttl: 128, win: 64240 }, macos: { ttl: 64, win: 65535 } };
const synSeg = (os, o = {}) => tcpHeader({ flags: 0x02, win: SYN[os].win, opts: SYN_OPTS, ...o });

/* Every benign input with its natural 5-tuple. `tcp`/`udp` ports are the ones
 * that traffic is really seen on; the cross-check tries each. */
const BENIGN = [
  { name: "curl GET", bytes: enc(CURL_GET), proto: 6, dports: [80, 8080] },
  { name: "Firefox GET (%2F in query, cookies)", bytes: enc(FIREFOX_GET), proto: 6, dports: [80, 8080] },
  { name: "multipart POST (WebKit boundary)", bytes: enc(MULTIPART_POST), proto: 6, dports: [80, 8080] },
  { name: "JSON API POST", bytes: enc(JSON_POST), proto: 6, dports: [80, 8080] },
  { name: "HTTP 200 response", bytes: enc(HTTP_200), proto: 6, dports: [51514], sport: 8080 },
  { name: "openssl ClientHello", bytes: HELLO, proto: 6, dports: [443] },
  { name: "curl ClientHello", bytes: HELLO_CURL, proto: 6, dports: [443] },
  { name: "openssl TLS1.2 ClientHello", bytes: HELLO_TLS12, proto: 6, dports: [443] },
  { name: "DNS A query", bytes: DNS_A, proto: 17, dports: [53], sport: 40212 },
  { name: "DNS TXT query", bytes: DNS_TXT, proto: 17, dports: [53], sport: 40213 },
];

/* What each showcase program reads, so the cross-check hands it the right frame. */
const LAYER = { syn_flood: "tcp", os_fingerprint: "ip" };
const SHOWCASE = readdirSync(new URL("examples/", root)).filter((f) => f.endsWith(".pfc")).map((f) => f.slice(0, -4)).filter((n) => !OWNER.has(n)).sort();

/* ---- per-program cases --------------------------------------------------- */

/* live_blocklist / control_plane — needles and dials the host sets at runtime. */
{
  const o = (extra = {}) => ({ dport: 8080, ...extra });
  const hostReq = enc("GET / HTTP/1.1\r\nHost: tracker.evil.example\r\nUser-Agent: curl/8.23.0\r\nAccept: */*\r\n\r\n");
  attack("live_blocklist", "a host the operator just listed", hostReq, o({ knobStrs: { bad_host: "tracker.evil.example" } }), "rst", "blocked_host");
  attack("live_blocklist", "a token the operator just listed", enc("GET /api/me HTTP/1.1\r\nHost: api.example\r\nAuthorization: Bearer leaked-token-7f3a\r\n\r\n"), o({ knobStrs: { bad_token: "leaked-token-7f3a" } }), "ban", "blocked_token");
  attack("live_blocklist", "a user-agent the operator just listed", enc(CURL_GET), o({ knobStrs: { bad_ua: "curl/8.23.0" } }), "drop", "blocked_ua");
  benign("live_blocklist", "the same host with nothing listed", hostReq, o());
  benign("live_blocklist", "listed host, but the kill-switch is off", hostReq, o({ knobStrs: { bad_host: "tracker.evil.example" }, knobs: { enforce: 0 } }));
  benign("live_blocklist", "a different host than the one listed", enc(CURL_GET), o({ knobStrs: { bad_host: "tracker.evil.example" } }));

  attack("control_plane", "listed host, enforce mode (the default)", hostReq, o({ knobStrs: { bad_host: "tracker.evil.example" } }), "ban", "blocked_host");
  benign("control_plane", "listed host, kill-switch off", hostReq, o({ knobStrs: { bad_host: "tracker.evil.example" }, knobs: { enforce: 0 } }));
  benign("control_plane", "nothing listed", hostReq, o());
}

/* blocklist — `src in set`, the set loaded by the host. */
{
  const set = ["203.0.113.0/24", "198.51.100.64/26"];
  attack("blocklist", "source inside a listed /24", enc(CURL_GET), { src: "203.0.113.9", set }, "drop", "blocklist");
  attack("blocklist", "source inside a listed /26", enc(FIREFOX_GET), { src: "198.51.100.100", set }, "drop", "blocklist");
  benign("blocklist", "source just outside the /26", enc(CURL_GET), { src: "198.51.100.128", set });
  benign("blocklist", "unlisted source", enc(FIREFOX_GET), { src: "192.0.2.10", set });
}

/* crawlers — user-agent match, case-insensitive, :80. */
{
  const ua = (s) => enc(`GET /robots.txt HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ${s}\r\nAccept: */*\r\n\r\n`);
  attack("crawlers", "GPTBot", ua("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"), { dport: 80 }, "rst", "crawler");
  attack("crawlers", "ClaudeBot", ua("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"), { dport: 80 }, "rst", "crawler");
  attack("crawlers", "Bytespider, lower-cased", ua("mozilla/5.0 (linux; android 5.0) applewebkit/537.36 (compatible; bytespider; spider-feedback@bytedance.com)"), { dport: 80 }, "rst", "crawler");
  benign("crawlers", "curl", enc(CURL_GET), { dport: 80 });
  benign("crawlers", "Firefox", enc(FIREFOX_GET), { dport: 80 });
  benign("crawlers", "GPTBot on another port is not this rule's business", ua("GPTBot/1.2"), { dport: 8080 });
}

/* dlp_redact — in-place rewrite; assert on the bytes. */
{
  const TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
  const body = `ssn=123-45-6789&card=4111-1111-1111-1111&token=${TOKEN}&phone=415-555-0100`;
  const want = `ssn=***********&card=XXXXXXXXXXXXXXXXXXX&token=ghp_${"X".repeat(36)}&phone=415-555-0100`;
  const req = post("/signup", "application/x-www-form-urlencoded", body);
  let r = attack("dlp_redact", "request to the app: verdict", enc(req), { dport: 8080 }, "pass");
  ok(dec(r.bytes) === req.replace(body, want), "examples/dlp_redact: SSN, card and token rewritten in the request", dec(r.bytes).slice(-120));
  ok(r.bytes.length === req.length, "examples/dlp_redact: length preserved");
  const resp = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ssn":"987-65-4321","pat":"${TOKEN}"}`;
  r = attack("dlp_redact", "reply from the app: verdict", enc(resp), { dport: 51514, sport: 8080 }, "pass");
  ok(dec(r.bytes).endsWith(`{"ssn":"***********","pat":"ghp_${"X".repeat(36)}"}`), "examples/dlp_redact: reply rewritten", dec(r.bytes).slice(-80));
  r = benign("dlp_redact", "another port is left alone", enc(req), { dport: 9000, sport: 51514 });
  ok(dec(r.bytes) === req, "examples/dlp_redact: nothing rewritten off the guarded port");
  const near = post("/x", "text/plain", "date 2026-11-14, phone 415-555-0100, ref GHP_16C7E42F292C6912E7710C838347AE178B4A, id ghp_tooshort");
  r = benign("dlp_redact", "near misses", enc(near), { dport: 8080 });
  ok(dec(r.bytes) === near, "examples/dlp_redact: dates, phone numbers, an upper-case prefix and a short token are untouched", dec(r.bytes).slice(-110));
}

/* dns_tunnel — QNAME walk. */
{
  const udp = { proto: 17, dport: 53, sport: 40212 };
  attack("dns_tunnel", "62-byte base32 labels (real query)", DNS_TUNNEL, udp, "drop", "dns_tunnel_label");
  attack("dns_tunnel", "23 labels (real query)", DNS_MANY, udp, "drop", "dns_tunnel_labels");
  /* four 45-byte labels: no single label over 50, but 180 bytes of name */
  const big = cat(DNS_A.subarray(0, 12), ...Array.from({ length: 4 }, () => [45, ...enc("a1b2c3d4e5".repeat(5)).subarray(0, 45)]), [7, ...enc("example"), 3, ...enc("com"), 0, 0, 16, 0, 1]);
  attack("dns_tunnel", "oversized name built from 45-byte labels", big, udp, "drop", "dns_tunnel_size");
  benign("dns_tunnel", "www.example.com A", DNS_A, udp, "dns_query");
  benign("dns_tunnel", "_dmarc.mail.example.co.uk TXT", DNS_TXT, udp, "dns_query");
  /* The same real query with an EDNS OPT record carrying a client cookie whose
   * bytes look like long labels (0x3f = 63). The walk must stop at the root label
   * and never read the additional section as part of the name. */
  const edns = cat(DNS_A, [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 0x3f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a, 0x39, 0x38]);
  edns[11] = 1; // ARCOUNT
  benign("dns_tunnel", "EDNS cookie after the question is not a label", edns, udp, "dns_query");
  benign("dns_tunnel", "the tunnel query on a non-DNS port", DNS_TUNNEL, { proto: 17, dport: 5353 });
}

/* fsm — greet, authenticate, then commands; CONFIG stays gated. */
{
  const run = (steps) => { let flow = {}; const out = []; for (const s of steps) { const r = P("fsm").exec(enc(s), { dport: 7000, flow }); flow = r.flow; out.push(show(r)); } return out.join(" "); };
  const seq = (label, steps, want, kind) => { const got = run(steps); ok(got === want, `examples/fsm: ${label}`, `got ${got}, want ${want}`); note("fsm", kind); };
  seq("a well-behaved session", ["HELO client.example\r\n", "AUTH alice s3cret\r\n", "GET inventory\r\n", "PUT item 42\r\n"], "pass pass pass pass", "benign");
  seq("command before greeting", ["GET inventory\r\n"], "drop(no_greeting)", "positive");
  seq("command before authenticating", ["HELO client.example\r\n", "GET inventory\r\n"], "pass drop(not_authenticated)", "positive");
  seq("admin command after authenticating", ["HELO x\r\n", "AUTH alice s3cret\r\n", "CONFIG set debug 1\r\n"], "pass pass rst(admin_blocked)", "positive");
  benign("fsm", "pure ACK", new Uint8Array(0), { dport: 7000 });
  benign("fsm", "other ports are not this protocol", enc("GET inventory\r\n"), { dport: 7001 });
}

/* heartbleed — the public exploit's heartbeat vs. well-formed and encrypted ones. */
{
  const tls = { dport: 443 };
  const EXPLOIT = [0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x40, 0x00]; // heartbeat record, 3 bytes, claiming 16384
  let r = attack("heartbleed", "the exploit heartbeat (claims 16384 bytes in a 3-byte record)", EXPLOIT, tls, "ban", "heartbleed");
  ok(r.source.banned === true, "examples/heartbleed: the source is banned");
  ok(r.console.join("|") === "heartbleed: claims 16384 payload bytes in a 3-byte record", "examples/heartbleed: console line", r.console.join("|"));
  attack("heartbleed", "exploit sent in the same segment after a handshake record", cat(HELLO_TLS12, EXPLOIT), tls, "ban", "heartbleed");
  attack("heartbleed", "claim one byte over what the record can hold", cat([0x18, 3, 3, 0, 35, 1, 0, 17], new Uint8Array(32)), tls, "ban", "heartbleed");
  const honest = cat([0x18, 3, 3, 0, 35, 1, 0, 16], enc("0123456789abcdef"), new Uint8Array(16)); // 16 payload + 16 padding
  benign("heartbleed", "well-formed heartbeat request", honest, tls);
  benign("heartbleed", "heartbeat response", cat([0x18, 3, 3, 0, 35, 2, 0xff, 0xff], new Uint8Array(32)), tls);
  for (const [n, h] of [["openssl", HELLO], ["curl", HELLO_CURL], ["TLS1.2", HELLO_TLS12], ["TLS1.0", HELLO_TLS10]]) benign("heartbleed", `${n} ClientHello`, h, tls);
  /* After ChangeCipherSpec the record body is ciphertext: an encrypted heartbeat
   * whose bytes happen to look like an overread must be left alone. */
  const ccs = cat([0x14, 3, 3, 0, 1, 1], [0x16, 3, 3, 0, 40], new Uint8Array(40).fill(0xa7));
  r = benign("heartbleed", "ChangeCipherSpec + encrypted Finished", ccs, tls);
  benign("heartbleed", "encrypted heartbeat record later on that connection", [0x18, 3, 3, 0, 24, 1, 0xfe, 0xdc, ...new Uint8Array(21).fill(0x5c)], { ...tls, flow: r.flow });
  benign("heartbleed", "the exploit bytes on a non-TLS port", EXPLOIT, { dport: 8080 });
}

/* http_router — method x path x source. */
{
  const req = (line, extra = "") => enc(`${line} HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: curl/8.23.0\r\nAccept: */*\r\n${extra}\r\n`);
  const out = { dport: 80, src: "203.0.113.9" }, inside = { dport: 80, src: "10.1.2.3" };
  attack("http_router", "/admin from outside", req("GET /admin/users"), out, "rst", "admin_from_outside");
  attack("http_router", "/internal from outside", req("GET /internal/metrics"), out, "drop", "internal_from_outside");
  attack("http_router", "TRACE", req("TRACE /"), inside, "drop", "trace_method");
  attack("http_router", "unauthenticated API write", req("DELETE /api/v1/orders/48213"), out, "rst", "api_write_noauth");
  attack("http_router", "unauthenticated API POST", enc(post("/api/v1/orders", "application/json", JSON_BODY)), out, "rst", "api_write_noauth");
  attack("http_router", "X-Authorization is not Authorization", req("PUT /api/v1/orders/1", "X-Authorization: Bearer abc\r\n"), out, "rst", "api_write_noauth");
  benign("http_router", "/admin from an internal address", req("GET /admin/users"), inside, "admin_ok");
  benign("http_router", "/internal from loopback", req("GET /internal/metrics"), { dport: 80, src: "127.0.0.1" });
  benign("http_router", "authenticated API write", enc(post("/api/v1/orders", "application/json", JSON_BODY, "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc\r\n")), out, "api_write_authed");
  benign("http_router", "API read needs no credentials", req("GET /api/v1/orders/48213"), out, "routed");
  benign("http_router", "curl", enc(CURL_GET), out, "routed");
  benign("http_router", "Firefox", enc(FIREFOX_GET), out, "routed");
}

/* json_depth — nesting depth of the request body. */
{
  const web = { dport: 8080 };
  const nest = (open, close, n, leaf = "1") => open.repeat(n) + leaf + close.repeat(n);
  attack("json_depth", "objects nested 20 deep", enc(post("/v1/orders", "application/json", nest('{"a":', "}", 20))), web, "drop", "json_too_deep");
  attack("json_depth", "arrays nested 400 deep (the classic bomb)", enc(post("/v1/orders", "application/json", nest("[", "]", 400))), web, "drop", "json_too_deep");
  attack("json_depth", "mixed objects and arrays, 18 deep", enc(post("/v1/orders", "application/json", nest('{"a":[', "]}", 9))), web, "drop", "json_too_deep");
  benign("json_depth", "exactly 16 deep is allowed", enc(post("/v1/orders", "application/json", nest('{"a":', "}", 16))), web);
  benign("json_depth", "an ordinary API body", enc(JSON_POST), web);
  benign("json_depth", "many shallow brackets", enc(post("/v1/batch", "application/json", JSON.stringify(Array.from({ length: 40 }, (_, i) => ({ i, t: [i] }))))), web);
  benign("json_depth", "braces in a cookie are headers, not body", enc(FIREFOX_GET), web);
  benign("json_depth", "deep JSON on another port", enc(post("/x", "application/json", nest("[", "]", 400))), { dport: 9000 });
}

/* multi_tenant — one image, argv-tuned. */
{
  const ua = (s, path = "/") => enc(`GET ${path} HTTP/1.1\r\nHost: t1.example.com\r\nUser-Agent: ${s}\r\nAccept: */*\r\n\r\n`);
  const get = (path) => ua("curl/8.23.0", path);
  attack("multi_tenant", "sqlmap names itself", ua("sqlmap/1.8.11#stable (https://sqlmap.org)"), { dport: 80 }, "ban", "scanner");
  attack("multi_tenant", "Nmap NSE user-agent", ua("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"), { dport: 80 }, "ban", "scanner");
  attack("multi_tenant", "dot-dot in the request line", get("/static/../../../../etc/passwd"), { dport: 80 }, "rst", "attack");
  attack("multi_tenant", "encoded dot-dot in the request line", get("/static/..%2f..%2f..%2fetc/passwd"), { dport: 80 }, "rst", "attack");
  attack("multi_tenant", "UNION SELECT", get("/item?id=1+union+select+user,pass+from+users"), { dport: 80 }, "rst", "attack");
  /* argv[0]: the tenant's port */
  attack("multi_tenant", "tenant on :8443 (argv[0])", ua("sqlmap/1.8.11"), { dport: 8443, argv: [8443] }, "ban", "scanner");
  benign("multi_tenant", "that tenant does not guard :80", ua("sqlmap/1.8.11"), { dport: 80, argv: [8443] });
  /* argv[3]: strikes per source before a ban, counted across connections */
  const strikes = (argv) => { let source = {}; const out = []; for (let i = 0; i < 6; i++) { const r = P("multi_tenant").exec(get("/a/../../etc/shadow"), { dport: 80, argv, source, flow: {}, sport: 40000 + i }); source = r.source; out.push(r.banned ? "banned" : `${r.verdict}(${r.ruleName})`); } return out.join(" "); };
  let got = strikes([]);
  ok(got === "rst(attack) rst(attack) rst(attack) rst(attack) ban(attack_repeat) banned", "examples/multi_tenant: default 5 strikes, across fresh connections", got);
  got = strikes([80, 1024, 0, 2]);
  ok(got === "rst(attack) ban(attack_repeat) banned banned banned banned", "examples/multi_tenant: argv[3]=2 strikes", got);
  note("multi_tenant", "positive");
  /* argv[1] / argv[2]: request-line ceiling, strict or permissive */
  const long = get("/search?q=" + "a".repeat(1500));
  benign("multi_tenant", "long request line, permissive tenant: tallied", long, { dport: 80 }, "uri_too_long_seen");
  attack("multi_tenant", "long request line, strict tenant", long, { dport: 80, argv: [80, 1024, 1] }, "rst", "uri_too_long");
  benign("multi_tenant", "same line under a raised ceiling", long, { dport: 80, argv: [80, 4096, 1] });
  attack("multi_tenant", "a lowered ceiling (argv[1]=64)", enc(FIREFOX_GET), { dport: 80, argv: [80, 64, 1] }, "rst", "uri_too_long");
  benign("multi_tenant", "'unmapped' is not nmap", get("/api/unmapped/regions"), { dport: 80 });
  benign("multi_tenant", "../ in an uploaded stylesheet is not a traversal", enc(MULTIPART_POST), { dport: 80, argv: [80, 1024, 1] });
  benign("multi_tenant", "Firefox, strict tenant", enc(FIREFOX_GET), { dport: 80, argv: [80, 1024, 1] });
}

/* os_fingerprint — observe-only; the guess is the counted rule. */
{
  const pkt = (os, ttl) => ipv4({ ttl: ttl ?? SYN[os].ttl }, synSeg(os));
  let r = attack("os_fingerprint", "Linux SYN (TTL 64, window 64240)", pkt("linux"), { payload: 60, sport: 51514 }, "pass", "os_linux");
  ok(r.console.join("|") === "osfp sport=51514 ttl=64 win=64240", "examples/os_fingerprint: console line", r.console.join("|"));
  attack("os_fingerprint", "Linux SYN, 11 hops away (TTL 53)", pkt("linux", 53), { payload: 60 }, "pass", "os_linux");
  attack("os_fingerprint", "Windows SYN, 10 hops away (TTL 118)", pkt("windows", 118), { payload: 60 }, "pass", "os_windows");
  attack("os_fingerprint", "macOS SYN (TTL 64, window 65535)", pkt("macos"), { payload: 60 }, "pass", "os_macos_bsd");
  attack("os_fingerprint", "router (TTL 255)", pkt("linux", 255), { payload: 60 }, "pass", "os_other");
  /* IP options push the TCP header out: the IHL must be honoured */
  const withOpts = cat([0x46, 0, 0, 64, 0x1c, 0x46, 0x40, 0, 128, 6, 0, 0, 192, 0, 2, 10, 198, 51, 100, 7, 1, 1, 1, 0], synSeg("windows"));
  attack("os_fingerprint", "IPv4 options (IHL 6)", withOpts, { payload: 64 }, "pass", "os_windows");
  r = benign("os_fingerprint", "a data segment is not fingerprinted", ipv4({}, cat(tcpHeader({}), enc(CURL_GET))), { payload: 40 });
  ok(r.ruleName === undefined && r.console.length === 0, "examples/os_fingerprint: no guess for a non-SYN", `${r.ruleName} ${r.console}`);
  r = benign("os_fingerprint", "SYN-ACK is not an opening SYN", ipv4({}, tcpHeader({ flags: 0x12, win: 65160, opts: SYN_OPTS })), { payload: 60 });
  ok(r.ruleName === undefined, "examples/os_fingerprint: no guess for a SYN-ACK");
}

/* port_knock — three in-order markers open the connection. */
{
  const run = (steps) => { let flow = {}; const out = []; for (const s of steps) { const r = P("port_knock").exec(enc(s), { dport: 7000, flow }); flow = r.flow; out.push(show(r)); } return out.join(" "); };
  const seq = (label, steps, want, kind) => { const got = run(steps); ok(got === want, `examples/port_knock: ${label}`, `got ${got}, want ${want}`); note("port_knock", kind); };
  seq("the full knock, then the real protocol", ["KNOCK-ALPHA", "KNOCK-BRAVO", "KNOCK-CHARLIE", "SSH-2.0-OpenSSH_9.9\r\n", "\x00\x00\x05\x1c\x06\x14"], "pass pass pass pass pass", "benign");
  seq("speaking the real protocol without knocking", ["SSH-2.0-OpenSSH_9.9\r\n"], "drop(knock_1)", "positive");
  seq("knocks out of order", ["KNOCK-ALPHA", "KNOCK-CHARLIE"], "pass drop(knock_2)", "positive");
  seq("a wrong knock does not advance, the right one still does", ["KNOCK-ALPHA", "KNOCK-ALPHA", "KNOCK-BRAVO", "KNOCK-CHARLIE", "hello"], "pass drop(knock_2) pass pass pass", "positive");
  seq("two of three is not enough", ["KNOCK-ALPHA", "KNOCK-BRAVO", "SSH-2.0-OpenSSH_9.9\r\n"], "pass pass drop(knock_3)", "positive");
  benign("port_knock", "pure ACK", new Uint8Array(0), { dport: 7000 });
  benign("port_knock", "other ports are untouched", enc(CURL_GET), { dport: 8080 });
}

/* shadow_mode — the same rule, enforced and shadowed. */
{
  const web = { dport: 8080 };
  const scanner = enc("GET /index.php?id=1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: sqlmap/1.8.11#stable (https://sqlmap.org)\r\nAccept: */*\r\n\r\n");
  const probe = enc("GET /index.php?id=1%20UNION%20SELECT%20NULL,NULL HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/8.23.0\r\nAccept: */*\r\n\r\n");
  let r = attack("shadow_mode", "enforcing: scanner", scanner, web, "ban", "scanner");
  ok(r.source.banned === true, "examples/shadow_mode: enforcing plants the source ban");
  attack("shadow_mode", "enforcing: UNION SELECT probe", probe, web, "rst", "sqli");
  r = attack("shadow_mode", "shadowed: scanner is let through", scanner, { ...web, shadow: true }, "pass", "scanner");
  ok(r.would === "ban" && r.source.banned === false, "examples/shadow_mode: shadow reports would=ban and plants no ban", `would=${r.would} banned=${r.source.banned}`);
  r = attack("shadow_mode", "shadowed: probe is let through", probe, { ...web, shadow: true }, "pass", "sqli");
  ok(r.would === "rst", "examples/shadow_mode: shadow reports would=rst", `would=${r.would}`);
  r = benign("shadow_mode", "curl", enc(CURL_GET), web);
  ok(r.would === undefined, "examples/shadow_mode: nothing would have happened to a clean request");
  benign("shadow_mode", "multipart with 'union' and 'select' apart", enc(MULTIPART_POST), web);
}

/* sqli — scored signals; the weak one never acts alone. */
{
  const web = { dport: 8080 };
  const get = (target) => enc(`GET ${target} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/8.23.0\r\nAccept: */*\r\n\r\n`);
  const form = (body) => enc(post("/login", "application/x-www-form-urlencoded", body));
  attack("sqli", "UNION SELECT with a comment terminator in the URL", get("/item?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"), web, "ban", "sqli_high_confidence");
  attack("sqli", "UNION/**/SELECT (comment as whitespace)", get("/item?id=1+union/**/select+1,2,3"), web, "ban", "sqli_high_confidence");
  attack("sqli", "UNION ALL SELECT, no terminator: one signal", get("/item?id=-1+UNION+ALL+SELECT+NULL,version()"), web, "rst", "sqli");
  attack("sqli", "two strong signals", get("/item?id=1%27+or+1%3D1+union+select+1"), web, "ban", "sqli_high_confidence");
  attack("sqli", "encoded tautology", get("/login?user=admin%27+or+1%3D1"), web, "rst", "sqli");
  attack("sqli", "raw quote tautology in a form body", form("user=admin&pass=x' or '1'='1"), web, "rst", "sqli");
  attack("sqli", "time-based blind", get("/item?id=1+AND+SLEEP(5)"), web, "rst", "sqli");
  attack("sqli", "sqlmap-style nested sleep", get("/item?id=1%20AND%20(SELECT%204242%20FROM%20(SELECT(SLEEP(5)))a)"), web, "rst", "sqli");
  attack("sqli", "MSSQL waitfor in a form body (the `--` there is not in the request line)", form("id=1';WAITFOR DELAY '0:0:5'--"), web, "rst", "sqli");
  /* one strong signal per request: the third from the same address is a ban, on any connection */
  let source = {}; const out = [];
  for (let i = 0; i < 4; i++) { const r = P("sqli").exec(get("/login?user=admin%27+or+1%3D1"), { ...web, source, flow: {}, sport: 40000 + i }); source = r.source; out.push(r.banned ? "banned" : `${r.verdict}(${r.ruleName})`); }
  ok(out.join(" ") === "rst(sqli) rst(sqli) ban(sqli_repeat) banned", "examples/sqli: three strikes from one source, across fresh connections", out.join(" "));
  benign("sqli", "curl (Accept: */* is not a comment)", enc(CURL_GET), web);
  benign("sqli", "Firefox", enc(FIREFOX_GET), web);
  benign("sqli", "multipart (boundary dashes, quoted 'red' or 'blue', a CSS comment)", enc(MULTIPART_POST), web);
  benign("sqli", "a search for the words", get("/search?q=credit+union+near+me+select+branch"), web);
  benign("sqli", "code upload calling time.sleep(5)", enc(post("/paste", "text/plain", "import time\nfor i in range(3):\n    time.sleep(5)  # -- wait\n")), web);
  benign("sqli", "an attack on another port is not this rule's business", get("/item?id=1+union+select+1"), { dport: 9000 });
}

/* syn_flood — per-source SYN rate; the frame starts at the TCP header (l4 = 0). */
{
  const syn = (sport) => synSeg("linux", { sport, dport: 443 });
  const flood = (n, at = () => 0n) => { const source = {}; const tally = {}; let last; for (let i = 0; i < n; i++) { const r = P("syn_flood").exec(syn(20000 + i), { payload: 40, sport: 20000 + i, dport: 443, src: "203.0.113.9", flow: {}, source, now: at(i) }); Object.assign(source, r.source); last = r; const k = r.banned ? "banned" : `${r.verdict}${r.ruleName && r.verdict !== "pass" ? `(${r.ruleName})` : ""}`; tally[k] = (tally[k] ?? 0) + 1; } return { tally, last, source }; };
  /* 200 SYNs in one instant, each from a new source port, so each on a new flow */
  let f = flood(200);
  ok(JSON.stringify(f.tally) === JSON.stringify({ pass: 40, "drop(syn_rate)": 99, "ban(syn_flood)": 1, banned: 60 }), "examples/syn_flood: 200 SYNs from one address: burst, then drops, then a source ban", JSON.stringify(f.tally));
  note("syn_flood", "positive");
  /* a browser opening connections at a human pace never trips it */
  f = flood(120, (i) => BigInt(i) * (S / 10n)); // 10 new connections/s for 12 s
  ok(JSON.stringify(f.tally) === JSON.stringify({ pass: 120 }), "examples/syn_flood: 10 connections/s for 12 s all pass", JSON.stringify(f.tally));
  note("syn_flood", "benign");
  /* the limit is per source: the flooder's state does not touch anyone else */
  benign("syn_flood", "another source's SYN during the flood", syn(51514), { payload: 40, src: "192.0.2.10" });
  /* non-SYN segments are never counted, however many */
  const source = {}; let allPass = true;
  for (let i = 0; i < 500; i++) { const r = P("syn_flood").exec(cat(tcpHeader({}), enc(CURL_GET)), { payload: 20, flow: {}, source, now: 0n }); Object.assign(source, r.source); allPass &&= r.verdict === "pass"; }
  ok(allPass, "examples/syn_flood: 500 data segments in one instant all pass");
  benign("syn_flood", "SYN-ACK is not an opening SYN", tcpHeader({ flags: 0x12, opts: SYN_OPTS }), { payload: 40 });
}

/* tls_sni — parse to the server_name extension. */
{
  const tls = { dport: 443 };
  attack("tls_sni", "real ClientHello for c2.evil.example", HELLO_C2, tls, "rst", "blocked_sni");
  let source = {}; const out = [];
  for (let i = 0; i < 4; i++) { const r = P("tls_sni").exec(Uint8Array.from(HELLO_C2), { ...tls, source, flow: {}, sport: 40000 + i, now: BigInt(i) * S }); source = r.source; out.push(r.banned ? "banned" : `${r.verdict}(${r.ruleName})`); }
  ok(out.join(" ") === "rst(blocked_sni) rst(blocked_sni) ban(sni_repeat) banned", "examples/tls_sni: third blocked hello from one source is a ban", out.join(" "));
  /* the same hello segmented before the server_name extension (it sits at ~164) */
  const two = (hello, cut) => { let r = P("tls_sni").exec(hello.slice(0, cut), { ...fresh(), ...tls }); const first = r.verdict; r = P("tls_sni").exec(hello.slice(cut), { ...fresh(), ...tls, flow: r.flow }); return `${first} ${show(r)}`; };
  ok(two(HELLO_C2, 120) === "pass rst(blocked_sni)", "examples/tls_sni: server_name in the second segment is still caught", two(HELLO_C2, 120));
  ok(two(HELLO_C2, 170) === "pass rst(blocked_sni)", "examples/tls_sni: a name split across the segment boundary is still caught", two(HELLO_C2, 170));
  ok(two(HELLO, 120) === "pass pass", "examples/tls_sni: a benign hello in two segments passes", two(HELLO, 120));
  note("tls_sni", "positive"); note("tls_sni", "benign");
  for (const [n, h] of [["openssl", HELLO], ["curl", HELLO_CURL], ["TLS1.2", HELLO_TLS12], ["TLS1.0", HELLO_TLS10]]) benign("tls_sni", `${n} ClientHello for example.com`, h, tls);
  /* a blocked name anywhere but the server_name extension is not SNI: here in the session id */
  const sid = Uint8Array.from(HELLO); sid.set(enc("c2.evil.example"), 46);
  benign("tls_sni", "the blocked string inside the session id, real SNI example.com", sid, tls);
  benign("tls_sni", "application data record", cat([0x17, 3, 3, 0, 32], enc("c2.evil.example .onion padding!!")), tls);
  /* per-source ClientHello rate: burst 40 */
  source = {}; const flood = [];
  for (let i = 0; i < 42; i++) { const r = P("tls_sni").exec(Uint8Array.from(HELLO), { ...tls, source, flow: {}, sport: 30000 + i, now: 0n }); Object.assign(source, r.source); flood.push(r.verdict === "pass" ? "pass" : `${r.verdict}(${r.ruleName})`); }
  ok(flood.slice(0, 40).every((v) => v === "pass") && flood[40] === "drop(tls_handshake_flood)" && flood[41] === "drop(tls_handshake_flood)", "examples/tls_sni: the 41st ClientHello in an instant from one source is dropped", flood.slice(38).join(" "));
}

/* token_bucket — rate(5, 20) per connection. */
{
  const bucket = {}; let flow = {};
  const hit = (now) => { const r = P("token_bucket").exec(enc(CURL_GET), { dport: 80, flow, bucket, now }); flow = r.flow; return r.verdict === "pass" ? "pass" : `${r.verdict}(${r.ruleName})`; };
  const burst = Array.from({ length: 22 }, () => hit(0n));
  ok(burst.slice(0, 20).every((v) => v === "pass") && burst[20] === "drop(too_fast)" && burst[21] === "drop(too_fast)", "examples/token_bucket: burst of 20, then dropped", burst.slice(18).join(" "));
  const later = Array.from({ length: 6 }, () => hit(1n * S));
  ok(later.join(" ") === "pass pass pass pass pass drop(too_fast)", "examples/token_bucket: one second refills five tokens", later.join(" "));
  note("token_bucket", "positive");
  const b2 = {};
  const steady = Array.from({ length: 40 }, (_, i) => P("token_bucket").exec(enc(CURL_GET), { dport: 80, bucket: b2, now: BigInt(i) * (S / 4n) }).verdict);
  ok(steady.every((v) => v === "pass"), "examples/token_bucket: 4 requests/s for 10 s all pass");
  note("token_bucket", "benign");
  benign("token_bucket", "pure ACKs spend no tokens", new Uint8Array(0), { dport: 80, bucket: { tokens: 0, ts: 0 } });
}

/* ---- contrib/: regressions for the programs that were found broken ------- */
/* contrib/ is otherwise only compile-checked. These pin the specific failures
 * that were fixed, so they stay fixed; they are not a claim that the rest of
 * each program is right. */
const C = "contrib";
const CONTRIB_FIXED = ["tls_hello_policy", "url_decode_scan", "citrix_bleed", "session_pin", "ssn_leak", "banner_hide", "card_leak", "doh_detect",
  "email_dlp", "error_leak", "observe", "jwt_leak", "version_leak", "prototype_pollution", "proxyshell", "secret_scan"];
const reply = (type, body, extra = "") => enc(`HTTP/1.1 200 OK\r\n${extra}Content-Type: ${type}\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
const FROM_APP = { dport: 51514, sport: 8080 }; // a reply from the app on the plaintext hop

/* tls_hello_policy (was tls_ja3): reset every stock ClientHello as "tls_sslv3". */
{
  const tls = { dport: 443 };
  for (const [n, h] of [["openssl", HELLO], ["curl", HELLO_CURL], ["openssl -tls1_2", HELLO_TLS12]]) benign("tls_hello_policy", `${n} ClientHello`, h, tls, undefined, C);
  attack("tls_hello_policy", "real TLS 1.0 ClientHello (openssl -tls1)", HELLO_TLS10, tls, "rst", "tls_legacy_version", C);
  const ssl3 = Uint8Array.from(HELLO_TLS10); ssl3[10] = 0x00;            // legacy_version 0x0300
  attack("tls_hello_policy", "legacy_version SSLv3", ssl3, tls, "rst", "tls_sslv3", C);
  /* the TLS 1.2 hello has an empty session id, so its suites start at byte 46 */
  const suite = (i, v) => { const h = Uint8Array.from(HELLO_TLS12); h[46 + 2 * i] = v >> 8; h[47 + 2 * i] = v & 0xff; return h; };
  attack("tls_hello_policy", "RC4-SHA offered among the suites", suite(7, 0x0005), tls, "rst", "tls_weak_suites", C);
  const nSuites = ((HELLO_TLS12[44] << 8) | HELLO_TLS12[45]) / 2;
  attack("tls_hello_policy", "a NULL suite offered last", suite(nSuites - 1, 0x003b), tls, "rst", "tls_weak_suites", C);
  /* bytes 00 05 straddling two suites (xx00 05xx) are not RC4-SHA: alignment matters */
  const straddle = Uint8Array.from(HELLO_TLS12); straddle[47] = 0x00; straddle[48] = 0x05;
  benign("tls_hello_policy", "00 05 straddling two suites", straddle, tls, undefined, C);
}

/* url_decode_scan: dropped any request with %2F / %2e anywhere, query included. */
{
  const web = { dport: 8080 };
  const get = (t) => enc(`GET ${t} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/8.23.0\r\nAccept: */*\r\n\r\n`);
  attack("url_decode_scan", "%2e%2e in the path", get("/static/%2e%2e/%2e%2e/etc/passwd"), web, "drop", "encoded_traversal", C);
  attack("url_decode_scan", "Apache CVE-2021-41773 form (.%2e)", get("/cgi-bin/.%2e/.%2e/.%2e/bin/sh"), web, "drop", "encoded_traversal", C);
  attack("url_decode_scan", "..%2f in the path", get("/files/..%2f..%2fetc%2fpasswd"), web, "drop", "encoded_traversal", C);
  attack("url_decode_scan", "plain dot-dot segment", get("/static/../../etc/passwd"), web, "drop", "path_traversal", C);
  benign("url_decode_scan", "encoded slash in a redirect parameter", get("/login?next=%2Fhome%2Findex&src=%2e"), web, undefined, C);
  benign("url_decode_scan", "Firefox (%2F in the query)", enc(FIREFOX_GET), web, undefined, C);
  benign("url_decode_scan", "encoded dots in the QUERY are out of scope", get("/view?file=%2e%2e%2fnotes.txt"), web, undefined, C);
  benign("url_decode_scan", "dotfile and versioned paths", get("/.well-known/security.txt?v=1..2"), web, undefined, C);
}

/* citrix_bleed: scanned :443 (ciphertext) and tested len > 4096 in a 2048-byte window. */
{
  const web = { dport: 8080 };
  const probe = (host) => enc(`GET /oauth/idp/.well-known/openid-configuration HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
  attack("citrix_bleed", "the exploit: a 24 KB Host header (runs past the window)", probe("a".repeat(24576)), web, "rst", "citrix_bleed", C);
  attack("citrix_bleed", "a 600-byte Host header, measured", probe("a".repeat(600)), web, "rst", "citrix_bleed", C);
  let source = {}; const out = [];
  for (let i = 0; i < 4; i++) { const r = P("citrix_bleed", C).exec(probe("a".repeat(24576)), { ...web, source, flow: {}, sport: 40000 + i }); source = r.source; out.push(show(r)); }
  ok(out.join(" ") === "rst(citrix_bleed) rst(citrix_bleed) ban(citrix_bleed_repeat) banned", "contrib/citrix_bleed: a harvest loop is banned", out.join(" "));
  benign("citrix_bleed", "the same endpoint with an ordinary Host", probe("gateway.example.com"), web, undefined, C);
  benign("citrix_bleed", "a 251-byte hostname is still a hostname", probe(("a".repeat(61) + ".").repeat(4) + "com"), web, undefined, C);
  benign("citrix_bleed", "another path with a long header elsewhere", enc(FIREFOX_GET), web, undefined, C);
}

/* session_pin: pinned the source port, which cannot change within a flow. */
{
  const req = (cookie, path = "/account") => enc(`GET ${path} HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: curl/8.23.0\r\nAccept: */*\r\n${cookie ? `Cookie: ${cookie}\r\n` : ""}\r\n`);
  const A = "8f2b1c9e4d7a4f0b9c3e5a6d7f801234", B = "8f2b1c9e0000000000000000deadbeef"; // differ from the 9th byte on
  const run = (steps) => { let flow = {}; const out = []; for (const s of steps) { const r = P("session_pin", C).exec(s, { dport: 8080, flow }); flow = r.flow; out.push(show(r)); } return out.join(" "); };
  let got = run([req(`session=${A}`), req(`theme=dark; session=${A}; _ga=GA1.2.1`, "/orders"), req(`session=${A}`, "/logout")]);
  ok(got === "pass pass pass", "contrib/session_pin: one session on a connection, cookie order varying", got);
  got = run([req(`session=${A}`), req(`session=${A}`), req(`theme=dark; session=${B.slice(0, 4)}XXXX${B.slice(8)}`)]);
  ok(got === "pass pass rst(session_changed)", "contrib/session_pin: a different session on the same connection is reset", got);
  got = run([req(`session=${A}`), req(`session=${A.slice(0, 7)}0${A.slice(8)}`)]);
  ok(got === "pass rst(session_changed)", "contrib/session_pin: a change in the 8th byte is seen", got);
  got = run([req(""), req(`session=${A}`), req(""), req(`lang=en`), req(`session=${A}`)]);
  ok(got === "pass pass pass pass pass", "contrib/session_pin: requests without the cookie do not disturb the pin", got);
  got = run([req(`session=${B}`)]);
  ok(got === "pass", "contrib/session_pin: another session on its own connection is fine", got);
}

/* The programs that scanned payload bytes on :443. Each now names the plaintext
 * hop; one positive each on that hop proves the rule can fire at all. */
{
  const web = { dport: 8080 };
  let r = attack("ssn_leak", "record dump in a reply", reply("text/csv", "name,email,ssn\r\nAda,ada@example.com,123-45-6789\r\nBob,bob@example.com,987-65-4321\r\n"), FROM_APP, "rst", "ssn_dump", C);
  ok(dec(r.bytes).includes("Ada,ada@example.com,***********") && dec(r.bytes).includes("Content-Length: 82\r\n"), "contrib/ssn_leak: SSNs scrubbed, Content-Length digits left alone", dec(r.bytes).slice(-90));
  r = attack("banner_hide", "Apache banner in a reply", reply("text/html", "<h1>It works!</h1>", "Server: Apache/2.4.49\r\n"), FROM_APP, "pass", undefined, C);
  ok(dec(r.bytes).includes("Server: svc-tier-aaaa\r\n") && !dec(r.bytes).includes("Apache"), "contrib/banner_hide: banner rewritten in place", dec(r.bytes).slice(0, 60));
  attack("card_leak", "PAN in a reply", reply("application/json", '{"card":"4111-1111-1111-1111","exp":"12/29"}'), FROM_APP, "rst", "card_leak", C);
  attack("email_dlp", "CSV export in a reply", reply("text/csv", "name,email\r\nAda,ada@example.com\r\nBob,bob@example.com\r\n"), FROM_APP, "rst", "email_dump", C);
  attack("error_leak", "Python traceback in a reply", reply("text/plain", 'Traceback (most recent call last):\n  File "/srv/app/views.py", line 42, in order\nKeyError: \'id\'\n'), FROM_APP, "rst", "error_leak", C);
  r = attack("version_leak", "PHP version header in a reply", reply("text/html", "<p>ok</p>", "X-Powered-By: PHP/8.1.2\r\n"), FROM_APP, "pass", undefined, C);
  ok(!dec(r.bytes).includes("PHP/8.1.2"), "contrib/version_leak: fingerprint redacted in place", dec(r.bytes).slice(0, 60));
  r = attack("jwt_leak", "JWT in a URL", enc("GET /cb?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc HTTP/1.1\r\nHost: a.example.com\r\nAccept: */*\r\n\r\n"), web, "pass", undefined, C);
  ok(r.console.length === 1 && r.console[0].startsWith("jwt leaked outside Authorization"), "contrib/jwt_leak: the leak is reported", r.console.join("|"));
  attack("prototype_pollution", "__proto__ in a JSON body", enc(post("/v1/profile", "application/json", '{"name":"x","__proto__":{"isAdmin":true}}')), web, "drop", "proto_pollution", C);
  attack("proxyshell", "autodiscover path confusion", enc("GET /autodiscover/autodiscover.json?@evil.example/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.example HTTP/1.1\r\nHost: mail.example.com\r\n\r\n"), web, "rst", "proxyshell", C);
  attack("secret_scan", "AWS key id in a request", enc(post("/hook", "application/json", '{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE"}')), web, "rst", "secret_leak", C);
  const crawler = enc("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)\r\n\r\n");
  attack("observe", "crawler on :80 is tallied", crawler, { dport: 80 }, "pass", "ai_crawler", C);
  attack("observe", "a TLS connection is tallied by port, not scanned", HELLO, { dport: 443 }, "pass", "https", C);
  attack("doh_detect", "ClientHello for dns.google (real capture)", fixture("clienthello-openssl-sni-doh"), { dport: 443 }, "rst", "doh_resolver_sni", C);
  attack("doh_detect", "RFC 8484 POST on the plaintext hop", enc(post("/dns-query", "application/dns-message", "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01")), web, "rst", "doh_block", C);
  benign("doh_detect", "ClientHello for example.com", HELLO, { dport: 443 }, undefined, C);
  benign("doh_detect", "application data that mentions a resolver is not a ClientHello", cat([0x17, 3, 3, 0, 10], enc("dns.google")), { dport: 443 }, undefined, C);
}

/* every benign input through every fixed contrib program, as for the showcase */
for (const name of CONTRIB_FIXED) {
  for (const b of BENIGN) {
    for (const dport of b.dports) {
      const buf = Uint8Array.from(b.bytes);
      const r = P(name, C).exec(buf, { ...fresh(), proto: b.proto, dport, sport: b.sport ?? 51514, src: "192.0.2.10" });
      ok(r.verdict === "pass", `cross-check: ${b.name} -> contrib/${name} (:${dport})`, `got ${r.verdict}(${r.ruleName})`);
      ok(buf.every((v, i) => v === b.bytes[i]), `cross-check: ${b.name} -> contrib/${name} (:${dport}) left the bytes alone`);
    }
  }
}

/* ---- cross-check: every benign input through every showcase program ------ */
{
  let n = 0;
  for (const name of SHOWCASE) {
    for (const b of BENIGN) {
      for (const dport of b.dports) {
        const sport = b.sport ?? 51514;
        let frame = b.bytes, payload = 0;
        if (b.proto === 6 && LAYER[name]) {             // give header readers a real header
          const seg = cat(tcpHeader({ sport, dport }), b.bytes);
          frame = LAYER[name] === "ip" ? ipv4({}, seg) : seg;
          payload = LAYER[name] === "ip" ? 40 : 20;
        }
        const buf = Uint8Array.from(frame);
        const r = P(name).exec(buf, { ...fresh(), proto: b.proto, dport, sport, src: "192.0.2.10", payload });
        const same = buf.length === frame.length && buf.every((v, i) => v === frame[i]);
        ok(r.verdict === "pass", `cross-check: ${b.name} -> examples/${name} (:${dport})`, `got ${r.verdict}(${r.ruleName})`);
        ok(same, `cross-check: ${b.name} -> examples/${name} (:${dport}) left the bytes alone`);
        n++;
      }
    }
  }
  console.log(`cross-check: ${BENIGN.length} benign inputs x ${SHOWCASE.length} showcase programs = ${n} runs`);
}

/* ---- the showcase must be fully covered ---------------------------------- */
for (const name of SHOWCASE) {
  const c = covered.get(name) ?? { positive: 0, benign: 0 };
  ok(c.positive > 0, `coverage: examples/${name} has a positive case`);
  ok(c.benign > 0, `coverage: examples/${name} has a benign case`);
}
void LIMITS;

console.log(failed ? `${failed} failed, ${passed} passed` : `${passed}/${passed} behaviour checks passed (${SHOWCASE.length} showcase programs)`);
process.exit(failed ? 1 : 0);
