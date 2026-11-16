/* Kernel language-coverage test: the pfw-C features that had only ever run on
 * the host interpreter, on live loopback traffic against the real VM.
 *
 *   per-flow state     ring.push / ring.get / ring.len, flow.count, flow.state (+ TTL)
 *   scan queries       seq, within, byte-list patterns
 *   cursor parsing     skip, the frame walker, `frame at (l3)`
 *   control / structure switch (with fall-through), macro, decide count
 *   host parameters    argc, knob struct (seeded default and host-set field)
 *   stream decoders    decode <table> (rot13), decode huffman
 *
 * The stateless and per-flow cases use UDP: one datagram is one packet, a socket
 * is one flow, and the verdict is read from what the server receives (a dropped
 * datagram never arrives). The decoders need a TCP stream. Each case is checked
 * against the reference interpreter where it models the feature; it does not
 * model decoding. Needs yeetd + loopback; `npm run test:lang` (node). */
import net from "node:net";
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { load } from "#/index.js";
import { codes } from "#/huffman";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const PORT = 59731;
const GUARD = `if (proto != 17) decide pass; if (dport != ${PORT}) decide pass;`;

async function withProgram(source, args, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "40", ...args], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 150 && !/READY|COMPILE FAIL/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out.slice(-2000)); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(500); }
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

/* A UDP flow: one socket, so every datagram shares a 5-tuple. */
function udpFlow() {
  const c = dgram.createSocket("udp4");
  const ready = new Promise((r) => c.bind(0, "127.0.0.1", r));
  return {
    send: async (msg) => { await ready; await new Promise((r) => c.send(Buffer.from(msg, "latin1"), PORT, "127.0.0.1", r)); await sleep(40); },
    close: () => c.close(),
  };
}

/* Run `source`, hand the case a fresh server log and a flow factory. */
async function udpCase(title, source, fn, args = []) {
  console.log(`\n${title}`);
  const got = [];
  const srv = dgram.createSocket("udp4");
  srv.on("message", (m) => got.push(m.toString("latin1")));
  await new Promise((r) => srv.bind(PORT, "127.0.0.1", r));
  const flows = [];
  const flow = () => { const f = udpFlow(); flows.push(f); return f; };
  try { await withProgram(source, args, async () => { await fn(got, flow); }); }
  finally { for (const f of flows) f.close(); srv.close(); }
}

/* The stateless cases: send each payload on its own flow; `want` says which the
 * kernel must drop. The reference interpreter must agree on every one. */
async function stateless(title, source, cases, { args = [], opts = {} } = {}) {
  const ref = load(source);
  await udpCase(title, source, async (got, flow) => {
    for (const [label, payload] of cases) { await flow().send(payload); }
    await sleep(300);
    for (const [label, payload, dropped] of cases) {
      const r = ref.exec(Buffer.from(payload, "latin1"), { proto: 17, dport: PORT, ...opts }).verdict;
      const k = got.includes(payload) ? "pass" : "drop";
      check(`${label}`, k === (dropped ? "drop" : "pass") && r === k, `reference=${r} kernel=${k}`);
    }
  }, args);
}

console.log(`kernel language coverage — loopback :${PORT}`);

/* ---- per-flow state -------------------------------------------------------- */

await udpCase("flow.count", `filter { ${GUARD} if (flow.count >= 3) decide drop("strikes"); decide pass; }`, async (got, flow) => {
  const a = flow(), b = flow();
  for (let i = 1; i <= 5; i++) await a.send("a" + i);
  await b.send("b1");
  await sleep(300);
  check("the third packet of a flow is the first dropped", got.filter((g) => g[0] === "a").join(",") === "a1,a2", got.join(","));
  check("another flow has its own count", got.includes("b1"));
});

await udpCase("flow.state, with a TTL", `pattern arm = "ARM"; filter { ${GUARD} if (flow.state == 1) decide drop("armed"); if (starts(payload, arm)) flow.state = 1 for 2; decide pass; }`, async (got, flow) => {
  const a = flow(), b = flow();
  await a.send("ARM"); await a.send("after-arm"); await b.send("other-flow");
  await sleep(300);
  check("the packet that sets the state is itself unaffected (deferred write)", got.includes("ARM"));
  check("the next packet on the flow sees the state", !got.includes("after-arm"), got.join(","));
  check("another flow does not", got.includes("other-flow"));
  await sleep(2400); await a.send("after-ttl"); await sleep(300);
  check("the state expires after its TTL", got.includes("after-ttl"), got.join(","));
});

await udpCase("ring.push / ring.len / ring.get", `filter { ${GUARD} ring.push(len); if (ring.len >= 2) { let prev = ring.get(1); if (prev == 5) decide drop("after_a_5"); } decide pass; }`, async (got, flow) => {
  const a = flow();
  await a.send("warmup"); await a.send("12345"); await a.send("x"); await a.send("yy"); await a.send("zzz");
  await sleep(300);
  check("the packet after a 5-byte one is dropped (ring.get(1) is the previous length)", !got.includes("x"), got.join(","));
  check("the 5-byte packet itself and the ones after pass", ["12345", "yy", "zzz"].every((m) => got.includes(m)), got.join(","));
});

await udpCase("ring.len saturation across a flow", `filter { ${GUARD} ring.push(len); if (ring.len >= 4) decide drop("fourth"); decide pass; }`, async (got, flow) => {
  const a = flow(), b = flow();
  for (let i = 1; i <= 6; i++) await a.send("r" + i);
  await b.send("fresh");
  await sleep(300);
  const passed = got.filter((g) => g[0] === "r").length;
  check("the ring fills as the flow sends, then the rule fires and keeps firing", passed >= 3 && passed <= 4 && !got.includes("r6"), got.join(","));
  check("a new flow starts with an empty ring", got.includes("fresh"));
});

/* ---- scan queries, cursor parsing, control flow ---------------------------- */

await stateless("seq", `pattern u = "UNION"; pattern s = "SELECT"; filter { ${GUARD} mask m = scan(payload, 256); if (seq(m, u, s)) decide drop("sqli"); decide pass; }`, [
  ["in order -> drop", "1 UNION SELECT x", true],
  ["reversed -> pass", "1 SELECT x UNION", false],
  ["one missing -> pass", "1 UNION x", false],
]);

await stateless("within", `pattern bad = "BAD"; filter { ${GUARD} mask all = scan(payload, 64); if (within(payload, 4) & bad) decide drop("at_start"); decide pass; }`, [
  ["inside the window -> drop", "BAD then more", true],
  ["seen by the earlier scan but outside the window -> pass", "xxxxxxxx BAD", false],
]);

await stateless("byte-list patterns", `pattern java = { 0xac, 0xed, 0x00, 0x05 }; filter { ${GUARD} if (scan(payload, 64) & java) decide drop("java_ser"); decide pass; }`, [
  ["the magic bytes -> drop", "xx\xac\xed\x00\x05yy", true],
  ["one byte off -> pass", "xx\xac\xed\x00\x06yy", false],
]);

await stateless("skip", `pattern admin = "/admin"; filter { ${GUARD} ptr path = find(payload, ' ', 16); skip(path, ' '); if (starts(path, admin)) decide drop("admin"); decide pass; }`, [
  ["a run of spaces is skipped -> drop", "GET    /admin", true],
  ["a single space -> drop", "GET /admin", true],
  ["another path -> pass", "GET   /public", false],
]);

await stateless("the frame walker", `pattern bot = "BOT"; filter { ${GUARD} frame (len = u8 @ 0, type = u8 @ 1, head = 2) up to 4 { if (frame.type == 7) { if (within(frame.data, 16) & bot) decide drop("typed_bot"); } } decide pass; }`, [
  ["a type-7 record holding the pattern -> drop", "\x02\x01hi\x03\x07BOT", true],
  ["the pattern in a record of another type -> pass", "\x03\x01BOT\x02\x07hi", false],
  ["the pattern outside the type-7 record's length -> pass", "\x01\x07x\x03\x01BOT", false],
]);

await stateless("switch with fall-through", `filter { ${GUARD} switch (len) { case 1: case 2: decide drop("short"); case 3: break; default: decide drop("long"); } decide pass; }`, [
  ["case 1 falls into case 2 -> drop", "a", true],
  ["case 2 -> drop", "ab", true],
  ["case 3 breaks out -> pass", "abc", false],
  ["default -> drop", "abcd", true],
]);

await stateless("macro", `pattern bad = "BAD"; macro guard { ${GUARD} } macro block_bad { if (scan(payload, 64) & bad) decide drop("bad"); } filter { guard; block_bad; decide pass; }`, [
  ["the expanded body runs -> drop", "a BAD one", true],
  ["and falls through -> pass", "a good one", false],
]);

await stateless("decide count is not terminal", `pattern bad = "BAD"; filter { ${GUARD} decide count("seen"); count("again"); if (starts(payload, bad)) decide drop("bad"); decide pass; }`, [
  ["execution continues past it -> drop", "BAD", true],
  ["and to the end -> pass", "fine", false],
]);

/* ---- host parameters ------------------------------------------------------- */

await stateless("argc", `filter { ${GUARD} if (argc == 2) decide drop("two_args"); decide pass; }`,
  [["two args set -> drop", "x", true]], { args: ["--argv", "7,9"], opts: { argv: [7, 9] } });
await stateless("argc, none set", `filter { ${GUARD} if (argc == 0) decide pass; decide drop("has_args"); }`,
  [["no args -> pass", "x", false]]);

/* A knob struct's fields are ordinary live knobs: the default is seeded by the
 * loader, and the host can set the field by its dotted name. */
const KNOBS = `knob struct cfg { cap ?? 3, mode }; filter { ${GUARD} if (len > cfg.cap) decide drop("over_cap"); decide pass; }`;
await udpCase("knob struct: the seeded default", KNOBS, async (got, flow) => {
  await flow().send("abcd"); await flow().send("ab"); await sleep(300);
  check("over the default cap (3) -> drop", !got.includes("abcd"), got.join(","));
  check("under it -> pass", got.includes("ab"));
});
await udpCase("knob struct: a host-set field", KNOBS, async (got, flow) => {
  await flow().send("abcd"); await flow().send("abcdefghijkl"); await sleep(300);
  check("under the host's cap (10) -> pass", got.includes("abcd"), got.join(","));
  check("over it -> drop", !got.includes("abcdefghijkl"));
}, ["--knobs", "cfg.cap=10"]);

/* ---- registers ------------------------------------------------------------- */

/* The IPv4 version/IHL byte, read through `frame at (l3)`: 0x45 on loopback. The
 * host model has no L3 header, so there is no reference verdict for this one. */
for (const [op, dropped] of [["==", true], ["!=", false]]) {
  await udpCase(`frame at (l3): version/IHL ${op} 0x45`, `filter { ${GUARD} let vihl = 0; frame at (l3) (len = u8 @ 0, head = 20) up to 1 { vihl = frame.len; } if (vihl ${op} 0x45) decide drop("v4_ihl5"); decide pass; }`, async (got, flow) => {
    await flow().send("probe"); await sleep(300);
    check(dropped ? "the byte at l3 is 0x45 -> drop" : "…and is not anything else -> pass", got.includes("probe") === !dropped);
  });
}

/* ---- stream decoders (TCP) ------------------------------------------------- */

const rot13 = (s) => s.replace(/[a-z]/gi, (ch) => String.fromCharCode((ch <= "Z" ? 90 : 122) >= ch.charCodeAt(0) + 13 ? ch.charCodeAt(0) + 13 : ch.charCodeAt(0) - 13));
const byId = new Map(codes().map((c) => [c.sym, c]));
function huffEncode(text) {
  let acc = 0n, nbits = 0n;
  const out = [];
  for (const b of Buffer.from(text, "latin1")) {
    const { code, bits } = byId.get(b);
    acc = (acc << BigInt(bits)) | BigInt(code); nbits += BigInt(bits);
    while (nbits >= 8n) { nbits -= 8n; out.push(Number((acc >> nbits) & 0xffn)); }
  }
  if (nbits > 0n) { const pad = 8n - nbits; out.push(Number(((acc << pad) | ((1n << pad) - 1n)) & 0xffn)); }
  return Buffer.from(out);
}

/* One TCP connection sending `bytes`; resolves with what the server received. */
async function tcpCase(title, source, sends) {
  console.log(`\n${title}`);
  const seen = [];
  const srv = net.createServer((s) => { const i = seen.push(Buffer.alloc(0)) - 1; s.on("data", (d) => { seen[i] = Buffer.concat([seen[i], d]); }); s.on("error", () => {}); });
  await new Promise((r) => srv.listen(PORT, "127.0.0.1", r));
  try {
    await withProgram(source, [], async () => {
      for (const [label, wire, dropped] of sends) {
        const before = seen.length;
        await new Promise((resolve) => {
          const s = net.connect({ port: PORT, host: "127.0.0.1", noDelay: true });
          const done = () => { try { s.destroy(); } catch {} resolve(); };
          s.setTimeout(1500, done);
          s.on("connect", () => { s.write(wire); setTimeout(done, 500); });
          s.on("error", done);
        });
        await sleep(200);
        const arrived = seen.slice(before).some((b) => b.equals(Buffer.from(wire)));
        check(label, arrived === !dropped, arrived ? "delivered" : "not delivered");
      }
    });
  } finally { srv.close(); }
}

const DECODED = (decl) => `decode ${decl} ${PORT}; pattern bot = "GPTBot"; filter { if (dport != ${PORT}) decide pass; if (scan(payload, 2048) & bot) decide drop("bot"); decide pass; }`;

await tcpCase("decode <table> (rot13)", DECODED("rot13"), [
  ["the pattern, rot13-encoded on the wire -> dropped", Buffer.from(rot13("hello GPTBot here")), true],
  ["clean text, encoded -> delivered", Buffer.from(rot13("hello nobody here")), false],
  ["the pattern in the clear decodes to something else -> delivered", Buffer.from("hello GPTBot here"), false],
]);

await tcpCase("decode huffman", DECODED("huffman"), [
  ["the pattern, HPACK-Huffman-coded on the wire -> dropped", huffEncode("hello GPTBot here"), true],
  ["clean text, coded -> delivered", huffEncode("hello nobody here"), false],
]);

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
