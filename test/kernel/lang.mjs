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
 * model decoding.
 *
 * The VM is loaded once, with every case's program in it at the same time, each
 * routed the packets to a port of its own: loading is most of what a kernel test
 * waits for, and there are twenty programs here. Needs yeetd + loopback;
 * `npm run test:lang` (node). */
import net from "node:net";
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { load } from "#/index.js";
import { codes } from "#/huffman";

const ROOT = new URL("../..", import.meta.url).pathname;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const PORT = 59731;

/* Every case, in the order declared: its title, the route its program is on
 * ("udp/59731"), the program, its argv, and what to send and check once the
 * loader holds them all. */
const cases = [];
const knobs = [];
function add(proto, title, sourceOf, run, argv = []) {
  const port = PORT + cases.length;
  cases.push({ title, route: `${proto}/${port}`, source: sourceOf(port), argv, run: () => run(port) });
  return port;
}
const guard = (port) => `if (proto != 17) decide pass; if (dport != ${port}) decide pass;`;

async function withPrograms(fn) {
  const args = ["--routes", cases.map((c) => `${c.route}=${hex(c.source)}`).join(",")];
  const rargv = cases.filter((c) => c.argv.length).map((c) => `${c.route}=${c.argv.join("+")}`);
  if (rargv.length) args.push("--rargv", rargv.join(","));
  if (knobs.length) args.push("--knobs", knobs.join(","));
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--iface", "1", "--hold", "600", ...args], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY|COMPILE FAIL|failed/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out.slice(-2000)); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(500); }
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

/* A UDP flow: one socket, so every datagram shares a 5-tuple. */
function udpFlow(port) {
  const c = dgram.createSocket("udp4");
  const ready = new Promise((r) => c.bind(0, "127.0.0.1", r));
  return {
    send: async (msg) => { await ready; await new Promise((r) => c.send(Buffer.from(msg, "latin1"), port, "127.0.0.1", r)); await sleep(40); },
    close: () => c.close(),
  };
}

/* A program of its own on a UDP port of its own; the case is handed a fresh
 * server log and a flow factory. `sourceOf(port)` is the program. */
function udpCase(title, sourceOf, fn, argv = []) {
  return add("udp", title, sourceOf, async (port) => {
    const got = [];
    const srv = dgram.createSocket("udp4");
    srv.on("message", (m) => got.push(m.toString("latin1")));
    await new Promise((r) => srv.bind(port, "127.0.0.1", r));
    const flows = [];
    const flow = () => { const f = udpFlow(port); flows.push(f); return f; };
    try { await fn(got, flow); } finally { for (const f of flows) f.close(); srv.close(); }
  }, argv);
}

/* The stateless cases: send each payload on its own flow; `want` says which the
 * kernel must drop. The reference interpreter must agree on every one. */
function stateless(title, sourceOf, sends, { argv = [] } = {}) {
  let ref;
  const port = udpCase(title, sourceOf, async (got, flow) => {
    for (const [, payload] of sends) { await flow().send(payload); }
    await sleep(300);
    for (const [label, payload, dropped] of sends) {
      const r = ref.exec(Buffer.from(payload, "latin1"), { proto: 17, dport: port, argv }).verdict;
      const k = got.includes(payload) ? "pass" : "drop";
      check(`${label}`, k === (dropped ? "drop" : "pass") && r === k, `reference=${r} kernel=${k}`);
    }
  }, argv);
  ref = load(sourceOf(port));
}

console.log(`kernel language coverage — loopback, from :${PORT}`);

/* ---- per-flow state -------------------------------------------------------- */

udpCase("flow.count", (port) => `filter { ${guard(port)} if (flow.count >= 3) decide drop("strikes"); decide pass; }`, async (got, flow) => {
  const a = flow(), b = flow();
  for (let i = 1; i <= 5; i++) await a.send("a" + i);
  await b.send("b1");
  await sleep(300);
  check("the third packet of a flow is the first dropped", got.filter((g) => g[0] === "a").join(",") === "a1,a2", got.join(","));
  check("another flow has its own count", got.includes("b1"));
});

udpCase("flow.state, with a TTL", (port) => `pattern arm = "ARM"; filter { ${guard(port)} if (flow.state == 1) decide drop("armed"); if (starts(payload, arm)) flow.state = 1 for 2; decide pass; }`, async (got, flow) => {
  const a = flow(), b = flow();
  await a.send("ARM"); await a.send("after-arm"); await b.send("other-flow");
  await sleep(300);
  check("the packet that sets the state is itself unaffected (deferred write)", got.includes("ARM"));
  check("the next packet on the flow sees the state", !got.includes("after-arm"), got.join(","));
  check("another flow does not", got.includes("other-flow"));
  await sleep(2400); await a.send("after-ttl"); await sleep(300);
  check("the state expires after its TTL", got.includes("after-ttl"), got.join(","));
});

udpCase("ring.push / ring.len / ring.get", (port) => `filter { ${guard(port)} ring.push(len); if (ring.len >= 2) { let prev = ring.get(1); if (prev == 5) decide drop("after_a_5"); } decide pass; }`, async (got, flow) => {
  const a = flow();
  await a.send("warmup"); await a.send("12345"); await a.send("x"); await a.send("yy"); await a.send("zzz");
  await sleep(300);
  check("the packet after a 5-byte one is dropped (ring.get(1) is the previous length)", !got.includes("x"), got.join(","));
  check("the 5-byte packet itself and the ones after pass", ["12345", "yy", "zzz"].every((m) => got.includes(m)), got.join(","));
});

udpCase("ring.len saturation across a flow", (port) => `filter { ${guard(port)} ring.push(len); if (ring.len >= 4) decide drop("fourth"); decide pass; }`, async (got, flow) => {
  const a = flow(), b = flow();
  for (let i = 1; i <= 6; i++) await a.send("r" + i);
  await b.send("fresh");
  await sleep(300);
  const passed = got.filter((g) => g[0] === "r").length;
  check("the ring fills as the flow sends, then the rule fires and keeps firing", passed >= 3 && passed <= 4 && !got.includes("r6"), got.join(","));
  check("a new flow starts with an empty ring", got.includes("fresh"));
});

/* ---- scan queries, cursor parsing, control flow ---------------------------- */

stateless("seq", (port) => `pattern u = "UNION"; pattern s = "SELECT"; filter { ${guard(port)} mask m = scan(payload, 256); if (seq(m, u, s)) decide drop("sqli"); decide pass; }`, [
  ["in order -> drop", "1 UNION SELECT x", true],
  ["reversed -> pass", "1 SELECT x UNION", false],
  ["one missing -> pass", "1 UNION x", false],
]);

stateless("within", (port) => `pattern bad = "BAD"; filter { ${guard(port)} mask all = scan(payload, 64); if (within(payload, 4) & bad) decide drop("at_start"); decide pass; }`, [
  ["inside the window -> drop", "BAD then more", true],
  ["seen by the earlier scan but outside the window -> pass", "xxxxxxxx BAD", false],
]);

stateless("byte-list patterns", (port) => `pattern java = { 0xac, 0xed, 0x00, 0x05 }; filter { ${guard(port)} if (scan(payload, 64) & java) decide drop("java_ser"); decide pass; }`, [
  ["the magic bytes -> drop", "xx\xac\xed\x00\x05yy", true],
  ["one byte off -> pass", "xx\xac\xed\x00\x06yy", false],
]);

stateless("skip", (port) => `pattern admin = "/admin"; filter { ${guard(port)} ptr path = find(payload, ' ', 16); skip(path, ' '); if (starts(path, admin)) decide drop("admin"); decide pass; }`, [
  ["a run of spaces is skipped -> drop", "GET    /admin", true],
  ["a single space -> drop", "GET /admin", true],
  ["another path -> pass", "GET   /public", false],
]);

stateless("the frame walker", (port) => `pattern bot = "BOT"; filter { ${guard(port)} frame (len = u8 @ 0, type = u8 @ 1, head = 2) up to 4 { if (frame.type == 7) { if (within(frame.data, 16) & bot) decide drop("typed_bot"); } } decide pass; }`, [
  ["a type-7 record holding the pattern -> drop", "\x02\x01hi\x03\x07BOT", true],
  ["the pattern in a record of another type -> pass", "\x03\x01BOT\x02\x07hi", false],
  ["the pattern outside the type-7 record's length -> pass", "\x01\x07x\x03\x01BOT", false],
]);

stateless("switch with fall-through", (port) => `filter { ${guard(port)} switch (len) { case 1: case 2: decide drop("short"); case 3: break; default: decide drop("long"); } decide pass; }`, [
  ["case 1 falls into case 2 -> drop", "a", true],
  ["case 2 -> drop", "ab", true],
  ["case 3 breaks out -> pass", "abc", false],
  ["default -> drop", "abcd", true],
]);

stateless("macro", (port) => `pattern bad = "BAD"; macro guard { ${guard(port)} } macro block_bad { if (scan(payload, 64) & bad) decide drop("bad"); } filter { guard; block_bad; decide pass; }`, [
  ["the expanded body runs -> drop", "a BAD one", true],
  ["and falls through -> pass", "a good one", false],
]);

stateless("decide count is not terminal", (port) => `pattern bad = "BAD"; filter { ${guard(port)} decide count("seen"); count("again"); if (starts(payload, bad)) decide drop("bad"); decide pass; }`, [
  ["execution continues past it -> drop", "BAD", true],
  ["and to the end -> pass", "fine", false],
]);

/* ---- host parameters ------------------------------------------------------- */

stateless("argc", (port) => `filter { ${guard(port)} if (argc == 2) decide drop("two_args"); decide pass; }`,
  [["two args set -> drop", "x", true]], { argv: [7, 9] });
stateless("argc, none set", (port) => `filter { ${guard(port)} if (argc == 0) decide pass; decide drop("has_args"); }`,
  [["no args -> pass", "x", false]]);

/* A knob struct's fields are ordinary live knobs: the default is seeded by the
 * loader, and the host can set the field by its dotted name. Knobs are shared by
 * name between the programs the loader holds, so the two cases name theirs apart. */
const KNOBS = (name) => (port) => `knob struct ${name} { cap ?? 3, mode }; filter { ${guard(port)} if (len > ${name}.cap) decide drop("over_cap"); decide pass; }`;
udpCase("knob struct: the seeded default", KNOBS("cfg"), async (got, flow) => {
  await flow().send("abcd"); await flow().send("ab"); await sleep(300);
  check("over the default cap (3) -> drop", !got.includes("abcd"), got.join(","));
  check("under it -> pass", got.includes("ab"));
});
knobs.push("host.cap=10");
udpCase("knob struct: a host-set field", KNOBS("host"), async (got, flow) => {
  await flow().send("abcd"); await flow().send("abcdefghijkl"); await sleep(300);
  check("under the host's cap (10) -> pass", got.includes("abcd"), got.join(","));
  check("over it -> drop", !got.includes("abcdefghijkl"));
});

/* ---- registers ------------------------------------------------------------- */

/* The IPv4 version/IHL byte, read through `frame at (l3)`: 0x45 on loopback. The
 * host model has no L3 header, so there is no reference verdict for this one. */
for (const [op, dropped] of [["==", true], ["!=", false]]) {
  udpCase(`frame at (l3): version/IHL ${op} 0x45`, (port) => `filter { ${guard(port)} let vihl = 0; frame at (l3) (len = u8 @ 0, head = 20) up to 1 { vihl = frame.len; } if (vihl ${op} 0x45) decide drop("v4_ihl5"); decide pass; }`, async (got, flow) => {
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

/* A decoded program on a TCP port of its own: one connection per send, and
 * whether the server received it. */
function tcpCase(title, decl, sends) {
  const sourceOf = (port) => `decode ${decl} ${port}; pattern bot = "GPTBot"; filter { if (dport != ${port}) decide pass; if (scan(payload, 4096) & bot) decide drop("bot"); decide pass; }`;
  add("tcp", title, sourceOf, async (port) => {
    const seen = [];
    const srv = net.createServer((s) => { const i = seen.push(Buffer.alloc(0)) - 1; s.on("data", (d) => { seen[i] = Buffer.concat([seen[i], d]); }); s.on("error", () => {}); });
    await new Promise((r) => srv.listen(port, "127.0.0.1", r));
    try {
      for (const [label, wire, dropped] of sends) {
        const before = seen.length;
        await new Promise((resolve) => {
          const s = net.connect({ port, host: "127.0.0.1", noDelay: true });
          const done = () => { try { s.destroy(); } catch {} resolve(); };
          s.setTimeout(1500, done);
          s.on("connect", () => { s.write(wire); setTimeout(done, 500); });
          s.on("error", done);
        });
        await sleep(200);
        const arrived = seen.slice(before).some((b) => b.equals(Buffer.from(wire)));
        check(label, arrived === !dropped, arrived ? "delivered" : "not delivered");
      }
    } finally { srv.close(); }
  });
}

tcpCase("decode <table> (rot13)", "rot13", [
  ["the pattern, rot13-encoded on the wire -> dropped", Buffer.from(rot13("hello GPTBot here")), true],
  ["clean text, encoded -> delivered", Buffer.from(rot13("hello nobody here")), false],
  ["the pattern in the clear decodes to something else -> delivered", Buffer.from("hello GPTBot here"), false],
]);

tcpCase("decode huffman", "huffman", [
  ["the pattern, HPACK-Huffman-coded on the wire -> dropped", huffEncode("hello GPTBot here"), true],
  ["clean text, coded -> delivered", huffEncode("hello nobody here"), false],
]);

await withPrograms(async () => {
  for (const c of cases) { console.log(`\n${c.title}`); await c.run(); }
});

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
