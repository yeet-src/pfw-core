/* dnat and rate with computed arguments: the target of a steer, or a limit,
 * comes from a knob or a local instead of being written into the program. */
import { load } from "#/index.js";
import { compile } from "#/clang";

const eq = (g, w, m) => { if (JSON.stringify(g) !== JSON.stringify(w)) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };
const frame = new Uint8Array(8);
const ip = (a, b, c, d) => ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;

yeet.test("dnat with both written out is still one instruction, and exec says where it went", () => {
  const p = load(`filter { dnat("10.0.0.5", 8080); decide pass; }`);
  eq(p.exec(frame, {}).dnat, { ip: "10.0.0.5", port: 8080 }, "target");
  eq(p.listing.filter((l) => l.text.startsWith("dnat")).map((l) => l.text), ["dnat 10.0.0.5:8080"], "the constant form");
  eq(load(`filter { decide pass; }`).exec(frame, {}).dnat, null, "no dnat, no target");
});

yeet.test("the port from a knob: one program, the backend port retuned live", () => {
  const p = load(`filter { dnat("127.0.0.1", knob("backend_port") ?? 8182); decide pass; }`);
  eq(p.exec(frame, {}).dnat, { ip: "127.0.0.1", port: 8182 }, "the seeded default");
  eq(p.exec(frame, { knobs: { backend_port: 9000 } }).dnat, { ip: "127.0.0.1", port: 9000 }, "rewritten by the host");
});

yeet.test("the address from a knob, and both from knobs", () => {
  const a = load(`filter { dnat(knob("ip"), 443); decide pass; }`);
  eq(a.exec(frame, { knobs: { ip: ip(192, 168, 1, 9) } }).dnat, { ip: "192.168.1.9", port: 443 }, "address");
  const b = load(`filter { dnat(knob("ip"), knob("port")); decide pass; }`);
  eq(b.exec(frame, { knobs: { ip: ip(10, 1, 2, 3), port: 53 } }).dnat, { ip: "10.1.2.3", port: 53 }, "both");
});

yeet.test("an address of 0 steers nothing: an unset knob is not 0.0.0.0", () => {
  const p = load(`filter { dnat(knob("ip"), 443); decide pass; }`);
  eq(p.exec(frame, {}).dnat, null, "the knob was never set");
  const q = load(`filter { dnat("10.0.0.1", 80); dnat(knob("override"), 81); decide pass; }`);
  eq(q.exec(frame, {}).dnat, { ip: "10.0.0.1", port: 80 }, "the fallback stands");
  eq(q.exec(frame, { knobs: { override: ip(10, 0, 0, 2) } }).dnat, { ip: "10.0.0.2", port: 81 }, "until the override is set");
});

yeet.test("one packed value is a whole target: address low, port above", () => {
  const p = load(`filter { let backend = knob("target"); dnat(backend); decide pass; }`);
  const packed = (BigInt(8443) << 32n) | BigInt(ip(10, 9, 8, 7));
  eq(p.exec(frame, { knobs: { target: packed } }).dnat, { ip: "10.9.8.7", port: 8443 }, "packed");
});

yeet.test("a balancer whose split is arithmetic, not a ladder of ifs", () => {
  // three backends on consecutive ports, chosen by the flow hash
  const p = load(`filter { let n = flow.hash % 3; dnat("127.0.0.1", 8182 + n); decide pass; }`);
  const seen = new Set();
  for (let sport = 40000; sport < 40200; sport++) seen.add(p.exec(frame, { src: "127.0.0.1", dst: "127.0.0.1", sport, dport: 8181 }).dnat.port);
  eq([...seen].sort(), [8182, 8183, 8184], "all three, and only those");
  const one = p.exec(frame, { src: "127.0.0.1", dst: "127.0.0.1", sport: 40000, dport: 8181 }).dnat.port;
  eq(p.exec(frame, { src: "127.0.0.1", dst: "127.0.0.1", sport: 40000, dport: 8181 }).dnat.port, one, "a connection keeps its backend");
});

yeet.test("rate from knobs: the limit moves without a reload", () => {
  const p = load(`filter { if (rate(knob("per_sec") ?? 1, knob("burst") ?? 2)) decide drop("over"); decide pass; }`);
  const run = (knobs, n) => { const bucket = {}; const out = []; for (let i = 0; i < n; i++) out.push(p.exec(frame, { knobs, bucket, now: 1_000_000_000n }).verdict); return out.filter((v) => v === "pass").length; };
  eq(run({}, 6), 2, "the default burst of 2");
  eq(run({ burst: 5 }, 8), 5, "the host raises the burst");
  eq(run({ burst: 0 }, 3), 0, "a burst of 0 lets nothing through");
});

yeet.test("rate with one constant and one computed argument", () => {
  const p = load(`filter { let b = len + 1; if (rate(1, b)) decide drop("over"); decide pass; }`);
  const bucket = {};
  const verdicts = Array.from({ length: 5 }, () => p.exec(new Uint8Array(2), { bucket, now: 1_000_000_000n }).verdict);
  eq(verdicts.filter((v) => v === "pass").length, 3, "burst = len + 1 = 3");
});

yeet.test("src.rate takes computed arguments too", () => {
  const p = load(`filter { if (src.rate(knob("r") ?? 1, knob("b") ?? 2)) decide drop("over"); decide pass; }`);
  let source = {};
  const out = [];
  for (let i = 0; i < 4; i++) { const r = p.exec(frame, { source, now: 1_000_000_000n }); source = r.source; out.push(r.verdict); }
  eq(out, ["pass", "pass", "drop", "drop"], "the source's bucket");
});

yeet.test("literal arguments are still checked at compile time", () => {
  eq(compile(`filter { if (rate(0, 5)) decide drop("x"); decide pass; }`).ok, false, "a written-out rate of 0");
  eq(compile(`filter { dnat("10.0.0.1", 70000); decide pass; }`).ok, false, "a written-out port over 65535");
  eq(compile(`filter { dnat("10.0.0", 80); decide pass; }`).ok, false, "a bad address");
  eq(compile(`filter { dnat(); decide pass; }`).ok, false, "no arguments");
});
