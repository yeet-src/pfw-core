/* Per-connection numbers the program controls — flow.r0..r3 — and the two the
 * kernel counts for it: flow.bytes and flow.packets. flow.state is one small
 * value and flow.count only counts its own reads; these are what an upload cap,
 * a slow-sender check or a "third request on this connection" rule needs. */
import { load } from "#/index.js";
import { compile } from "#/clang";

const eq = (g, w, m) => { if (JSON.stringify(g) !== JSON.stringify(w)) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };
/* Run `packets` (payload sizes, or { len, ...opts }) through one connection. */
const stream = (p, packets) => {
  let flow = {};
  return packets.map((pk) => {
    const { len, ...opts } = typeof pk === "number" ? { len: pk } : pk;
    const r = p.exec(new Uint8Array(len), { ...opts, flow });
    flow = r.flow;
    return r.verdict === "pass" ? "pass" : `${r.verdict}:${r.ruleName}`;
  });
};

yeet.test("a register is any value, kept for the connection", () => {
  const p = load(`filter { flow.r0 = flow.r0 + len; if (flow.r0 > 100) decide drop("too_much"); decide pass; }`);
  eq(stream(p, [40, 40, 40, 5]), ["pass", "pass", "drop:too_much", "drop:too_much"], "a running total the program keeps");
});

yeet.test("a write is seen by a read later in the same packet (flow.state's is not)", () => {
  const p = load(`filter { flow.r1 = 7; if (flow.r1 != 7) decide drop("stale"); flow.state = 7; if (flow.state == 7) decide drop("state_was_immediate"); decide pass; }`);
  eq(stream(p, [1]), ["pass"], "r1 reads back at once; the state does not");
});

yeet.test("four registers, independent", () => {
  const p = load(`filter { flow.r0 = 1; flow.r1 = 2; flow.r2 = 3; flow.r3 = 4; let s = flow.r0 + flow.r1 * 10 + flow.r2 * 100 + flow.r3 * 1000; if (s == 4321) decide drop("y"); decide pass; }`);
  eq(stream(p, [1]), ["drop:y"], "each holds its own");
  eq(compile(`filter { flow.r4 = 1; decide pass; }`).ok, false, "there is no r4");
});

yeet.test("flow.bytes: an upload cap without the program adding anything up", () => {
  const p = load(`filter { if (flow.bytes > 1000) decide rst("upload_cap", 0); decide pass; }`);
  eq(stream(p, [400, 400, 200, 1, 500]), ["pass", "pass", "pass", "rst:upload_cap", "rst:upload_cap"], "1000 bytes pass, the 1001st does not");
});

yeet.test("flow.packets counts every packet, flow.count only its own reads", () => {
  // flow.count is read on data packets only; flow.packets saw the empty ones too.
  const p = load(`filter { if (len == 0) decide pass; emit("n", flow.packets, flow.count); decide pass; }`);
  let flow = {}; const seen = [];
  for (const len of [0, 0, 10, 0, 10]) { const r = p.exec(new Uint8Array(len), { flow }); flow = r.flow; for (const e of r.events) seen.push(e.values.map(Number)); }
  eq(seen, [[3, 1], [5, 2]], "packets 3 and 5 of the connection; the first and second read of the count");
});

yeet.test("slowloris: many packets, few bytes", () => {
  const p = load(`filter { if (flow.packets > 4) { let floor = flow.packets * 8; if (flow.bytes < floor) decide rst("slow_sender", 0); } decide pass; }`);
  eq(stream(p, [2, 2, 2, 2, 2]).at(-1), "rst:slow_sender", "five packets, ten bytes");
  eq(stream(p, [200, 2, 2, 2, 2]).at(-1), "pass", "a real request followed by small packets");
});

yeet.test("the third request on a connection, counted by the program", () => {
  const p = load(`pattern get = "GET "; filter { if (starts(payload, get)) { flow.r0 = flow.r0 + 1; if (flow.r0 >= 3) decide rst("too_many_requests", 0); } decide pass; }`);
  const req = (text) => Uint8Array.from(text, (ch) => ch.charCodeAt(0));
  let flow = {}; const out = [];
  for (const body of ["GET /a", "body bytes", "GET /b", "GET /c"]) { const r = p.exec(req(body), { flow }); flow = r.flow; out.push(r.verdict); }
  eq(out, ["pass", "pass", "pass", "rst"], "two requests pass, the third is reset");
});

yeet.test("the counts are read-only, and src has no registers", () => {
  eq(compile(`filter { flow.bytes = 0; decide pass; }`).ok, false, "flow.bytes is the kernel's to count");
  eq(compile(`filter { src.r0 = 1; decide pass; }`).ok, false, "registers are per connection");
});
