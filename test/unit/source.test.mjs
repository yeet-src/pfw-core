/* Per-SOURCE state: `src.state`, `src.count`, `src.rate(r, b)` and the source
 * ban. They are the per-flow members scoped to the source address (the kernel's
 * `sources` map), so they survive a reconnect from a new port — which is what a
 * ban, a per-source strike count or a SYN-flood limiter actually need. The
 * reference interpreter models the map as a `source` object the caller threads
 * across packets, the same way `flow` models a connection. */
import { load } from "#/index.js";
import { compile } from "#/clang";
import { assemble } from "#/asm";
import { OP } from "#/isa.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const S = 1_000_000_000n;

yeet.test("src.* lower to the flow ops with the source scope set", () => {
  const c = compile(`filter { if (src.count > 2) decide drop("a"); if (src.state == 1) decide drop("b"); if (src.rate(5, 9)) decide drop("c"); src.state = 7 for 300; decide pass; }`);
  if (!c.ok) throw new Error(JSON.stringify(c.errors));
  const find = (code) => c.program.ops.find((o) => o.code === code);
  eq(find(OP.BUMP).reg, 1, "bump scope");
  eq(find(OP.SLOAD).reg, 1, "sload scope");
  eq(find(OP.RATE).reg, 1, "rate scope");
  const st = find(OP.SSTORE);
  eq(Number(st.imm & 0xffffffffn), 7, "sstore state"); eq(Number((st.imm >> 32n) & 1n), 1, "sstore scope"); eq(st.reg, 300, "sstore ttl");
});

yeet.test("the flow forms keep scope 0", () => {
  const c = compile(`filter { if (flow.count > 2) decide drop("a"); if (rate(5, 9)) decide drop("c"); flow.state = 7 for 300; decide pass; }`);
  const find = (code) => c.program.ops.find((o) => o.code === code);
  eq(find(OP.BUMP).reg, 0, "bump"); eq(find(OP.RATE).reg, 0, "rate"); eq(Number((find(OP.SSTORE).imm >> 32n) & 1n), 0, "sstore");
});

yeet.test("the assembler's src* mnemonics set the same scope", () => {
  const a = assemble(`        srcbump %cur\n        srcload %cur\n        srcstore $3, $60\n        srcrate $5, $9\n        pass`);
  if (!a.ok) throw new Error(JSON.stringify(a.errors));
  const [bump, sload, sstore, rate] = a.program.ops;
  eq(bump.reg, 1, "srcbump"); eq(sload.reg, 1, "srcload"); eq(rate.reg, 1, "srcrate");
  eq(Number((sstore.imm >> 32n) & 1n), 1, "srcstore scope"); eq(sstore.reg, 60, "srcstore ttl");
});

yeet.test("src.count survives a new connection; flow.count does not", () => {
  const perSrc = load(`filter { if (src.count >= 3) decide drop("src_strikes"); decide pass; }`);
  const perFlow = load(`filter { if (flow.count >= 3) decide drop("flow_strikes"); decide pass; }`);
  let source = {};
  const verdicts = [];
  for (let i = 0; i < 4; i++) {
    const r = perSrc.exec(enc("x"), { source, flow: {}, sport: 40000 + i }); // a fresh flow every time
    source = r.source; verdicts.push(r.verdict);
  }
  eq(verdicts.join(","), "pass,pass,drop,drop", "per-source strikes across fresh flows");
  const flowVerdicts = [];
  for (let i = 0; i < 4; i++) flowVerdicts.push(perFlow.exec(enc("x"), { flow: {} }).verdict);
  eq(flowVerdicts.join(","), "pass,pass,pass,pass", "per-flow strikes reset with the flow");
});

yeet.test("src.state is written for the NEXT packet and read on any connection", () => {
  const p = load(`pattern bad = "attack"; filter { if (src.state == 1) decide drop("flagged"); if (scan(payload, 64) & bad) src.state = 1 for 60; decide pass; }`);
  let r = p.exec(enc("an attack"), { source: {} });
  eq(r.verdict, "pass", "the packet that sets the state still passes (deferred write)");
  r = p.exec(enc("hello"), { source: r.source, flow: {}, sport: 5 });
  eq(r.verdict, "drop", "a clean packet on a new connection from the flagged source");
  eq(p.exec(enc("hello"), { source: {} }).verdict, "pass", "another source is unaffected");
});

yeet.test("src.rate is one bucket per source, shared by all its connections", () => {
  const p = load(`filter { if (src.rate(1, 2)) decide drop("src_rl"); decide pass; }`);
  const source = {};
  const hit = (now, sport) => p.exec(enc("x"), { source, flow: {}, sport, now }).verdict;
  eq(hit(0n, 1), "pass", "burst 1"); eq(hit(0n, 2), "pass", "burst 2 (another connection)");
  eq(hit(0n, 3), "drop", "third connection: the source's bucket is empty");
  eq(hit(2n * S, 4), "pass", "refilled after 2s");
});

yeet.test("ban is a SOURCE ban: later packets on any connection are dropped unseen", () => {
  const p = load(`pattern bad = "sqlmap"; filter { if (scan(payload, 64) & bad) decide ban("scanner", 600); decide pass; }`);
  let r = p.exec(enc("User-Agent: sqlmap"), { source: {} });
  eq(r.verdict, "ban", "the offending packet"); eq(r.source.banned, true, "the source is marked");
  r = p.exec(enc("a perfectly clean request"), { source: r.source, flow: {}, sport: 51000 });
  eq(r.verdict, "drop", "a clean packet from the banned source, new port"); eq(r.banned, true, "dropped by the standing ban");
  eq(p.exec(enc("a perfectly clean request"), { source: {} }).verdict, "pass", "another source passes");
});

yeet.test("shadow mode never plants a source ban", () => {
  const p = load(`pattern bad = "sqlmap"; filter { if (scan(payload, 64) & bad) decide ban("scanner", 600); decide pass; }`);
  const r = p.exec(enc("sqlmap"), { source: {}, shadow: true });
  eq(r.verdict, "pass", "shadowed"); eq(r.would, "ban", "would-be verdict"); eq(r.source.banned, false, "no ban planted");
});
