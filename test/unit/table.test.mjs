/* Lookup tables — `table NAME[SIZE];` declares one, `NAME[i]` reads a cell, and
 * the host fills it. The decision a program makes can then be data: a backend
 * per slot, a policy per port, rewritten without touching the program. */
import { load, flowHash } from "#/index.js";
import { compile } from "#/clang";
import { LIMITS } from "#/isa.js";

const eq = (g, w, m) => { if (JSON.stringify(g) !== JSON.stringify(w)) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };
const frame = new Uint8Array(8);
const ip = (a, b, c, d) => ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
const target = (addr, port) => (BigInt(port) << 32n) | BigInt(addr);

yeet.test("a cell reads what the host put there", () => {
  const p = load(`table policy[8]; filter { if (policy[dport & 7] == 1) decide drop("blocked"); decide pass; }`);
  eq(p.lookupTables, [{ name: "policy", base: 0, size: 8 }], "the program says what it declares");
  const tables = { policy: [0, 0, 1, 0, 0, 0, 0, 1] };
  eq(p.exec(frame, { dport: 2, tables }).verdict, "drop", "cell 2");
  eq(p.exec(frame, { dport: 3, tables }).verdict, "pass", "cell 3");
  eq(p.exec(frame, { dport: 7, tables }).verdict, "drop", "cell 7");
  eq(p.exec(frame, { dport: 2 }).verdict, "pass", "an unfilled table is all zeros");
});

yeet.test("an index past the end reads 0, never a neighbour's cell", () => {
  const p = load(`table a[2]; table b[2]; filter { if (a[len] == 9) decide drop("leak"); if (b[0] == 9) decide drop("b0"); decide pass; }`);
  const tables = { a: [1, 2], b: [9, 9] };
  eq(p.lookupTables.map((t) => t.base), [0, 2], "laid out one after another");
  eq(p.exec(new Uint8Array(2), { tables }).verdict, "drop", "a[2] is past a, so 0; b[0] is 9");
  eq(p.exec(new Uint8Array(2), { tables }).ruleName, "b0", "and it was b's own read that matched");
});

yeet.test("a balancer that is a table: the backend in each slot, and dnat takes the cell", () => {
  const p = load(`table backends[251]; filter { if (dport != 8181) decide pass; dnat(backends[flow.hash % 251]); decide pass; }`);
  const pool = [target(ip(127, 0, 0, 1), 8182), target(ip(127, 0, 0, 1), 8183), target(ip(127, 0, 0, 1), 8184)];
  const backends = Array.from({ length: 251 }, (_, slot) => pool[slot % 3]);
  const tuple = (sport) => ({ src: "127.0.0.1", dst: "127.0.0.1", sport, dport: 8181 });
  const seen = new Map();
  for (let sport = 40000; sport < 40300; sport++) {
    const got = p.exec(frame, { ...tuple(sport), tables: { backends } }).dnat;
    // The host indexes its own table with the same hash the program used.
    const slot = flowHash({ saddr: ip(127, 0, 0, 1), daddr: ip(127, 0, 0, 1), sport, dport: 8181, proto: 6 }) % 251;
    eq(got.port, Number(backends[slot] >> 32n), `sport ${sport} goes where the host's table says`);
    seen.set(got.port, (seen.get(got.port) ?? 0) + 1);
  }
  eq([...seen.keys()].sort(), [8182, 8183, 8184], "all three backends are used");
  // Take a backend out by rewriting its slots: no new program.
  const drained = backends.map((cell) => (cell === pool[1] ? pool[0] : cell));
  for (let sport = 40000; sport < 40100; sport++) if (p.exec(frame, { ...tuple(sport), tables: { backends: drained } }).dnat.port === 8183) throw new Error("a drained backend was chosen");
  eq(p.exec(frame, tuple(40000)).dnat, null, "an empty table steers nothing");
});

yeet.test("a full-size Maglev table fits, with room for another beside it", () => {
  const c = compile(`table maglev[65537]; table weights[64]; filter { dnat(maglev[flow.hash % 65537]); if (weights[0] == 0) decide pass; decide pass; }`);
  eq(c.ok, true, JSON.stringify(c.errors));
  eq(c.lookupTables.map((t) => [t.name, t.base, t.size]), [["maglev", 0, 65537], ["weights", 65537, 64]], "layout");
  eq(c.listing.some((l) => l.text === "tload 0 65537"), true, "one instruction reads it");
});

yeet.test("cells are 64-bit values and take arithmetic for an index", () => {
  const p = load(`table t[4]; filter { let v = t[(len * 2) % 4]; if (v == 0xffffffffffffffff) decide drop("max"); decide pass; }`);
  eq(p.exec(new Uint8Array(3), { tables: { t: [0, 0, 0xffffffffffffffffn, 0] } }).verdict, "drop", "index (3 * 2) % 4 = 2");
});

yeet.test("what does not fit, or is not declared, is a compile error", () => {
  const over = compile(`table a[${LIMITS.TABLE_CELLS}]; table b[1]; filter { decide pass; }`);
  if (over.ok || !/does not fit/.test(over.errors[0].text)) throw new Error(JSON.stringify(over.errors));
  eq(compile(`table a[0]; filter { decide pass; }`).ok, false, "a size of 0");
  eq(compile(`table a[4]; table a[4]; filter { decide pass; }`).ok, false, "declared twice");
  eq(compile(`filter { let v = nope[1]; decide pass; }`).ok, false, "an undeclared table");
  eq(compile(Array.from({ length: LIMITS.TABLES + 1 }, (_, i) => `table t${i}[1];`).join(" ") + ` filter { decide pass; }`).ok, false, `more than ${LIMITS.TABLES} tables`);
});
