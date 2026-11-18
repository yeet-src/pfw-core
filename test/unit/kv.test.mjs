/* lookup(key) — the host-loaded key -> value map. `x in hash` says whether a
 * key is known; this says what goes with it. */
import { load } from "#/index.js";
import { compile } from "#/clang";

const eq = (g, w, m) => { if (JSON.stringify(g) !== JSON.stringify(w)) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };
const frame = new Uint8Array(8);

yeet.test("a key yields the value stored under it", () => {
  const p = load(`filter { let policy = lookup(dport); if (policy == 2) decide drop("blocked"); if (policy == 1) decide count("watched"); decide pass; }`);
  const kv = { 22: 2, 443: 1 };
  eq(p.exec(frame, { dport: 22, kv }).verdict, "drop", "port 22 -> policy 2");
  eq(p.exec(frame, { dport: 443, kv }).ruleName, "watched", "port 443 -> policy 1");
  eq(p.exec(frame, { dport: 80, kv }).verdict, "pass", "port 80 is not in the map: 0");
  eq(p.exec(frame, { dport: 22 }).verdict, "pass", "an empty map knows nothing");
});

yeet.test("?? gives an absent key a default, and leaves a stored 0 alone", () => {
  const p = load(`filter { if (lookup(dport) ?? 9 == 9) decide drop("unknown_port"); decide pass; }`);
  eq(p.exec(frame, { dport: 80, kv: { 443: 1 } }).verdict, "drop", "absent -> the default");
  eq(p.exec(frame, { dport: 443, kv: { 443: 1 } }).verdict, "pass", "present");
  eq(p.exec(frame, { dport: 53, kv: { 53: 0 } }).verdict, "pass", "present with 0 is 0, not the default");
});

yeet.test("an API key resolves to its tenant, and the tenant to its limit", () => {
  // The key is whatever number the program derives; here the first four payload bytes.
  const p = load(`filter {
    let tenant = lookup(be32(payload));
    if (tenant == 0) decide rst("unknown_key", 0);
    emit("request", tenant);
    if (rate(lookup(tenant + 0x100000000) ?? 1, 2)) decide drop("over_quota");
    decide pass;
  }`);
  const bytes = (s) => Uint8Array.from(s, (ch) => ch.charCodeAt(0));
  const key = (s) => { const b = bytes(s); return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0; };
  const kv = new Map([[BigInt(key("ak_1")), 11n], [BigInt(key("ak_2")), 22n], [0x100000000n + 11n, 100n]]);
  const r = p.exec(bytes("ak_2...."), { kv, bucket: {}, now: 1n });
  eq(r.events.map((e) => Number(e.values[0])), [22], "the tenant the key belongs to");
  eq(p.exec(bytes("nope...."), { kv }).ruleName, "unknown_key", "an unknown key is refused");
});

yeet.test("keys and values are 64-bit, and a key is any arithmetic", () => {
  const p = load(`filter { let v = lookup((sport << 16) + dport); if (v == 0xffffffffffffffff) decide drop("max"); decide pass; }`);
  eq(p.exec(frame, { sport: 7, dport: 9, kv: new Map([[(7n << 16n) + 9n, 0xffffffffffffffffn]]) }).verdict, "drop", "a composed key, a full-width value");
});

yeet.test("lookup wants one key, and a literal default", () => {
  eq(compile(`filter { let v = lookup(); decide pass; }`).ok, false, "no key");
  eq(compile(`filter { let v = lookup(dport) ?? sport; decide pass; }`).ok, false, "a computed default");
  eq(compile(`filter { let lookup = 3; if (lookup == 3) decide drop("y"); decide pass; }`).ok, true, "lookup alone is still a name");
});
