/* emit("name", values...) — a typed event to the host: a name and numbers, not
 * a line of text to format in the kernel's stead and parse back on the host. */
import { load } from "#/index.js";
import { compile } from "#/clang";
import { LIMITS } from "#/isa.js";

const eq = (g, w, m) => { if (JSON.stringify(g, (_, v) => (typeof v === "bigint" ? Number(v) : v)) !== JSON.stringify(w)) throw new Error(`${m}: got ${JSON.stringify(g, (_, v) => (typeof v === "bigint" ? Number(v) : v))}, want ${JSON.stringify(w)}`); };
const frame = new Uint8Array(8);

yeet.test("an event carries its name and its values as numbers", () => {
  const p = load(`filter { emit("flow", src, sport, dport); decide pass; }`);
  const r = p.exec(frame, { src: "10.0.0.7", sport: 40000, dport: 443 });
  eq(r.events, [{ name: "flow", values: [0x0a000007, 40000, 443] }], "one event");
  if (typeof r.events[0].values[0] !== "bigint") throw new Error("values are BigInt, as counters are");
  eq(r.console, [], "and it is not a console line");
  eq(r.verdict, "pass", "emit is not a verdict");
});

yeet.test("values are expressions, up to eight of them", () => {
  const p = load(`filter { let n = len + 1; emit("sizes", n, len * 2, u8(payload), flow.hash % 7, 5, 6, 7, 8); decide pass; }`);
  const r = p.exec(Uint8Array.from([9, 0, 0, 0]), { src: "1.2.3.4", sport: 1, dport: 2 });
  eq(r.events[0].values.slice(0, 3), [5, 8, 9], "computed values");
  eq(r.events[0].values.length, 8, "eight");
  eq(compile(`filter { emit("x", 1, 2, 3, 4, 5, 6, 7, 8, 9); decide pass; }`).ok, false, `more than ${LIMITS.FARGS} is refused`);
});

yeet.test("several events, each under its own name, in order", () => {
  const p = load(`filter {
    emit("open", sport);
    if (dport == 443) emit("tls", sport, 771);
    emit("open", dport);
    decide drop("x");
  }`);
  eq(p.emits, [{ id: 0, name: "open", arity: 1 }, { id: 1, name: "tls", arity: 2 }], "the program says what it emits");
  eq(p.exec(frame, { sport: 5, dport: 443 }).events, [{ name: "open", values: [5] }, { name: "tls", values: [5, 771] }, { name: "open", values: [443] }], "in order");
  eq(p.exec(frame, { sport: 5, dport: 80 }).events.map((e) => e.name), ["open", "open"], "the conditional one is skipped");
});

yeet.test("the callback form, as the loader delivers them", () => {
  const got = [];
  load(`filter { emit("a", 1); emit("b"); decide pass; }`).exec(frame, { onEmit: (e) => got.push(e.name) });
  eq(got, ["a", "b"], "onEmit");
});

yeet.test("one name has one shape", () => {
  const r = compile(`filter { emit("flow", sport); emit("flow", sport, dport); decide pass; }`);
  if (r.ok || !/one name, one shape/.test(r.errors[0].text)) throw new Error(JSON.stringify(r.errors));
  eq(compile(`filter { emit(sport); decide pass; }`).ok, false, "the name comes first");
  eq(compile(`filter { emit("two words", 1); decide pass; }`).ok, false, "a name is an identifier");
});

yeet.test("console still works beside it, and now takes eight numbers", () => {
  const p = load(`filter { console("a=%d b=%d c=%d d=%d e=%d f=%d", 1, 2, 3, 4, 5, 6); emit("n", 7); decide pass; }`);
  const r = p.exec(frame, {});
  eq(r.console, ["a=1 b=2 c=3 d=4 e=5 f=6"], "six numbers in a console line");
  eq(r.events, [{ name: "n", values: [7] }], "and the event");
});

yeet.test("a call's argument may be arithmetic: console, ring.push, ring.get", () => {
  const p = load(`filter { ring.push(len + 1); ring.push(len * 3); console("%d %d", ring.get(1 - 1), len % 3 + 10); decide pass; }`);
  eq(p.exec(new Uint8Array(4), {}).console, ["12 11"], "arithmetic arguments");
});
