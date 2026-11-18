/* Arithmetic and locals — let/assign parked in scratch registers, the operators
 * (+, -, &, |, <<, >>), register+register add, and scratch reuse across dead
 * ranges (more named locals than there are physical registers). */
import { fromC, V } from "./helpers.mjs";

/* Compute `expr` into x and drop("hit") iff x == want; so a pass means the
 * arithmetic produced something other than `want`. len comes from frame length. */
const isVal = (expr, want, len = 0, opts = {}) =>
  fromC(`filter { let x = ${expr}; if (x == ${want}) decide drop("hit"); decide pass; }`)
    .run(new Uint8Array(len), {}, opts).verdict === V.DROP;
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("each operator against a constant", () => {
  eq(isVal("5 + 3", 8), true, "+");
  eq(isVal("10 - 4", 6), true, "-");
  eq(isVal("12 & 10", 8), true, "& (0b1100 & 0b1010)");
  eq(isVal("12 | 3", 15), true, "| (0b1100 | 0b0011)");
  eq(isVal("3 << 4", 48), true, "<<");
  eq(isVal("255 >> 4", 15), true, ">>");
});

yeet.test("arithmetic on a register operand (len)", () => {
  eq(isVal("len + 1", 6, 5), true, "len(5)+1");
  eq(isVal("len << 1", 10, 5), true, "len(5)<<1");
  eq(isVal("len + 1", 6, 2), false, "len(2)+1 != 6");
});

yeet.test("register + register", () => {
  // len(4) + dport(80) == 84
  eq(fromC(`filter { let x = len + dport; if (x == 84) decide drop("h"); decide pass; }`)
    .run(new Uint8Array(4), {}, { dport: 80 }).verdict, V.DROP, "reg+reg");
});

yeet.test("assign updates an existing local", () => {
  const s = `filter { let x = 1; x = x + 10; x = x << 1; if (x == 22) decide drop("h"); decide pass; }`;
  eq(fromC(s).run(new Uint8Array(0), {}, {}).verdict, V.DROP, "(1+10)<<1 == 22");
});

yeet.test("many locals with non-overlapping live ranges reuse registers", () => {
  // Twenty named locals (> 16 registers) but each dies before the next is needed.
  let body = "let acc = 0;";
  for (let i = 1; i <= 20; i++) body += ` let t${i} = ${i}; acc = acc + t${i};`;
  const s = `filter { ${body} if (acc == 210) decide drop("h"); decide pass; }`;
  eq(fromC(s).run(new Uint8Array(0), {}, {}).verdict, V.DROP, "sum 1..20 == 210");
});

/* ---- multiply, modulo, precedence, parentheses, the flow hash ---- */
{
  const { fromC, V } = await import("./helpers.mjs");
  const { compile } = await import("#/clang");
  const { flowHash } = await import("#/interp.js");
  const is = (expr, want, opts = {}) => {
    const v = fromC(`filter { let x = ${expr}; if (x == ${want}) decide drop("y"); decide pass; }`).run(new Uint8Array(8), {}, { dport: 80, sport: 40000, ...opts }).verdict;
    if (v !== V.DROP) throw new Error(`${expr} is not ${want}`);
  };
  yeet.test("* and % compute, with a constant or a register on the right", () => {
    is("6 * 7", 42);
    is("65537 % 251", 65537 % 251);
    is("dport * 2", 160);
    is("sport % dport", 40000 % 80);
    is("sport * dport", 40000 * 80);
  });
  yeet.test("* and % bind tighter than + - & | << >>", () => {
    is("2 + 3 * 4", 14);
    is("20 - 12 % 5", 18);
    is("1 + sport % 7 * 3", 1 + (40000 % 7) * 3);
    is("2 + 3 + 4 << 1", 18);                   // the old level is still left to right
  });
  yeet.test("parentheses group arithmetic", () => {
    is("(2 + 3) * 4", 20);
    is("100 % (3 + 4)", 2);
    is("100 - (sport % 7)", 100 - (40000 % 7));
    is("(sport >> 1) * 157 & 255", ((40000 >> 1) * 157) & 255);
    is("3 * (dport + (sport % 9))", 3 * (80 + (40000 % 9)));
  });
  yeet.test("parentheses still hold a condition", () => {
    const run = (src, opts) => fromC(src).run(new Uint8Array(8), {}, opts).verdict;
    const s = `pattern a = "x"; filter { if ((dport == 80) && (sport > 1000 || sport == 7)) decide drop("y"); if ((scan(payload, 8) & (a))) decide drop("z"); decide pass; }`;
    if (run(s, { dport: 80, sport: 7 }) !== V.DROP) throw new Error("grouped comparison");
    if (run(s, { dport: 81, sport: 7 }) !== V.PASS) throw new Error("grouped comparison, false");
  });
  yeet.test("- and % with an expression on the right keep their order", () => {
    is("100 - (dport + 5)", 15);
    is("sport % (dport + 1)", 40000 % 81);
  });
  yeet.test("% 0 is refused at compile time; a zero divisor at run time yields 0", () => {
    if (compile(`filter { let x = 5 % 0; decide pass; }`).ok) throw new Error("% 0 compiled");
    is("9 % dport", 0, { dport: 0 });
  });
  yeet.test("& | << >> still want a constant or a register", () => {
    const r = compile(`filter { let x = 5 << (dport + 1); decide pass; }`);
    if (r.ok || !/constant or a plain register/.test(r.errors[0].text)) throw new Error(JSON.stringify(r.errors));
  });
  yeet.test("flow.hash is the host's flowHash, so a host-built table lines up", () => {
    const t = { saddr: 0x0a000001, daddr: 0x0a000002, sport: 40000, dport: 443, proto: 6 };
    is("flow.hash", flowHash(t), t);
    is("flow.hash % 65537", flowHash(t) % 65537, t);
    const spread = new Set();
    for (let sport = 32768; sport < 32768 + 512; sport += 2) spread.add(flowHash({ ...t, sport }) % 251);
    if (spread.size < 150) throw new Error(`neighbouring ports land on only ${spread.size} of 251 slots`);
  });
}

yeet.test("Program.exec takes the destination, and the root exports flowHash", async () => {
  const { load, flowHash } = await import("#/index.js");
  const p = load(`filter { if (flow.hash == ${flowHash({ saddr: 0x0a000001, daddr: 0x0a000002, sport: 5, dport: 80, proto: 6 })}) decide drop("y"); decide pass; }`);
  if (p.exec(new Uint8Array(4), { src: "10.0.0.1", dst: "10.0.0.2", sport: 5, dport: 80 }).verdict !== "drop") throw new Error("exec did not hash the same tuple");
});
