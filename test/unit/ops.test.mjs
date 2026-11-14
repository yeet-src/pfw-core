/* Behavioral coverage of the whole ISA: a tiny assembly program per opcode, run
 * through the reference interpreter, asserting the resulting verdict (or the
 * returned flow). This is what makes the base matching engine — scan, the
 * automaton, loads, arithmetic, the branches, the flow-state ops — actually
 * tested, not just compiled. (Primitive end-to-end behavior is in the other
 * files; this pins each op.) Every opcode in isa.js is exercised at least once;
 * the "coverage" case at the end fails if one is missed. */
import { assemble } from "#/asm.js";
import { build } from "#/ac.js";
import { machine, V } from "#/interp.js";
import { OP } from "#/isa.js";

const enc = new TextEncoder();
const used = new Set();
const note = (asm) => { for (const op of asm.program.ops) used.add(op.code); };

function run(src, { frame = new Uint8Array(64), flow = {}, opts = {} } = {}) {
  const asm = assemble(src);
  if (!asm.ok) throw new Error("assemble failed: " + JSON.stringify(asm.errors) + "\n" + src);
  note(asm);
  const res = machine({ asm, tables: build(asm.patterns, asm.nocase) })(frame, 0, { ac: 0, mask: 0n, ...flow }, opts);
  return { ...res, rules: asm.rules };
}
/* Most ops are checked by the "RST iff the computed value is right" shape:
 *   <compute cur>; cmp $E, %cur; jne no; rst $1,$0; no: pass
 * so verdict RST means the op produced E. */
const eq = (setup, E) => `${setup}\n        cmp     $${E}, %cur\n        jne     no\n        rst     $1, $0\n no:    pass`;
const expectRst = (name, src, env) => { const r = run(src, env); if (r.verdict !== V.RST) throw new Error(`${name}: verdict=${r.verdict} (want RST)`); };
const expect = (name, src, want, env) => { const r = run(src, env); if (r.verdict !== want) throw new Error(`${name}: verdict=${r.verdict} (want ${want})`); };

/* ---- arithmetic & moves ---- */
yeet.test("add/sub/and/or/shl/shr (imm)", () => {
  expectRst("add", eq("        and     $0, %cur\n        add     $5, %cur", 5));
  expectRst("sub", eq("        and     $0, %cur\n        add     $9, %cur\n        sub     $4, %cur", 5));
  expectRst("and", eq("        and     $0, %cur\n        add     $0xff, %cur\n        and     $0x0f, %cur", 15));
  expectRst("or", eq("        and     $0, %cur\n        add     $0x10, %cur\n        or      $1, %cur", 17));
  expectRst("shl", eq("        and     $0, %cur\n        add     $3, %cur\n        shl     $4, %cur", 48));
  expectRst("shr", eq("        and     $0, %cur\n        add     $48, %cur\n        shr     $4, %cur", 3));
});
yeet.test("mov reg<->cur, add/sub reg", () => {
  expectRst("mov_cr/mov_rc", eq("        and     $0, %cur\n        add     $42, %cur\n        mov     %cur, %s0\n        and     $0, %cur\n        mov     %s0, %cur", 42));
  expectRst("add_r", eq("        and     $0, %cur\n        add     $10, %cur\n        mov     %cur, %s0\n        and     $0, %cur\n        add     $3, %cur\n        add     %s0, %cur", 13));
  expectRst("sub_r", eq("        and     $0, %cur\n        add     $3, %cur\n        mov     %cur, %s0\n        and     $0, %cur\n        add     $10, %cur\n        sub     %s0, %cur", 7));
  expectRst("mov_rc(dport)", eq("        mov     %dport, %cur", 8080), { opts: { dport: 8080 } });
});

/* ---- loads (little- and big-endian, all sizes) ---- */
yeet.test("load movb/w/l/q and movbew/movbel", () => {
  const frame = Uint8Array.of(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);
  expectRst("movb", eq("        movb    0(%cur), %cur", "0x11"), { frame });
  expectRst("movw LE", eq("        movw    0(%cur), %cur", "0x2211"), { frame });
  expectRst("movl LE", eq("        movl    0(%cur), %cur", "0x44332211"), { frame });
  expectRst("movq LE", eq("        movq    0(%cur), %cur", "0x8877665544332211"), { frame });
  expectRst("movbew BE", eq("        movbew  0(%cur), %cur", "0x1122"), { frame });
  expectRst("movbel BE", eq("        movbel  0(%cur), %cur", "0x11223344"), { frame });
});

/* ---- compare & branch ---- */
yeet.test("cmp_i, cmp_r and every conditional branch", () => {
  expect("jmp", `        jmp     ok\n        drop    $1\n ok:    pass`, V.PASS);
  expect("je", `        and     $0, %cur\n        cmp     $0, %cur\n        je      ok\n        drop    $1\n ok:    pass`, V.PASS);
  expect("jne", `        and     $0, %cur\n        add     $1, %cur\n        cmp     $0, %cur\n        jne     ok\n        drop    $1\n ok:    pass`, V.PASS);
  expect("jb (CF)", `        and     $0, %cur\n        cmp     $5, %cur\n        jb      ok\n        drop    $1\n ok:    pass`, V.PASS);
  expect("jae (!CF)", `        and     $0, %cur\n        add     $5, %cur\n        cmp     $5, %cur\n        jae     ok\n        drop    $1\n ok:    pass`, V.PASS);
  expect("ja (!CF&!ZF)", `        and     $0, %cur\n        add     $10, %cur\n        cmp     $5, %cur\n        ja      ok\n        drop    $1\n ok:    pass`, V.PASS);
  expect("jbe (CF|ZF)", `        and     $0, %cur\n        add     $5, %cur\n        cmp     $5, %cur\n        jbe     ok\n        drop    $1\n ok:    pass`, V.PASS);
  expectRst("cmp_r", eq("        and     $0, %cur\n        add     $7, %cur\n        mov     %cur, %s0\n        and     $0, %cur\n        add     $7, %cur\n        cmp     %s0, %cur", 7)); // cur==7 and ==s0
});
yeet.test("jf takes on a fault (load past %end)", () => {
  expect("jf", `        mov     %end, %cur\n        movb    0(%cur), %cur\n        jf      ok\n        drop    $1\n ok:    pass`, V.PASS);
});

/* ---- patterns: scan, test, mpos, cmpstr, findb, skipb ---- */
yeet.test("scan + test find a pattern; mpos / cmpstr", () => {
  const frame = enc.encode("GET GPTBot here");
  const body = `.pat    bot, "GPTBot"\n        mov     %payload, %cur\n        scan    $64, (%cur)\n        test    $bot, %m\n        je      no\n        rst     $1, $0\n no:    pass`;
  expectRst("scan+test", body, { frame });
  // mpos: end offset of "GPTBot" within "GET GPTBot..." is 4 + 6 = 10
  expectRst("mpos", `.pat    bot, "GPTBot"\n        mov     %payload, %cur\n        scan    $64, (%cur)\n        mpos    $bot, %cur\n        cmp     $10, %cur\n        jne     no\n        rst     $1, $0\n no:    pass`, { frame });
  // cmpstr: anchored "GET" at payload start
  expectRst("cmpstr", `.pat    get, "GET"\n        mov     %payload, %cur\n        cmpstr  $get, (%cur)\n        jne     no\n        rst     $1, $0\n no:    pass`, { frame });
});
yeet.test("findb finds a byte; skipb skips a run", () => {
  const frame = enc.encode("ab cd"); // space (0x20) at offset 2
  expectRst("findb", eq("        findb   $0x20, $16", 2), { frame });
  const spaces = enc.encode("   X"); // three spaces then X
  expectRst("skipb", eq("        skipb   $0x20", 3), { frame: spaces });
});

/* ---- verdicts ---- */
yeet.test("pass / drop / ban / rst and count/log continue", () => {
  expect("pass", `        pass`, V.PASS);
  expect("drop", `        drop    $1`, V.DROP);
  expect("ban", `        ban     $1, $0`, V.BAN);
  expect("rst", `        rst     $1, $0`, V.RST);
  expect("count continues", `        count   $1\n        drop    $2`, V.DROP); // count doesn't end
  expect("log continues", `        log     $4\n        drop    $2`, V.DROP);  // log doesn't end
  // the implicit END (falling off the program) is a pass
  expect("fall-through END", `        and     $0, %cur`, V.PASS);
});

/* ---- flow state: sload, sstore, bump, flow, mark ---- */
yeet.test("sload/flow read; bump increments; sstore/mark write back", () => {
  expectRst("sload", eq("        sload   %cur", 7), { flow: { userState: 7 } });
  expectRst("flow(mark)", eq("        flow    %cur", 16), { flow: { mark: 16 } });
  expectRst("bump x2", eq("        bump    %cur\n        bump    %cur", 2));
  const s = run(`        sstore  $9\n        pass`);
  if (s.flow.userState !== 9) throw new Error("sstore -> flow.userState=" + s.flow.userState);
  const m = run(`        mark    $16\n        pass`);
  if (m.flow.mark !== 16) throw new Error("mark -> flow.mark=" + m.flow.mark);
});

/* ---- cidr / ring (also covered in their own files; here for op coverage) ---- */
yeet.test("cidr, rpush/rget/rlen", () => {
  expectRst("cidr in", `        mov     %saddr, %cur\n        cidr    10.0.0.0/8\n        je      ok\n        pass\n ok:    rst     $1, $0`, { opts: { saddr: (10 << 24) | 1 } });
  expectRst("ring push/len/get", `        and     $0, %cur\n        add     $99, %cur\n        rpush   %cur\n        rlen    %cur\n        cmp     $1, %cur\n        jne     no\n        and     $0, %cur\n        rget    %cur\n        cmp     $99, %cur\n        jne     no\n        rst     $1, $0\n no:    pass`);
});

/* ---- packet rewrite (also covered in rewrite.test.mjs; here for op coverage) ---- */
yeet.test("redact / replace rewrite the frame", () => {
  // redact "bb" with 'X', then verify the frame bytes changed, then pass.
  const red = assemble(`        .pat    bb, "bb"\n        redact  $bb, $0x58\n        pass`);
  if (!red.ok) throw new Error("assemble redact: " + JSON.stringify(red.errors));
  note(red);
  const f = Uint8Array.from(enc.encode("a bb c bb"));
  machine({ asm: red, tables: build(red.patterns, red.nocase) })(f, 0, { ac: 0, mask: 0n }, {});
  if (String.fromCharCode(...f) !== "a XX c XX") throw new Error("redact: " + String.fromCharCode(...f));
  // replace "GG" with "HH" (same length).
  const rep = assemble(`        .pat    g, "GG"\n        .pat    h, "HH"\n        replace $g, $h\n        pass`);
  if (!rep.ok) throw new Error("assemble replace: " + JSON.stringify(rep.errors));
  note(rep);
  const f2 = Uint8Array.from(enc.encode("x GG y"));
  machine({ asm: rep, tables: build(rep.patterns, rep.nocase) })(f2, 0, { ac: 0, mask: 0n }, {});
  if (String.fromCharCode(...f2) !== "x HH y") throw new Error("replace: " + String.fromCharCode(...f2));
});

/* ---- coverage gate ---- */
yeet.test("every opcode was exercised", () => {
  const miss = Object.entries(OP).filter(([, v]) => !used.has(v)).map(([k]) => k);
  // END is the implicit terminator (no mnemonic); the fall-through case exercises it at runtime.
  const allowed = new Set(["END"]);
  const real = miss.filter((k) => !allowed.has(k));
  if (real.length) throw new Error("opcodes never run: " + real.join(", "));
});
