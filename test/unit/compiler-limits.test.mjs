/* Three compiler defects, pinned:
 *   1. a subroutine's local could share a register with a caller's local that is
 *      live across the call, so the callee overwrote it;
 *   2. a regex whose DFA is larger than the kernel's table (LIMITS.RE_STATES)
 *      compiled anyway, and would have indexed past the table in the kernel;
 *   3. a program over the instruction budget threw from compile() instead of
 *      returning { ok: false }. */
import { compile } from "#/clang";
import { load } from "#/index.js";
import { LIMITS, SCRATCH } from "#/isa.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("a callee's locals do not clobber a caller's local live across the call", () => {
  const p = load(`fn f() { let s = 7; let t = 9; return s + t; }
    filter { let x = 1; let y = f(); if (x != 1) decide drop("clobbered"); if (y != 16) decide drop("bad_return"); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "pass", "x survives the call, y is the return value");
});

yeet.test("...with several caller locals, args, and a nested call", () => {
  const p = load(`fn inner(a) { let k = a + 100; let j = k + 1; return j; }
    fn outer(a, b) { let keep = a + b; let r = inner(keep); if (keep != 30) return 0; return r; }
    filter { let p1 = 11; let p2 = 22; let p3 = 33; let got = outer(10, 20);
      if (p1 != 11) decide drop("p1"); if (p2 != 22) decide drop("p2"); if (p3 != 33) decide drop("p3");
      if (got != 131) decide drop("got"); decide pass; }`);
  const r = p.exec(enc("x"), {});
  eq(r.verdict === "pass" ? "pass" : `${r.verdict}(${r.ruleName})`, "pass", "all locals intact, nested result correct");
});

yeet.test("a local that is NOT live across a call may still share a register", () => {
  /* Eight filter locals, none live across the call: the callee's two still fit. */
  const decls = Array.from({ length: 6 }, (_, i) => `let v${i} = ${i};`).join(" ");
  const uses = Array.from({ length: 6 }, (_, i) => `if (v${i} != ${i}) decide drop("v${i}");`).join(" ");
  const c = compile(`fn f() { let s = 7; let t = 9; return s + t; } filter { let y = f(); ${decls} ${uses} if (y != 16) decide drop("y"); decide pass; }`);
  if (!c.ok) throw new Error(JSON.stringify(c.errors));
});

yeet.test("a regex DFA over the kernel's table size is a compile error", () => {
  const c = compile(`regex key = "a[a-z]{40}"; filter { if (scan(payload, 256) & key) decide drop("k"); decide pass; }`);
  eq(c.ok, false, "must not compile");
  if (!/DFA too large/.test(c.errors[0].text) || !c.errors[0].text.includes(String(LIMITS.RE_STATES))) throw new Error("unhelpful error: " + c.errors[0].text);
  const small = compile(`regex ssn = "\\\\d{3}-\\\\d{2}-\\\\d{4}"; filter { if (scan(payload, 256) & ssn) decide drop("k"); decide pass; }`);
  eq(small.ok, true, "an ordinary regex still compiles");
  const aws = compile(`regex key = "AKIA[A-Z0-9]{16}"; filter { if (scan(payload, 256) & key) decide drop("k"); decide pass; }`);
  eq(aws.ok, true, "a whole AWS access key id fits the table");
  if (small.regex.nstates > LIMITS.RE_STATES) throw new Error("accepted DFA exceeds the table");
});

yeet.test("a program over the instruction budget is a compile error, not a throw", () => {
  const body = Array.from({ length: LIMITS.MAX_OPS / 2 }, (_, i) => `if (len == ${i}) decide drop("r");`).join("\n");
  let c;
  try { c = compile(`filter { ${body} decide pass; }`); } catch (e) { throw new Error("compile() threw: " + e.message); }
  eq(c.ok, false, "must not compile");
  if (!c.errors[0].text.includes(String(LIMITS.MAX_OPS))) throw new Error("unhelpful error: " + c.errors[0].text);
});

yeet.test("running out of registers names what holds them, by line", () => {
  /* Two locals short of every register, and a frame walk that needs three: one
   * more than there are. The old message listed only the locals
   * ("all 8 are held by q"), which was no help when a walk held most of them. */
  const names = Array.from({ length: SCRATCH.length - 2 }, (_, i) => `v${i}`);
  const r = compile(`filter {
    ${names.map((n, i) => `let ${n} = ${i};`).join(" ")}
    frame (len = u8 @ 1, head = 2) up to 1 {
      if (frame.len == 35) decide drop("x");
    }
    ${names.map((n) => `if (${n} == 99) decide drop("x");`).join(" ")}
    decide pass;
  }`);
  eq(r.ok, false, "it does not fit");
  const e = r.errors[0];
  if (!/too many locals live at once/.test(e.text)) throw new Error("wrong error: " + e.text);
  if (/^internal/.test(e.text)) throw new Error("it is the program's error, not the compiler's: " + e.text);
  if (!e.text.includes(`${names.length} by your locals (\`v0\`, \`v1\`,`)) throw new Error("does not count the locals: " + e.text);
  if (!/2 by the `frame` walk at line 3/.test(e.text) || !/the `frame` walk at line 3 needs a register/.test(e.text)) throw new Error("does not name the frame: " + e.text);
  eq(e.line, 3, "the error is at the construct that could not be placed");
});

yeet.test("two frame walks nest, with locals to spare", () => {
  /* Each walk holds three or four registers; with eight in all, a walk inside
   * a walk left none for the program. */
  const p = load(`filter {
    let hits = 0;
    frame (type = u8 @ 0, len = u8 @ 1, head = 2) up to 4 {
      if (frame.type == 1) {
        frame at (frame.data) (type = u8 @ 0, len = u8 @ 1, head = 2) up to 4 {
          if (frame.type == 7) hits = hits + frame.len;
        }
      }
    }
    if (hits == 5) decide drop("nested");
    decide pass;
  }`);
  // outer: [type 9, len 1, x] [type 1, len 9: inner [7,2,a,b] [3,0] [7,3,c,d,e]]
  const inner = [7, 2, 0x61, 0x62, 3, 0, 7, 3, 0x63, 0x64, 0x65];
  eq(p.exec(Uint8Array.from([9, 1, 0x78, 1, inner.length, ...inner]), {}).verdict, "drop", "the inner walk summed its two type-7 records");
  eq(p.exec(Uint8Array.from([9, 1, 0x78, 2, inner.length, ...inner]), {}).verdict, "pass", "and only inside a type-1 outer record");
});

yeet.test("a scan shorter than the reassembly window is a warning, not an error", () => {
  const prog = (decl, call) => compile(`${decl} pattern sig = "evil"; filter { if (${call} & sig) decide drop("s"); decide pass; }`);
  const short = prog("reassemble 80;", "scan(payload, 2048)");
  eq(short.ok, true, "it still compiles");
  eq(short.warnings.length, 1, "and says so once");
  eq(short.warnings[0].line, 1, "at the scan");
  if (!short.warnings[0].text.includes("2048") || !short.warnings[0].text.includes(String(LIMITS.REASM_CAP))) throw new Error("unhelpful warning: " + short.warnings[0].text);
  eq(prog("decode h2 80;", "scan(payload, 2048)").warnings.length, 1, "a decoded view is a window too");
  eq(prog("reassemble 80;", `scan(payload, ${LIMITS.REASM_CAP})`).warnings.length, 0, "the whole window");
  eq(prog("", "scan(payload, 256)").warnings.length, 0, "per packet, a short scan is just a short scan");
  eq(prog("reassemble 80;", "within(payload, 256)").warnings.length, 0, "within is a bounded look by design");
  const elsewhere = compile(`reassemble 80; pattern sig = "evil", sp = " "; filter { if (!(scan(payload, ${LIMITS.REASM_CAP}) & sp)) decide pass; ptr p = after(sp); if (scan(p, 64) & sig) decide drop("s"); decide pass; }`);
  eq(elsewhere.warnings.length, 0, "so is a scan from another pointer");
});
