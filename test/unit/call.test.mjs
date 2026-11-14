/* Subroutines: `fn name() { ... }` defines a routine; `name();` calls it with
 * OP_CALL (return pc pushed on the data stack) and an implicit `ret` at the end.
 * Routines share the register file and the stack with the caller, so they pass
 * values through registers or push/pop. */
import { compile } from "#/clang.js";
import { toProgram } from "#/program.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };

yeet.test("a call runs the routine and ret returns to the caller", () => {
  // the routine sets %bp; control returns and the caller reads it
  const p = prog(`fn mark() { bp = 1; } filter { mark(); if (bp == 1) decide drop("marked"); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "drop", "routine ran (bp set) and control returned");
});

yeet.test("a routine may use the stack internally if it stays balanced across ret", () => {
  // push/pop balanced inside the routine (so ret still finds the return addr);
  // the result is handed back in a register
  const p = prog(`fn compute() { push(dport); let t = pop(); bp = t; } filter { compute(); if (bp == 77) decide rst("ok", 0); decide pass; }`);
  eq(p.exec(enc("x"), { dport: 77 }).verdict, "rst", "balanced stack use + register result");
  eq(p.exec(enc("x"), { dport: 80 }).verdict, "pass", "different value");
});

yeet.test("routines can call other routines (nested)", () => {
  const p = prog(`fn inner() { bp = 9; } fn outer() { inner(); } filter { outer(); if (bp == 9) decide drop("nested"); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "drop", "nested call reached inner()");
});

yeet.test("the routine returns (code after the call still runs)", () => {
  // if ret didn't return, the trailing rst would never execute
  const p = prog(`fn noop() { bp = 2; } filter { noop(); count("after"); decide rst("reached", 0); }`);
  eq(p.exec(enc("x"), {}).verdict, "rst", "reached the statement after the call");
});

yeet.test("a routine may call one defined earlier (back-call allowed)", () => {
  const p = prog(`fn a() { bp = 5; } fn b() { a(); } filter { b(); if (bp == 5) decide drop("backcall"); decide pass; }`);
  eq(p.exec(enc("x"), {}).verdict, "drop", "b() called the earlier a()");
});
