/* The VM data stack: push(v) / pop() backed by a per-CPU stack map, with %sp
 * (stack pointer) and %bp (base pointer) registers. push stores %cur and bumps
 * %sp; pop lowers %sp and loads %cur; %bp lets a program save/restore %sp. */
import { compile } from "#/clang";
import { toProgram } from "#/program";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };

yeet.test("push then pop round-trips a value", () => {
  const p = prog(`filter { push(dport); let x = pop(); if (x == 443) decide rst("hit", 0); decide pass; }`);
  eq(p.exec(enc("x"), { dport: 443 }).verdict, "rst", "popped the pushed dport");
  eq(p.exec(enc("x"), { dport: 80 }).verdict, "pass", "different value");
});

yeet.test("the stack is LIFO", () => {
  const p = prog(`filter { push(dport); push(proto); let a = pop(); let b = pop(); if (a == proto) { if (b == dport) decide rst("lifo", 0); } decide pass; }`);
  eq(p.exec(enc("x"), { dport: 8080, proto: 6 }).verdict, "rst", "popped in reverse push order");
});

yeet.test("%sp tracks the depth", () => {
  const p = prog(`filter { if (sp != 0) decide pass; push(dport); push(dport); if (sp == 2) decide rst("depth", 0); decide pass; }`);
  eq(p.exec(enc("x"), { dport: 1 }).verdict, "rst", "sp is 0 then 2 after two pushes");
});

yeet.test("%bp saves and restores %sp", () => {
  // bp = sp; push a few; sp = bp  -> stack unwound to the saved depth
  const p = prog(`filter { bp = sp; push(dport); push(dport); push(dport); sp = bp; if (sp == 0) decide rst("unwound", 0); decide pass; }`);
  eq(p.exec(enc("x"), { dport: 1 }).verdict, "rst", "sp restored from bp");
});

yeet.test("pop() is usable inline in an expression", () => {
  const p = prog(`filter { push(dport); if (pop() == 1234) decide drop("x"); decide pass; }`);
  eq(p.exec(enc("x"), { dport: 1234 }).verdict, "drop", "inline pop compares");
});
