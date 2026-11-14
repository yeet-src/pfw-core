/* `redirect(ifindex)` — forward the packet out another interface (XDP_REDIRECT).
 * Kernel-only (the host frame model has no forwarding), so the reference
 * interpreter treats it as a no-op that falls through to pass; these tests pin
 * the lowering: the op carries the ifindex in imm, and all three front-ends
 * (pfw-C, DSL, asm) produce the same bytecode. */
import * as C from "#/dsl.js";
import { compile } from "#/clang";
import { assemble } from "#/asm.js";
import { OP } from "#/isa.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const J = (ops) => JSON.stringify(ops, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));

yeet.test("redirect lowers to OP_REDIRECT with the ifindex in imm", () => {
  const p = C.program(C.filter(C.redirect(7), C.pass()));
  const op = p.program.ops.find((o) => o.code === OP.REDIRECT);
  if (!op) throw new Error("no OP_REDIRECT emitted");
  eq(Number(op.imm), 7, "ifindex");
});

yeet.test("redirect is a no-op in the host model (falls through to pass)", () => {
  const p = C.program(C.filter(C.redirect(1), C.pass()));
  eq(p.exec(enc("anything"), {}).verdict, "pass", "redirect then pass");
});

yeet.test("pfw-C, DSL and asm all lower redirect identically", () => {
  const s = compile(`filter { redirect(2); decide pass; }`);
  if (!s.ok) throw new Error("source: " + JSON.stringify(s.errors));
  const d = C.program(C.filter(C.redirect(2), C.pass()));
  if (J(s.program.ops) !== J(d.program.ops)) throw new Error("DSL != source");

  const a = assemble(`        redirect 2\n        pass`);
  if (!a.ok) throw new Error("asm: " + JSON.stringify(a.errors));
  const aop = a.program.ops.find((o) => o.code === OP.REDIRECT);
  if (!aop || Number(aop.imm) !== 2) throw new Error("asm redirect ifindex wrong");
});

yeet.test("pfw-C rejects a bad redirect ifindex", () => {
  for (const bad of [`redirect();`, `redirect(0);`, `redirect(-1);`]) {
    const r = compile(`filter { ${bad} decide pass; }`);
    if (r.ok) throw new Error("should have rejected: " + bad);
  }
});
