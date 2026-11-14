/* `argv[i]` / `argv[i] ?? default` / `argc` — runtime scalar parameters the host
 * sets without recompiling the program. The bytecode references args by index;
 * the values live in the program's args[] (set from JS via exec opts, or the
 * loader's --argv). `??` supplies an inline default used when the host set fewer
 * than i+1 args. These tests pin the lowering, the default behaviour, and that
 * all three front-ends agree. */
import * as C from "#/dsl.js";
import { compile } from "#/clang";
import { toProgram } from "#/program.js";
import { assemble } from "#/asm.js";
import { OP } from "#/isa.js";

const prog = (src) => toProgram(compile(src));

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

/* if (dport != argv[0] ?? 80) decide pass; decide rst; — a port filter whose
 * port is a runtime argument, defaulting to 80. */
const portFilter = `filter { if (dport != argv[0] ?? 80) decide pass; decide rst("hit", 0); }`;

yeet.test("argv[i] ?? d lowers to one OP_ARG encoding index + default", () => {
  const s = compile(portFilter);
  if (!s.ok) throw new Error("source: " + JSON.stringify(s.errors));
  const op = s.program.ops.find((o) => o.code === OP.ARG);
  if (!op) throw new Error("no OP_ARG emitted");
  eq(Number((op.imm >> 32n) & 0xffffn), 0, "index");
  eq(Number(op.imm & 0xffffffffn), 80, "default");
});

yeet.test("default is used when the host set no args", () => {
  const p = prog(portFilter);
  eq(p.exec(enc(""), { dport: 80 }).verdict, "rst", "default 80 matches :80");
  eq(p.exec(enc(""), { dport: 9090 }).verdict, "pass", "default 80 ignores :9090");
});

yeet.test("a runtime arg overrides the default", () => {
  const p = prog(portFilter);
  eq(p.exec(enc(""), { dport: 9090, argv: [9090] }).verdict, "rst", "argv[0]=9090 matches :9090");
  eq(p.exec(enc(""), { dport: 80, argv: [9090] }).verdict, "pass", "argv[0]=9090 ignores :80");
});

yeet.test("argc reflects how many args the host set", () => {
  const p = prog(`filter { if (argc == 0) decide drop("no_args"); decide pass; }`);
  eq(p.exec(enc("")).verdict, "drop", "no args -> argc 0");
  eq(p.exec(enc(""), { argv: [1, 2] }).verdict, "pass", "two args -> argc 2");
});

yeet.test("argv works as a threshold, not just equality", () => {
  // drop when the request is larger than a runtime cap (default 1000)
  const p = prog(`filter { if (len > argv[0] ?? 1000) decide drop("too_big"); decide pass; }`);
  eq(p.exec(enc("x".repeat(50)), { payload: 0 }).verdict, "pass", "under default cap");
  eq(p.exec(enc("x".repeat(50)), { argv: [10] }).verdict, "drop", "over a cap of 10");
});

yeet.test("pfw-C, DSL and asm all lower argv identically", () => {
  const s = compile(`filter { if (dport != argv[0] ?? 80) decide pass; decide rst("hit", 0); }`);
  const d = C.program(C.filter(C.iff(C.ne(C.ref("dport"), C.arg(0, 80)), C.pass()), C.rst("hit", 0)));
  const J = (ops) => JSON.stringify(ops, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));
  if (J(s.program.ops) !== J(d.program.ops)) throw new Error("DSL != source:\n" + J(s.program.ops) + "\n" + J(d.program.ops));

  const a = assemble(`        mov     %dport, %cur\n        mov     %cur, %s0\n        arg     $0, $80\n        cmp     %s0, %cur\n        je      no\n        rst     $1, $0\n no:    pass`);
  if (!a.ok) throw new Error("asm: " + JSON.stringify(a.errors));
  const aop = a.program.ops.find((o) => o.code === OP.ARG);
  if (!aop || Number((aop.imm >> 32n) & 0xffffn) !== 0 || Number(aop.imm & 0xffffffffn) !== 80) throw new Error("asm arg imm wrong");
});

yeet.test("pfw-C rejects a bad argv index or default", () => {
  for (const bad of [`argv[99]`, `argv[]`, `argv[0] ?? "x"`]) {
    const r = compile(`filter { if (dport != ${bad}) decide pass; decide rst("h", 0); }`);
    if (r.ok) throw new Error("should have rejected: " + bad);
  }
});
