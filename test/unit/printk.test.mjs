/* printk("fmt", args...) — bpf_trace_printk to the kernel trace pipe (debug). The
 * format lives in the program (in-kernel); up to 3 numeric args. It's kernel-only
 * (the reference interpreter treats it as a no-op), so these tests pin the
 * lowering, the stored format, and the validation. */
import * as C from "#/dsl.js";
import { compile } from "#/clang.js";
import { assemble } from "#/asm.js";
import { OP } from "#/isa.js";

const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };
const J = (ops) => JSON.stringify(ops, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));

yeet.test("printk lowers to farg(s) + OP_PRINTK and stores the format", () => {
  const c = compile(`filter { printk("drop port %d proto %d", dport, proto); return pass; }`);
  if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors));
  eq(c.printkFormats[0], "drop port %d proto %d", "format stored in the program");
  const op = c.program.ops.find((o) => o.code === OP.PRINTK);
  if (!op) throw new Error("no OP_PRINTK");
  eq(Number(op.imm), 0, "format id");
  eq(c.program.ops.filter((o) => o.code === OP.FARG).length >= 2, true, "two numeric args pushed");
});

yeet.test("printk is a no-op in the host model", () => {
  const p = C.program(C.filter(C.printk("hi %d", C.ref("dport")), C.pass()));
  eq(p.exec(new TextEncoder().encode("x"), { dport: 80 }).verdict, "pass", "no verdict change");
});

yeet.test("pfw-C, DSL and asm agree on printk lowering", () => {
  const s = compile(`filter { printk("p %d", dport); return pass; }`);
  const d = C.program(C.filter(C.printk("p %d", C.ref("dport")), C.pass()));
  if (J(s.program.ops) !== J(d.program.ops)) throw new Error("DSL != source");
  const a = assemble(`        mov     %dport, %cur\n        farg\n        printk  $0\n        pass`);
  if (!a.ok) throw new Error("asm: " + JSON.stringify(a.errors));
  if (!a.program.ops.some((o) => o.code === OP.PRINTK)) throw new Error("asm has no PRINTK");
});

yeet.test("printk validates args and rejects %s", () => {
  for (const [src, needle] of [
    [`printk("%s", payload)`, "%s"],
    [`printk("%d %d", dport)`, "conversion"],
    [`printk("%d %d %d %d", dport, dport, dport, dport)`, "at most 3"],
  ]) {
    const r = compile(`filter { ${src}; return pass; }`);
    if (r.ok) throw new Error("should reject: " + src);
    if (!JSON.stringify(r.errors).includes(needle)) throw new Error(`wrong error for ${src}: ${JSON.stringify(r.errors)}`);
  }
});
