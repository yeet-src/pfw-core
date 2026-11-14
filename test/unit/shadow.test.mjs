/* Shadow mode: a host-set flag that turns enforcement verdicts (drop/ban/rst)
 * into a dry run — the packet is let through (verdict reported as pass) but the
 * would-be verdict is surfaced in `would`, so you can see what a rule WOULD block
 * before enforcing it. Also readable in-program as `%shadow`. */
import { compile } from "#/clang";
import { toProgram } from "#/program";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };

yeet.test("shadow turns a drop into a pass, reporting the would-be verdict", () => {
  const p = prog(`filter { if (dport != 80) decide pass; decide drop("blk"); }`);
  const normal = p.exec(enc("x"), { dport: 80 });
  eq(normal.verdict, "drop", "normal: enforced");
  eq(normal.would, undefined, "normal: no would");
  const shad = p.exec(enc("x"), { dport: 80, shadow: true });
  eq(shad.verdict, "pass", "shadow: packet passes");
  eq(shad.would, "drop", "shadow: would-be drop surfaced");
});

yeet.test("shadow applies to rst and ban too, but not to a real pass", () => {
  const rst = prog(`filter { decide rst("r", 0); }`);
  eq(rst.exec(enc("x"), { shadow: true }).verdict, "pass", "rst shadowed");
  eq(rst.exec(enc("x"), { shadow: true }).would, "rst", "would=rst");
  const ban = prog(`filter { decide ban("b", 60); }`);
  eq(ban.exec(enc("x"), { shadow: true }).would, "ban", "would=ban");
  const pass = prog(`filter { decide pass; }`);
  eq(pass.exec(enc("x"), { shadow: true }).verdict, "pass", "a real pass stays pass");
  eq(pass.exec(enc("x"), { shadow: true }).would, undefined, "no would on a pass");
});

yeet.test("%shadow is readable in the program", () => {
  // behave differently in shadow mode: only count, never even request a drop
  const p = prog(`filter { if (shadow == 1) { count("dryrun"); decide pass; } decide drop("live"); }`);
  eq(p.exec(enc("x"), {}).verdict, "drop", "live mode drops");
  eq(p.exec(enc("x"), { shadow: true }).verdict, "pass", "shadow mode: program sees %shadow and passes");
});
