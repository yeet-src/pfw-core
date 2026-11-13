/* Verdicts and side-effects — pass / drop / count / ban / rst as return values
 * (each records the triggering rule's name), count(...) and log(...) as
 * non-terminating statements, and the default fall-through to pass. */
import { fromC, V } from "./helpers.mjs";

const res = (src, opts = {}) => fromC(src).run(new Uint8Array(0), {}, opts);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("the blocking verdicts return their code", () => {
  eq(res(`filter { return pass; }`).verdict, V.PASS, "pass");
  eq(res(`filter { return drop("d"); }`).verdict, V.DROP, "drop");
  eq(res(`filter { return ban("b", 60); }`).verdict, V.BAN, "ban");
  eq(res(`filter { return rst("r", 0); }`).verdict, V.RST, "rst");
});

yeet.test("count is a tally, not a blocking verdict — it falls through to pass", () => {
  const { run, rules } = fromC(`filter { return count("c"); }`);
  const r = run(new Uint8Array(0), {}, {});
  eq(r.verdict, V.PASS, "count -> pass");
  eq(rules[r.rule].name, "c", "count still records the rule");
});

yeet.test("the triggering rule name is recorded", () => {
  const { run, rules } = fromC(`filter { if (dport == 80) return rst("crawler", 0); return pass; }`);
  const r = run(new Uint8Array(0), {}, { dport: 80 });
  eq(r.verdict, V.RST, "rst");
  eq(rules[r.rule].name, "crawler", "rule name");
});

yeet.test("a filter with no matching rule falls through to pass", () => {
  eq(res(`filter { if (dport == 1) return drop("x"); }`, { dport: 80 }).verdict, V.PASS, "implicit pass");
});

yeet.test("count(...) as a statement tallies and continues", () => {
  // The count statement does not stop the program — the later rst still fires.
  const r = res(`filter { count("seen"); return rst("stop", 0); }`);
  eq(r.verdict, V.RST, "reached the rst after count()");
});

yeet.test("log(...) as a statement does not change the verdict", () => {
  eq(res(`filter { log(16); return pass; }`).verdict, V.PASS, "log then pass");
  eq(res(`filter { if (dport == 80) { log(1); return drop("d"); } return pass; }`, { dport: 80 }).verdict, V.DROP, "log then drop");
});
