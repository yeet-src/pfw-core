/* Verdicts and side-effects — `decide pass/drop/count/ban/rst` as the terminal
 * action (each records the triggering rule's name), count(...) and log(...) as
 * non-terminating statements, and the default fall-through to pass. `return` is
 * reserved for a subroutine's value, not verdicts. */
import { fromC, V } from "./helpers.mjs";
import { compile } from "#/clang";

const res = (src, opts = {}) => fromC(src).run(new Uint8Array(0), {}, opts);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("`return <verdict>` is rejected — verdicts use `decide`", () => {
  const r = compile(`filter { return pass; }`);
  if (r.ok) throw new Error("expected `return pass` to be rejected");
  if (!JSON.stringify(r.errors).includes("decide")) throw new Error("error should point at `decide`: " + JSON.stringify(r.errors));
  // and `decide` with a non-verdict is rejected too
  const r2 = compile(`filter { decide frobnicate; }`);
  if (r2.ok) throw new Error("expected `decide frobnicate` to be rejected");
});

yeet.test("the blocking verdicts return their code", () => {
  eq(res(`filter { decide pass; }`).verdict, V.PASS, "pass");
  eq(res(`filter { decide drop("d"); }`).verdict, V.DROP, "drop");
  eq(res(`filter { decide ban("b", 60); }`).verdict, V.BAN, "ban");
  eq(res(`filter { decide rst("r", 0); }`).verdict, V.RST, "rst");
});

yeet.test("count is a tally, not a blocking verdict — it falls through to pass", () => {
  const { run, rules } = fromC(`filter { decide count("c"); }`);
  const r = run(new Uint8Array(0), {}, {});
  eq(r.verdict, V.PASS, "count -> pass");
  eq(rules[r.rule].name, "c", "count still records the rule");
});

yeet.test("the triggering rule name is recorded", () => {
  const { run, rules } = fromC(`filter { if (dport == 80) decide rst("crawler", 0); decide pass; }`);
  const r = run(new Uint8Array(0), {}, { dport: 80 });
  eq(r.verdict, V.RST, "rst");
  eq(rules[r.rule].name, "crawler", "rule name");
});

yeet.test("a filter with no matching rule falls through to pass", () => {
  eq(res(`filter { if (dport == 1) decide drop("x"); }`, { dport: 80 }).verdict, V.PASS, "implicit pass");
});

yeet.test("count(...) as a statement tallies and continues", () => {
  // The count statement does not stop the program — the later rst still fires.
  const r = res(`filter { count("seen"); decide rst("stop", 0); }`);
  eq(r.verdict, V.RST, "reached the rst after count()");
});

yeet.test("log(...) as a statement does not change the verdict", () => {
  eq(res(`filter { log(16); decide pass; }`).verdict, V.PASS, "log then pass");
  eq(res(`filter { if (dport == 80) { log(1); decide drop("d"); } decide pass; }`, { dport: 80 }).verdict, V.DROP, "log then drop");
});
