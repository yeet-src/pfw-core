/* Run every kernel test (test/kernel/*.mjs), one after another, and say which
 * passed. They load the VM and send real traffic over loopback, share its XDP
 * hook and a few ports, and so cannot run side by side.
 *
 *   node scripts/kernel-tests.mjs [name ...]     # e.g. reasm route
 *   node scripts/kernel-tests.mjs --group streams        # one category (GROUPS below)
 *   node scripts/kernel-tests.mjs --group streams --list # name its tests, run nothing
 *
 * --group is for CI, where each category gets a machine (and so a loopback) of
 * its own: every loader start costs about half a minute on a GitHub runner, and
 * the whole set in a row is an hour. Every test belongs to exactly one group,
 * and any run fails until it does, so a new test cannot go unrun there. A new
 * group also needs adding to the matrix in .github/workflows/test.yml.
 *
 * Needs a built bin/vm.bpf.o (`make bpf`), yeetd, and the right to attach to
 * loopback. A test that fails is run once more before it counts: they wait on
 * real packets and timers, and a loaded machine can miss one. Exits non-zero if
 * any test failed twice.
 */
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";

const dir = new URL("../test/kernel/", import.meta.url);
/* By what is under test. Sized so that no group is much longer than `language`,
 * which is one test and the longest. */
const GROUPS = {
  language: ["lang"],
  matching: ["bloom", "diff", "hash", "lpm", "lpm6", "regex"],
  rewrite: ["dnat", "nat", "redirect", "regex-rewrite", "rewrite"],
  streams: ["examples", "h2", "midjoin", "reasm"],
  state: ["counters", "counts", "rate", "source"],
  host: ["argv", "knob", "kstr", "loader", "route", "shadow"],
  machine: ["args", "call", "console", "mpos", "printk", "stack"],
};

const argv = process.argv.slice(2);
const flag = (name, takesValue) => { const i = argv.indexOf(name); return i < 0 ? null : argv.splice(i, takesValue ? 2 : 1).at(-1); };
const list = flag("--list", false) !== null;
const group = flag("--group", true);
const want = argv;

const every = readdirSync(dir).filter((f) => f.endsWith(".mjs")).map((f) => f.slice(0, -4)).sort();
const grouped = Object.values(GROUPS).flat();
const problems = [
  ...every.filter((t) => !grouped.includes(t)).map((t) => `${t} is in no group`),
  ...grouped.filter((t) => !every.includes(t)).map((t) => `${t} is grouped but test/kernel/${t}.mjs does not exist`),
  ...grouped.filter((t, i) => grouped.indexOf(t) !== i).map((t) => `${t} is in two groups`),
];
if (problems.length) { console.log(`GROUPS in scripts/kernel-tests.mjs: ${problems.join("; ")}`); process.exit(2); }
if (group !== null && !GROUPS[group]) { console.log(`--group wants one of ${Object.keys(GROUPS).join(", ")}, not "${group}"`); process.exit(2); }

const tests = (group === null ? every : [...GROUPS[group]].sort()).filter((t) => !want.length || want.includes(t));
if (list) { console.log(tests.join("\n")); process.exit(0); }
if (!tests.length) { console.log("no kernel tests match"); process.exit(1); }

const run = (name) => {
  const started = Date.now();
  const r = spawnSync(process.execPath, [new URL(`${name}.mjs`, dir).pathname], { encoding: "utf8", timeout: 600_000 });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  return { ok: r.status === 0, out, secs: Math.round((Date.now() - started) / 1000), last: out.trim().split("\n").at(-1) ?? "" };
};

const failed = [];
for (const name of tests) {
  let r = run(name), retried = false;
  if (!r.ok) { retried = true; r = run(name); }
  console.log(`${r.ok ? "ok  " : "FAIL"} ${name} (${r.secs}s${retried ? ", second run" : ""}) ${r.last}`);
  if (!r.ok) { failed.push(name); console.log(r.out.split("\n").map((l) => "     " + l).join("\n")); }
}
console.log(`\n${tests.length - failed.length}/${tests.length} kernel tests passed${failed.length ? `; failed: ${failed.join(", ")}` : ""}`);
process.exit(failed.length ? 1 : 0);
