/* Run every kernel test (test/kernel/*.mjs), one after another, and say which
 * passed. They load the VM and send real traffic over loopback, share its XDP
 * hook and a few ports, and so cannot run side by side.
 *
 *   node scripts/kernel-tests.mjs [name ...]     # e.g. reasm route
 *   node scripts/kernel-tests.mjs --shard 2/6    # the second of six equal parts
 *   node scripts/kernel-tests.mjs --shard 2/6 --list   # name them, run nothing
 *
 * --shard i/n is for CI, where each part gets a machine (and so a loopback) of
 * its own: every loader start costs about half a minute on a GitHub runner, and
 * the whole set in a row is an hour. The parts are balanced by how long each
 * test took there (SECS below), longest first into whichever part is lightest,
 * so every shard computes the same split.
 *
 * Needs a built bin/vm.bpf.o (`make bpf`), yeetd, and the right to attach to
 * loopback. A test that fails is run once more before it counts: they wait on
 * real packets and timers, and a loaded machine can miss one. Exits non-zero if
 * any test failed twice.
 */
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";

const dir = new URL("../test/kernel/", import.meta.url);
/* Seconds each test took on a GitHub runner, for balancing shards only: a test
 * that is not listed is taken to be an average one. */
const SECS = {
  lang: 800, diff: 345, examples: 200, rewrite: 165, counters: 155, lpm: 137, source: 137, "regex-rewrite": 132,
  regex: 118, counts: 104, lpm6: 104, kstr: 101, rate: 100, route: 98, loader: 90, reasm: 79, h2: 70,
};
const AVERAGE = 60;

const argv = process.argv.slice(2);
const flag = (name) => { const i = argv.indexOf(name); return i < 0 ? null : argv.splice(i, name === "--list" ? 1 : 2).at(-1); };
const list = flag("--list") !== null;
const shard = flag("--shard");
const want = argv;

function shardOf(names, spec) {
  const m = /^(\d+)\/(\d+)$/.exec(spec ?? "");
  const [index, count] = m ? [Number(m[1]), Number(m[2])] : [0, 0];
  if (!m || index < 1 || index > count) { console.log(`--shard wants i/n with 1 <= i <= n, not "${spec}"`); process.exit(2); }
  const secs = (t) => SECS[t] ?? AVERAGE;
  const parts = Array.from({ length: count }, () => ({ load: 0, names: [] }));
  for (const t of [...names].sort((a, b) => secs(b) - secs(a) || a.localeCompare(b))) {
    const part = parts.reduce((least, p) => (p.load < least.load ? p : least));
    part.load += secs(t); part.names.push(t);
  }
  return parts[index - 1].names.sort();
}

const all = readdirSync(dir).filter((f) => f.endsWith(".mjs")).map((f) => f.slice(0, -4)).filter((t) => !want.length || want.includes(t)).sort();
const tests = shard === null ? all : shardOf(all, shard);
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
