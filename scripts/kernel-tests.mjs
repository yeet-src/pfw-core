/* Run every kernel test (test/kernel/*.mjs), one after another, and say which
 * passed. They load the VM and send real traffic over loopback, share its XDP
 * hook and a few ports, and so cannot run side by side.
 *
 *   node scripts/kernel-tests.mjs [name ...]     # e.g. reasm route
 *
 * Needs a built bin/vm.bpf.o (`make bpf`), yeetd, and the right to attach to
 * loopback. A test that fails is run once more before it counts: they wait on
 * real packets and timers, and a loaded machine can miss one. Exits non-zero if
 * any test failed twice.
 */
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";

const dir = new URL("../test/kernel/", import.meta.url);
const want = process.argv.slice(2);
const tests = readdirSync(dir).filter((f) => f.endsWith(".mjs")).map((f) => f.slice(0, -4)).filter((t) => !want.length || want.includes(t)).sort();
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
