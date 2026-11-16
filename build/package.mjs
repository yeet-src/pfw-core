/* Build the distributable package into pkg/: the compiled BPF object and the
 * JavaScript bundled and minified — no sources, docs or examples.
 *
 *   make package                 (builds bin/vm.bpf.o first, passes the vendored esbuild)
 *   node build/package.mjs <esbuild> [version]
 *   npm pack ./pkg               -> pfw-core-<version>.tgz
 *
 * pkg/
 *   package.json   name, version, engines and an exports map onto dist/
 *   dist/*.js      one file per public entry point, plus shared chunks
 *   bin/vm.bpf.o   the once-verified VM
 *   README.md
 *
 * This is the only way the package is made: the repository's own package.json is
 * private and has no `files`, so `npm pack` at the root is not a second,
 * different package.
 *
 * Every public entry point is bundled in ONE esbuild run with code splitting, so
 * code two entry points share lands in a common chunk rather than being copied
 * into both: `pfw-core` and `pfw-core/asm` see the same classes and tables. The
 * entry files sit directly in dist/, which is what loader.js relies on to find
 * ../bin/vm.bpf.o. `yeet:*` (the loader's runtime) and `node:*` stay external. */
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";

const [esbuild, versionArg] = process.argv.slice(2);
if (!esbuild) { console.error("usage: node build/package.mjs <esbuild> [version]"); process.exit(1); }
const root = new URL("..", import.meta.url).pathname;
const src = JSON.parse(readFileSync(`${root}package.json`, "utf8"));
const out = `${root}pkg`;

if (!existsSync(`${root}bin/vm.bpf.o`)) { console.error("bin/vm.bpf.o is missing — run `make bpf` (or `make package`)"); process.exit(1); }

/* The public surface, from the repository's own exports map: each named subpath,
 * and every top-level module the `./*` wildcard reaches (pfw-core/isa.js, …). */
const entries = new Map();
for (const [sub, target] of Object.entries(src.exports)) {
  if (sub.includes("*")) continue;
  entries.set(sub === "." ? "index" : sub.slice(2), target);
}
for (const f of readdirSync(`${root}src`)) {
  if (!f.endsWith(".js") || !statSync(`${root}src/${f}`).isFile()) continue;
  const name = f.slice(0, -3);
  if (!entries.has(name)) entries.set(name, `./src/${f}`);
}

rmSync(out, { recursive: true, force: true });
mkdirSync(`${out}/bin`, { recursive: true });
execFileSync(esbuild, [
  ...[...entries].map(([name, target]) => `${name}=${target}`),
  "--bundle", "--splitting", "--format=esm", "--minify", "--platform=neutral", "--target=es2022",
  "--external:yeet:*", "--external:node:*",
  "--chunk-names=chunk-[hash]", `--outdir=${out}/dist`, "--log-level=warning",
], { cwd: root, stdio: "inherit" });

cpSync(`${root}bin/vm.bpf.o`, `${out}/bin/vm.bpf.o`);
cpSync(`${root}README.md`, `${out}/README.md`);

const exports = {};
for (const [sub] of Object.entries(src.exports)) {
  if (sub.includes("*")) continue;
  exports[sub] = `./dist/${sub === "." ? "index" : sub.slice(2)}.js`;
}
exports["./*"] = "./dist/*"; /* pfw-core/isa.js, pfw-core/interp.js, … */
writeFileSync(`${out}/package.json`, JSON.stringify({
  name: src.name,
  version: versionArg || src.version,
  description: src.description,
  type: "module",
  engines: src.engines,
  exports,
  files: ["dist", "bin"],
}, null, 2) + "\n");

const size = (dir) => readdirSync(dir).reduce((n, f) => n + statSync(`${dir}/${f}`).size, 0);
console.log(`pkg/: ${readdirSync(`${out}/dist`).length} files in dist/ (${(size(`${out}/dist`) / 1024).toFixed(0)} kB), bin/vm.bpf.o (${(statSync(`${out}/bin/vm.bpf.o`).size / 1024).toFixed(0)} kB), version ${versionArg || src.version}`);
