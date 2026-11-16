/* Build the distributable package into pkg/: the compiled BPF object and the
 * JavaScript bundled and minified — no sources, docs or examples.
 *
 *   make package                 (builds bin/vm.bpf.o first, passes the vendored esbuild)
 *   make package PKG_ROLLING=yes (a snapshot build: see the version below)
 *   node build/package.mjs <esbuild> [rolling]
 *   npm pack ./pkg               -> pfw-core-<version>.tgz
 *
 * pkg/
 *   package.json   name, version, gitHead (the commit it was built from), engines
 *                  and an exports map onto dist/
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

const [esbuild, mode] = process.argv.slice(2);
if (!esbuild) { console.error("usage: node build/package.mjs <esbuild> [rolling]"); process.exit(1); }
const rolling = mode === "rolling" || mode === "yes";
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

/* The commit the package is built from, recorded as `gitHead` (the field npm
 * itself writes on publish). A tree with uncommitted changes is not that commit,
 * so it gets no gitHead rather than a misleading one. */
const git = (...args) => { try { return execFileSync("git", args, { cwd: root, stdio: ["ignore", "pipe", "ignore"], env: { ...process.env, TZ: "UTC" } }).toString().trim(); } catch { return ""; } };
const head = git("rev-parse", "HEAD");
const gitHead = git("status", "--porcelain") === "" ? head : "";

/* A rolling build is a snapshot of master, versioned the way yeet's rolling
 * packages are (`<version>~git<date>.<sha>` there), in semver's spelling:
 *
 *   <version>-git<commit date, UTC, YYYYMMDDHHMMSS>.g<short sha>
 *
 * The date comes first, so versions order as the commits do — a fixed-width run
 * of digits compares the same as text or as time — and it is the commit's date,
 * not the build's, so rebuilding a commit gives the same version. As a
 * prerelease, every snapshot sorts below the final <version>. The `g` keeps an
 * all-digit hash from being read as a number, which semver rejects when it has
 * a leading zero. */
let version = src.version;
if (rolling) {
  const date = git("show", "-s", "--format=%cd", "--date=format-local:%Y%m%d%H%M%S", "HEAD");
  if (!/^\d{14}$/.test(date) || !head) { console.error("a rolling build needs git metadata (commit date and hash), and found none"); process.exit(1); }
  version = `${src.version}-git${date}.g${head.slice(0, 7)}`;
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
  version,
  ...(gitHead ? { gitHead } : {}),
  description: src.description,
  type: "module",
  engines: src.engines,
  exports,
  files: ["dist", "bin"],
}, null, 2) + "\n");

const size = (dir) => readdirSync(dir).reduce((n, f) => n + statSync(`${dir}/${f}`).size, 0);
console.log(`pkg/: ${readdirSync(`${out}/dist`).length} files in dist/ (${(size(`${out}/dist`) / 1024).toFixed(0)} kB), bin/vm.bpf.o (${(statSync(`${out}/bin/vm.bpf.o`).size / 1024).toFixed(0)} kB), version ${version}, commit ${gitHead ? gitHead.slice(0, 12) : "(uncommitted tree)"}`);
