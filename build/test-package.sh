#!/bin/sh
# Check a built tarball the way a consumer meets it: install it into an empty
# project and run the host test suites against the INSTALLED package — the
# bundled, minified JavaScript — instead of against src/.
#
#   sh build/test-package.sh <pfw-core.tgz>
#
# The suites import the library as `#/asm`, `#/isa.js`, …; here those names are
# mapped onto the package's public entry points (`pfw-core/asm`, …), so every
# test goes through the same exports map a consumer uses. Needs `yeet` for the
# test runner.

set -eu

TGZ="${1:?usage: test-package.sh <tarball>}"
case "$TGZ" in /*) ;; *) TGZ="$PWD/$TGZ" ;; esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# What ships: the object and the bundle, and nothing of the sources.
LIST="$(mktemp)"
tar tzf "$TGZ" > "$LIST"
grep -qx 'package/bin/vm.bpf.o' "$LIST" || { echo "error: the tarball has no bin/vm.bpf.o" >&2; exit 1; }
grep -qx 'package/dist/index.js' "$LIST" || { echo "error: the tarball has no dist/index.js" >&2; exit 1; }
if grep -qE '^package/(src|bpf|test|docs|examples|contrib|build)/' "$LIST"; then
	echo "error: the tarball ships sources:" >&2
	grep -E '^package/(src|bpf|test|docs|examples|contrib|build)/' "$LIST" | head >&2
	exit 1
fi
echo ">> $(grep -c '' "$LIST") files, $(du -k "$TGZ" | cut -f1) kB packed"

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR" "$LIST"' EXIT
cd "$DIR"
cat > package.json <<'JSON'
{
  "name": "pfw-core-consumer",
  "private": true,
  "type": "module",
  "imports": {
    "#/asm": "pfw-core/asm",
    "#/builder": "pfw-core/builder",
    "#/bytes": "pfw-core/bytes",
    "#/clang": "pfw-core/clang",
    "#/huffman": "pfw-core/huffman",
    "#/program": "pfw-core/program",
    "#/*": "pfw-core/*"
  }
}
JSON
npm install --silent "$TGZ"
node --check node_modules/pfw-core/dist/loader.js   # imports yeet:bpf, so it is only parsed here

mkdir test
cp -r "$ROOT/test/isa" "$ROOT/test/unit" test/
echo ">> the ISA vectors and the unit suites, against the installed package"
yeet test test/isa
yeet test test/unit
