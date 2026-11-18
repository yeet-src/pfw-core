# The eBPF backend of the pfw VM: the once-verified interpreter in bpf/vm/.
#
#   make bpf       compile bpf/*.bpf.c into bin/vm.bpf.o
#   make veristat  load it and let this kernel's verifier judge it (needs sudo)
#   make package   pkg/: the compiled object + minified JS, ready for `npm pack`
#   make clean-bpf
#
# clang and bpftool come from the pinned static toolchain resolved by
# build/toolchain.mk, fetched once into a shared per-machine cache — the build
# needs no system C or BPF toolchain.

.DEFAULT_GOAL := bpf

include build/toolchain.mk
include build/bpf.mk

# Build the distributable package into pkg/: bin/vm.bpf.o plus the JavaScript
# bundled and minified (no sources). `npm pack ./pkg` makes the tarball the
# release publishes. PKG_ROLLING=yes makes it a snapshot build, versioned
# <version>-git<commit date>.g<sha> so snapshots order as the commits do and all
# sort below the final <version> (as yeet's rolling packages do).
PKG_ROLLING ?= no
.PHONY: package
package: bpf | toolchain
	node build/package.mjs "$(ESBUILD)" $(PKG_ROLLING)

# Regenerate bpf/include/huff_table.h from the RFC 7541 table in src/huffman/table.js.
.PHONY: gen-huff
gen-huff:
	node scripts/gen-huff.mjs
