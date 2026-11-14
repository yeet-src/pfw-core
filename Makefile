# The eBPF backend of the pfw VM: the once-verified interpreter in bpf/vm/.
#
#   make bpf       compile bpf/*.bpf.c into bin/vm.bpf.o
#   make veristat  load it and let this kernel's verifier judge it (needs sudo)
#   make clean-bpf
#
# clang and bpftool come from the pinned static toolchain resolved by
# build/toolchain.mk, fetched once into a shared per-machine cache — the build
# needs no system C or BPF toolchain.

.DEFAULT_GOAL := bpf

include build/toolchain.mk
include build/bpf.mk

# Regenerate bpf/include/huff_table.h from the RFC 7541 table in src/huffman.js.
.PHONY: gen-huff
gen-huff:
	node src/huffman.js
