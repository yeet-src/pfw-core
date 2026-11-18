/* pfw: shared base includes + shared macros for every module under bpf/vm/ and
 * bpf/include/. vmlinux.h and the libbpf headers are guarded, so including this
 * from every module is free after the first; it also makes each module
 * self-contained for the editor (clangd) rather than order-dependent.
 */
#ifndef PFW_COMMON_H
#define PFW_COMMON_H

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "pfw.h"
#include "core/macros.h"

/* Every cap that is masked (`x & (CAP - 1)`) must be a power of two, or the mask
 * silently reads the wrong slot. Check them all once, here, at compile time. */
PFW_ASSERT_POW2(SCAN_CAP);
PFW_ASSERT_POW2(REASM_CAP);
PFW_ASSERT_POW2(RING_CAP);
PFW_ASSERT_POW2(LOG_CAP);
PFW_ASSERT_POW2(TT_CELLS);
PFW_ASSERT_POW2(TT_STATES);
PFW_ASSERT_POW2(AC_STATES);
PFW_ASSERT_POW2(PFW_MAX_OPS);
PFW_ASSERT_POW2(PFW_MAX_PATS);
PFW_ASSERT_POW2(PFW_PAT_CAP);
PFW_ASSERT_POW2(NREGS);
PFW_ASSERT_POW2(TABLE_CELLS);
PFW_ASSERT_POW2(H2_CAP);
PFW_ASSERT_POW2(H2_DYN_SLOTS);
PFW_ASSERT_POW2(H2_ENT_CAP);

#endif /* PFW_COMMON_H */
