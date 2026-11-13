/* pfw: shared base includes for every pfw_*.h module.
 *
 * The interpreter is split across bpf/include/pfw_*.h headers, one responsibility
 * each, all `static __always_inline`. The single translation unit (bpf/pfw.bpf.c)
 * includes them, so everything inlines exactly as it did when this was one file —
 * the verifier sees byte-identical code. Modular source, same verified object.
 *
 * vmlinux.h and the libbpf headers are guarded, so including this from every
 * module is free after the first; it also makes each module self-contained for
 * the editor (clangd) rather than order-dependent.
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

#endif /* PFW_COMMON_H */
