/* pfw: small shared macros. Value macros only (no control flow), so they read
 * like what they replace and never hide a return. Included from core/common.h,
 * so every unit has them. */
#ifndef PFW_MACROS_H
#define PFW_MACROS_H

/* Power-of-two index mask — the form the verifier needs to prove a buffer index
 * is in range. Using it everywhere makes the mask impossible to forget (forget
 * it and the program is rejected or reads out of bounds) and names the
 * invariant. The cap must be a power of two; PFW_ASSERT_POW2 (below, applied in
 * common.h) checks every masked cap at compile time. */
#define PFW_MASK(i, cap) ((i) & ((cap) - 1))

/* Clamp to a cap / min. The callers these replace already reference the value
 * twice (they were `x > cap ? cap : x`), so there is no new double-evaluation. */
#define PFW_MIN(a, b)     ((a) < (b) ? (a) : (b))
#define PFW_CLAMP(n, cap) ((n) > (cap) ? (cap) : (n))

/* Point the program's view at a decoded buffer [0, len): the reset every decode
 * stage does before tail-calling the matcher. */
#define PFW_SET_VIEW(st, len) do {                 \
    (st)->r[R_PAYLOAD] = 0; (st)->r[R_CUR] = 0;    \
    (st)->r[R_END] = (len); (st)->r[R_LEN] = (len);\
} while (0)

/* Compile-time check that a masked cap is a power of two. */
#define PFW_ASSERT_POW2(x) _Static_assert(((x) & ((x) - 1)) == 0, #x " must be a power of two (it is masked)")

/* Global-function argument tags (libbpf). Define them if this libbpf lacks them,
 * so the cross-unit functions (parse, send_rst) build on an older toolchain. */
#ifndef __arg_ctx
#define __arg_ctx __attribute__((btf_decl_tag("arg:ctx")))
#endif
#ifndef __arg_nonnull
#define __arg_nonnull __attribute__((btf_decl_tag("arg:nonnull")))
#endif

#endif /* PFW_MACROS_H */
