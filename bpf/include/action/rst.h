/* pfw: the RST — rewrite the frame in place into a header-only TCP reset aimed
 * back at the sender (IPv4, no IP options) and return XDP_TX.
 *
 * Unlike the other machinery, send_rst is a real cross-unit BPF function, not an
 * inlined helper: it is self-contained (its own packet bounds checks, touches no
 * maps or globals), so it verifies in isolation and is linked ONCE instead of
 * inlined into every program that resets. Defined in bpf/vm/action/rst.bpf.c. */
#ifndef PFW_RST_H
#define PFW_RST_H

#include "core/common.h"

int send_rst(struct xdp_md *ctx, __u32 l2);

#endif /* PFW_RST_H */
