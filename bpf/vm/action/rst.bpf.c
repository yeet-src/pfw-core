/* pfw: send_rst as a real cross-unit BPF function (not an inlined helper).
 *
 * It is self-contained — its own packet bounds checks, no maps or globals — so it
 * verifies as a standalone global function and the BPF linker resolves every
 * caller to this one copy, instead of inlining the ~60-line RST builder into all
 * six programs. __arg_ctx tells the verifier the first argument is the XDP
 * context pointer (needed for a global function that takes ctx). */
#include "core/common.h"
#include "parse/parse.h"

static __always_inline __u16 csum_fold(__u32 sum)
{
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16) ~sum;
}

__attribute__((used))
int send_rst(struct xdp_md *ctx __arg_ctx, __u32 l2)
{
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    if (l2) {
        if (data + 14 > data_end)
            return XDP_DROP;
        __u8 *eth = data;
        __u8 mac[6];
        __builtin_memcpy(mac, eth + 6, 6);
        __builtin_memcpy(eth + 6, eth, 6);
        __builtin_memcpy(eth, mac, 6);
    }
    struct pkt_ip4 *ip = data + (l2 ? 14 : 0);
    if ((void *) (ip + 1) > data_end)
        return XDP_DROP;
    if (ip->vihl != 0x45)
        return XDP_DROP;
    struct pkt_tcp *tcp = (void *) (ip + 1);
    if ((void *) (tcp + 1) > data_end)
        return XDP_DROP;

    __u32 rst_seq = bpf_ntohl(tcp->ack_seq);
    __u32 tip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tip;
    __u16 tpt = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tpt;
    tcp->seq = bpf_htonl(rst_seq);
    tcp->ack_seq = 0;
    tcp->doff_res = 5 << 4;
    tcp->flags = 0x04; /* RST */
    tcp->window = 0;
    tcp->urg_ptr = 0;

    ip->tot_len = bpf_htons(40);
    ip->ttl = 64;
    ip->frag_off = 0;
    ip->check = 0;
    __u32 s = 0;
    __u16 *ipw = (__u16 *) ip;
#pragma unroll
    for (int i = 0; i < 10; i++)
        s += ipw[i];
    ip->check = csum_fold(s);

    __u32 t = 0;
    __u16 *sw = (__u16 *) &ip->saddr;
    __u16 *dw = (__u16 *) &ip->daddr;
    t += sw[0]; t += sw[1];
    t += dw[0]; t += dw[1];
    t += bpf_htons(IPPROTO_TCP);
    t += bpf_htons(20);
    tcp->check = 0;
    __u16 *tw = (__u16 *) tcp;
#pragma unroll
    for (int i = 0; i < 10; i++)
        t += tw[i];
    tcp->check = csum_fold(t);
    return XDP_TX;
}
