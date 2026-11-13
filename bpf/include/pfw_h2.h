/* pfw: HTTP/2 HEADERS/HPACK decode (DECODE_H2). Split into simple passes, each a
 * small bpf_loop callback, so neither explodes the verifier's state budget (one
 * combined state machine does). Pass 1 (h2_scan) walks frames to the first
 * complete HEADERS block; pass 2 (h2_hp) HPACK-decodes it into a compact
 * intermediate in st->dec; the resolve pass (h2_resolve) expands that to
 * "name: value\n" lines, resolving static-table names. Indexed and literal
 * fields with raw strings are decoded; Huffman strings, dynamic-table references
 * and CONTINUATION fail closed (reset). */
#ifndef PFW_H2_H
#define PFW_H2_H

#include "pfw_common.h"
#include "pfw_maps.h"

/* Pass 1: locate the first HEADERS block. */
struct h2_scan { struct flow *f; __u32 rlen, phase, pre; __u8 fh[16]; __u32 fhn, frame_rem, hb_off, hb_len, done, cont; };
static long h2_scan_step(__u32 i, void *ctx_)
{
    struct h2_scan *c = ctx_;
    if (i >= c->rlen || c->done)
        return 1;
    __u8 b = c->f->reasm[i & (REASM_CAP - 1)];
    switch (c->phase) {
    case 0: /* preface */
        if (c->pre) c->pre--;
        if (!c->pre) { c->phase = 1; c->fhn = 0; }
        return 0;
    case 1: /* frame header */
        c->fh[c->fhn & 15] = b; c->fhn++;
        if (c->fhn >= 9) {
            __u32 len = ((__u32) c->fh[0] << 16) | ((__u32) c->fh[1] << 8) | c->fh[2];
            __u8 type = c->fh[3], flags = c->fh[4];
            c->frame_rem = len;
            if (type == 0x1) {
                if (!(flags & 0x4)) { c->cont = 1; c->done = 1; return 1; } /* CONTINUATION: fail closed */
                c->hb_off = i + 1; c->hb_len = len; c->done = 1; return 1;
            }
            c->phase = len ? 2 : 1;
            if (!len) c->fhn = 0;
        }
        return 0;
    default: /* skip non-HEADERS payload */
        if (c->frame_rem) c->frame_rem--;
        if (!c->frame_rem) { c->phase = 1; c->fhn = 0; }
        return 0;
    }
}

/* Pass 2: HPACK walk. Emits a compact intermediate into st->dec that the
 * resolve stage expands: per field a marker byte, then length-prefixed strings.
 * Marker 0x80|idx = fully indexed (static name+value, no strings); marker ni
 * (0..61) = literal: ni>0 indexed name + 1 value string, ni==0 literal name +
 * value (2 strings), each string as [len_lo][len_hi][bytes]. */
struct h2_hp { struct flow *f; struct pfw_state *st; __u32 start, len, phase, strings_left, slen_val, slen_m, slen_cont, str_rem, decpos, fail; };
static __always_inline void h2_hp_emit(struct h2_hp *c, __u8 v) { if (c->decpos < REASM_CAP) c->st->dec[c->decpos++ & (REASM_CAP - 1)] = v; }
static __always_inline void h2_hp_strdone(struct h2_hp *c) { if (c->strings_left) c->strings_left--; c->phase = c->strings_left ? 1 : 0; c->slen_cont = 0; }
static __always_inline void h2_hp_emitlen(struct h2_hp *c, __u32 len) { if (len > REASM_CAP) len = REASM_CAP; h2_hp_emit(c, len & 0xff); h2_hp_emit(c, (len >> 8) & 0xff); c->str_rem = len; c->phase = 2; if (!len) h2_hp_strdone(c); }
static long h2_hp_step(__u32 j, void *ctx_)
{
    struct h2_hp *c = ctx_;
    if (j >= c->len || c->fail) return 1;
    __u8 b = c->f->reasm[(c->start + j) & (REASM_CAP - 1)];
    switch (c->phase) {
    case 0: /* field start -> marker */
        if (b & 0x80) { __u32 idx = b & 0x7f; if (idx == 0 || idx >= 62) { c->fail = 1; return 1; } h2_hp_emit(c, 0x80 | idx); return 0; }
        if (b & 0x40) { __u32 ni = b & 0x3f; if (ni >= 62) { c->fail = 1; return 1; } h2_hp_emit(c, ni); c->strings_left = ni == 0 ? 2 : 1; c->phase = 1; c->slen_cont = 0; return 0; }
        if (b & 0x20) { if ((b & 0x1f) == 0x1f) { c->fail = 1; return 1; } return 0; }
        { __u32 ni = b & 0x0f; if (ni >= 15) { c->fail = 1; return 1; } h2_hp_emit(c, ni); c->strings_left = ni == 0 ? 2 : 1; c->phase = 1; c->slen_cont = 0; }
        return 0;
    case 1: /* string length */
        if (!c->slen_cont) {
            if (b & 0x80) { c->fail = 1; return 1; }
            c->slen_val = b & 0x7f;
            if (c->slen_val < 0x7f) { h2_hp_emitlen(c, c->slen_val); return 0; }
            c->slen_cont = 1; c->slen_m = 0; return 0;
        }
        c->slen_val += (__u32) (b & 0x7f) << c->slen_m; c->slen_m += 7;
        if (!(b & 0x80)) h2_hp_emitlen(c, c->slen_val);
        if (c->slen_m > 28) { c->fail = 1; return 1; }
        return 0;
    default: /* copy string bytes */
        h2_hp_emit(c, b);
        if (c->str_rem) c->str_rem--;
        if (c->str_rem == 0) h2_hp_strdone(c);
        return 0;
    }
}

static __always_inline int h2_decode(struct flow *f, struct pfw_state *st, __u32 rlen)
{
    if (rlen < H2_PREFACE_LEN) { st->dec_len = 0; return 0; }     /* not enough yet: wait */
    struct h2_scan sc = { .f = f, .rlen = rlen, .phase = 0, .pre = H2_PREFACE_LEN };
    bpf_loop(rlen, h2_scan_step, &sc, 0);
    if (sc.cont)
        return 1;                                                 /* CONTINUATION: fail closed */
    if (!sc.done || sc.hb_len == 0) { st->dec_len = 0; return 0; } /* no complete HEADERS block yet */
    struct h2_hp hp = { .f = f, .st = st, .start = sc.hb_off, .len = sc.hb_len > REASM_CAP ? REASM_CAP : sc.hb_len, .phase = 0 };
    bpf_loop(hp.len, h2_hp_step, &hp, 0);
    if (hp.fail)
        return 1;
    st->dec_len = hp.decpos > REASM_CAP ? REASM_CAP : hp.decpos;
    return 0;
}

/* HPACK static table (RFC 7541 Appendix A) for h2 header-name resolution. */
static const char h2_nblob[1024] = "\x3a\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x3a\x6d\x65\x74\x68\x6f\x64\x3a\x70\x61\x74\x68\x3a\x73\x63\x68\x65\x6d\x65\x3a\x73\x74\x61\x74\x75\x73\x61\x63\x63\x65\x70\x74\x2d\x63\x68\x61\x72\x73\x65\x74\x61\x63\x63\x65\x70\x74\x2d\x65\x6e\x63\x6f\x64\x69\x6e\x67\x61\x63\x63\x65\x70\x74\x2d\x6c\x61\x6e\x67\x75\x61\x67\x65\x61\x63\x63\x65\x70\x74\x2d\x72\x61\x6e\x67\x65\x73\x61\x63\x63\x65\x70\x74\x61\x63\x63\x65\x73\x73\x2d\x63\x6f\x6e\x74\x72\x6f\x6c\x2d\x61\x6c\x6c\x6f\x77\x2d\x6f\x72\x69\x67\x69\x6e\x61\x67\x65\x61\x6c\x6c\x6f\x77\x61\x75\x74\x68\x6f\x72\x69\x7a\x61\x74\x69\x6f\x6e\x63\x61\x63\x68\x65\x2d\x63\x6f\x6e\x74\x72\x6f\x6c\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x64\x69\x73\x70\x6f\x73\x69\x74\x69\x6f\x6e\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x65\x6e\x63\x6f\x64\x69\x6e\x67\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x61\x6e\x67\x75\x61\x67\x65\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67\x74\x68\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x72\x61\x6e\x67\x65\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x74\x79\x70\x65\x63\x6f\x6f\x6b\x69\x65\x64\x61\x74\x65\x65\x74\x61\x67\x65\x78\x70\x65\x63\x74\x65\x78\x70\x69\x72\x65\x73\x66\x72\x6f\x6d\x68\x6f\x73\x74\x69\x66\x2d\x6d\x61\x74\x63\x68\x69\x66\x2d\x6d\x6f\x64\x69\x66\x69\x65\x64\x2d\x73\x69\x6e\x63\x65\x69\x66\x2d\x6e\x6f\x6e\x65\x2d\x6d\x61\x74\x63\x68\x69\x66\x2d\x72\x61\x6e\x67\x65\x69\x66\x2d\x75\x6e\x6d\x6f\x64\x69\x66\x69\x65\x64\x2d\x73\x69\x6e\x63\x65\x6c\x61\x73\x74\x2d\x6d\x6f\x64\x69\x66\x69\x65\x64\x6c\x69\x6e\x6b\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x6d\x61\x78\x2d\x66\x6f\x72\x77\x61\x72\x64\x73\x70\x72\x6f\x78\x79\x2d\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x65\x70\x72\x6f\x78\x79\x2d\x61\x75\x74\x68\x6f\x72\x69\x7a\x61\x74\x69\x6f\x6e\x72\x61\x6e\x67\x65\x72\x65\x66\x65\x72\x65\x72\x72\x65\x66\x72\x65\x73\x68\x72\x65\x74\x72\x79\x2d\x61\x66\x74\x65\x72\x73\x65\x72\x76\x65\x72\x73\x65\x74\x2d\x63\x6f\x6f\x6b\x69\x65\x73\x74\x72\x69\x63\x74\x2d\x74\x72\x61\x6e\x73\x70\x6f\x72\x74\x2d\x73\x65\x63\x75\x72\x69\x74\x79\x74\x72\x61\x6e\x73\x66\x65\x72\x2d\x65\x6e\x63\x6f\x64\x69\x6e\x67\x75\x73\x65\x72\x2d\x61\x67\x65\x6e\x74\x76\x61\x72\x79\x76\x69\x61\x77\x77\x77\x2d\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
static const char h2_vblob[64] = "\x47\x45\x54\x50\x4f\x53\x54\x2f\x2f\x69\x6e\x64\x65\x78\x2e\x68\x74\x6d\x6c\x68\x74\x74\x70\x68\x74\x74\x70\x73\x32\x30\x30\x32\x30\x34\x32\x30\x36\x33\x30\x34\x34\x30\x30\x34\x30\x34\x35\x30\x30\x67\x7a\x69\x70\x2c\x20\x64\x65\x66\x6c\x61\x74\x65\x00\x00";
static const __u16 h2_noff[62] = {0,0,10,10,17,17,22,22,29,29,29,29,29,29,29,36,50,65,80,93,99,126,129,134,147,160,179,195,211,225,241,254,266,272,276,280,286,293,297,301,309,326,339,347,366,379,383,391,403,421,440,445,452,459,470,476,486,511,528,538,542,545};
static const __u8  h2_nlen[62] = {0,10,7,7,5,5,7,7,7,7,7,7,7,7,7,14,15,15,13,6,27,3,5,13,13,19,16,16,14,16,13,12,6,4,4,6,7,4,4,8,17,13,8,19,13,4,8,12,18,19,5,7,7,11,6,10,25,17,10,4,3,16};
static const __u16 h2_voff[62] = {0,0,0,3,7,8,19,23,28,31,34,37,40,43,46,0,49,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static const __u8  h2_vlen[62] = {0,0,3,4,1,11,4,5,3,3,3,3,3,3,3,0,13,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

/* ---- h2 name-resolution pass (DECODE_H2) -------------------------------- *
 * Walks the HPACK intermediate in st->dec and expands each field to
 * "name: value\n" into the flow buffer, resolving static-table names. Its own
 * tail-call program: name emit + the HPACK walk together exceed the budget. */
struct h2_rs { struct flow *f; struct pfw_state *st; __u32 len, phase, strings_left, slo, str_rem, outpos, fail; };
static __always_inline void rs_emit(struct h2_rs *c, __u8 v) { if (c->outpos < REASM_CAP) c->f->reasm[c->outpos++ & (REASM_CAP - 1)] = v; }
struct rs_ne { struct h2_rs *c; __u32 off, len; };
static long rs_nblob_step(__u32 k, void *x) { struct rs_ne *e = x; if (k >= e->len) return 1; rs_emit(e->c, h2_nblob[(e->off + k) & 1023]); return 0; }
static long rs_vblob_step(__u32 k, void *x) { struct rs_ne *e = x; if (k >= e->len) return 1; rs_emit(e->c, h2_vblob[(e->off + k) & 63]); return 0; }
static __always_inline void rs_name(struct h2_rs *c, __u32 idx) { __u32 i = idx & 63; struct rs_ne e = { .c = c, .off = h2_noff[i], .len = h2_nlen[i] }; bpf_loop(28, rs_nblob_step, &e, 0); rs_emit(c, ':'); rs_emit(c, ' '); }
static __always_inline void rs_val(struct h2_rs *c, __u32 idx) { __u32 i = idx & 63; struct rs_ne e = { .c = c, .off = h2_voff[i], .len = h2_vlen[i] }; bpf_loop(16, rs_vblob_step, &e, 0); }
static __always_inline void rs_strdone(struct h2_rs *c) { if (c->strings_left) c->strings_left--; if (c->strings_left) { rs_emit(c, ':'); rs_emit(c, ' '); c->phase = 1; } else { rs_emit(c, '\n'); c->phase = 0; } }
static long h2_resolve_step(__u32 i, void *x)
{
    struct h2_rs *c = x;
    if (i >= c->len || c->fail) return 1;
    __u8 b = c->st->dec[i & (REASM_CAP - 1)];
    switch (c->phase) {
    case 0: /* marker */
        if (b & 0x80) { __u32 idx = b & 0x7f; rs_name(c, idx); rs_val(c, idx); rs_emit(c, '\n'); return 0; }
        c->strings_left = b == 0 ? 2 : 1;
        if (b) rs_name(c, b);
        c->phase = 1; return 0;
    case 1: c->slo = b; c->phase = 2; return 0;                     /* length low */
    case 2: { __u32 len = c->slo | ((__u32) b << 8); c->str_rem = len > REASM_CAP ? REASM_CAP : len; c->phase = 3; if (!c->str_rem) rs_strdone(c); } return 0; /* length high */
    default: rs_emit(c, b); if (c->str_rem) c->str_rem--; if (c->str_rem == 0) rs_strdone(c); return 0; /* copy */
    }
}

#endif /* PFW_H2_H */
