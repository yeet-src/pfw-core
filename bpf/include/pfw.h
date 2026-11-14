/* pfw: the ISA, the program layout and the event — shared with the
 * host, which writes programs and automata into the maps and reads
 * events and counters out. docs/isa.md is the contract; this is it in C.
 */
#ifndef PFW_H
#define PFW_H

#define PFW_MAX_OPS  8192 /* instructions per program */
#define PFW_MAX_PATS 64   /* patterns per program: one bit each in %m */
#define PFW_PAT_CAP  64   /* bytes per pattern */
#define LPM_MAX      4096 /* max prefixes in the `src in set` CIDR trie (lpm) */
#define LPM6_MAX     4096 /* max prefixes in the `src6 in set6` IPv6 CIDR trie (lpm6) */
#define HASH_MAX     16384 /* max keys in the `x in hash` exact set (hashset) */
#define BLOOM_MAX    65536 /* capacity of the `x in bloom` probabilistic set (bloom) */
#define BLOOM_HASHES 5     /* hash functions for the bloom filter (map_extra) */
#define RE_STATES    1024 /* max states in the regex DFA (re_goto/re_accept); a power of two */
#define PFW_ARGC     16   /* runtime scalar args a program can read (OP_ARG / OP_ARGC) */
#define FARGS_MAX    4    /* numeric format args a console()/printk() call can carry */
#define FSTR_MAX     2    /* %s string args a call can carry */
#define STRARG_CAP   256  /* bytes captured per %s arg (power of two) */
#define PFW_FMTS     8    /* printk format strings a program can hold (in-kernel, for bpf_trace_printk) */
#define PFW_FMT_CAP  64   /* bytes per printk format string */
#define RL_SCALE     1000000ULL /* OP_RATE fixed-point: tokens are stored x1e6 for sub-token precision */
#define RW_MAX       4    /* redact/replace requests a program may record per packet,
                            * applied by the pfw_rewrite tail-call stage. A power of
                            * two: the index is masked. */
#define PFW_NRULES   64   /* rule ids: counters[rule] */
#define PFW_GENS     2    /* program generations: apply writes the idle one, then flips */
#define AC_STATES    4096 /* automaton states per generation */
#define AC_MAX_FAIL  16   /* failure-link hops resolved per byte */
#define SCAN_CAP     2048 /* bytes one scan / findb may cover; a power of two */
#define LOG_CAP      256  /* bytes a log carries into the event */
#define RING_CAP     16   /* per-flow ring entries (P3); a power of two */
#define REASM_CAP    2048 /* per-flow reassembly buffer; <= SCAN_CAP so the whole
                           * reassembled head fits the interpreter's window. */
#define MAX_FLOWS    16384 /* lower than before: each flow now carries a REASM_CAP
                            * reassembly buffer, so the table trades count for depth. */
/* L7 decode front-ends (pfw_prog.decode): normalize the reassembled stream to
 * a plaintext view the matching ISA scans. Slice 1 covers HTTP/2 HEADERS with
 * HPACK indexed/literal fields; Huffman strings, the dynamic table and
 * CONTINUATION fail closed (reset) and are later slices. */
#define DECODE_NONE  0
#define DECODE_H2    1
#define DECODE_HUFFMAN 2  /* HPACK-Huffman-decode via the baked const table (huff_table.h) */
#define DECODE_TRANSFORM 3 /* decode via a host-LOADED table (tt_cells), chosen by
                            * pfw_prog.transform_table — the general P2 transform */

/* Transform tables: a nibble state machine, state × nibble -> decoded output.
 * The host builds a table from a spec (src/huffman.js builds the HPACK Huffman
 * one from RFC 7541) and either bakes it into bpf/include/huff_table.h (read as
 * a const by pfw_huff) or loads it into the tt_cells map (read by pfw_transform,
 * so a new decoding is data, no kernel change). A cell is one u32. This is P2 of
 * docs/primitives.md: a decoding is data, not kernel code. */
#define TT_STATES    256              /* states in a nibble machine */
#define TT_CELLS     (TT_STATES * 16) /* 4096 cells per table, a power of two */
#define TT_NTABLES   8                /* loadable tt_cells tables */
#define TT_NEXT      0x1ffu           /* cell bits 0..8: next state */
#define TT_EMIT      (1u << 9)        /* this transition completes a symbol */
#define TT_ACCEPT    (1u << 10)       /* next state is a valid end-of-input boundary */
#define TT_FAIL      (1u << 11)       /* input walked off the code tree (or hit EOS) */
#define TT_SYM_SHIFT 16               /* cell bits 16..23: the emitted byte */
#define H2_PREFACE   "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_PREFACE_LEN 24
#define H2_MAX_FRAMES 8    /* frames walked per decode pass */
#define DECIDE_BUCKETS 16 /* decision-time histogram buckets; a power of two */
/* Upper bounds (ns, exclusive) of the first DECIDE_BUCKETS - 1 buckets,
 * the last bucket being +inf: log-spaced at a ratio of 2^(2/3) from 63 ns
 * to 40.6 µs, so every other bound is a round doubling (100, 400, 1600 ...).
 * An X-macro, so the kernel compares against immediates and keeps no
 * table on its 512-byte stack. NS_BOUNDS in app/lib/pfw/metrics.js
 * mirrors this list; change both or neither. */
#define DECIDE_BOUNDS(X) \
    X(63) X(100) X(159) X(252) X(400) X(635) X(1008) X(1600) \
    X(2540) X(4032) X(6400) X(10159) X(16127) X(25600) X(40637)

/* The register file, as `mov %REG, %cur` names it. */
enum pfw_reg {
    R_FRAME = 0, /* offset 0 of the frame */
    R_L3,        /* the IP header */
    R_L4,        /* the TCP or UDP header */
    R_PAYLOAD,   /* first byte after L4 */
    R_END,       /* one past the last readable byte */
    R_PROTO,     /* IPPROTO_* */
    R_SPORT,
    R_DPORT,
    R_S0, R_S1, R_S2, R_S3, /* scratch */
    R_M,         /* match mask */
    R_CUR,       /* the cursor */
    R_IFINDEX,
    R_LEN,       /* bytes of payload */
    R_S4, R_S5, R_S6, R_S7, /* more scratch, for `let` locals */
    R_SADDR,     /* IPv4 source address, host byte order (0 for IPv6) */
    R_SHADOW,    /* the shadow-mode flag (set from the host), readable as %shadow */
    /* The file is padded to a power of two: pfw_step bounds the index
     * with `& (NREGS - 1)`, which is only a modulo when NREGS is one.
     * (At 20 the mask was 0b10011 and %dport read as %payload.) */
    NREGS = 32,
};

enum pfw_opcode {
    OP_END = 0,
    OP_MOV_RC,  /* cur = r[reg] */
    OP_MOV_CR,  /* r[reg] = cur */
    OP_ADD_I,   /* cur += imm */
    OP_SUB_I,   /* cur -= imm */
    OP_ADD_R,   /* cur += r[reg] */
    OP_SUB_R,   /* cur -= r[reg] */
    OP_AND_I,   /* cur &= imm */
    OP_LOAD,    /* cur = load(cur + imm, size = reg & 15, big-endian if reg & 16) */
    OP_CMP_I,   /* ZF = cur == imm; CF = cur < imm */
    OP_CMP_R,   /* ZF = cur == r[reg]; CF = cur < r[reg] */
    OP_TEST,    /* ZF = (r[R_M] & imm) == 0 */
    OP_JMP,     /* pc = imm (forward only) */
    OP_JE, OP_JNE, OP_JB, OP_JAE, OP_JA, OP_JBE,
    OP_JF,      /* jump if the fault flag is set */
    OP_SCAN,    /* run the automaton over imm bytes at cur */
    OP_MPOS,    /* cur = offset past the first match of pattern reg; fault if none */
    OP_CMPSTR,  /* ZF = bytes at cur equal pattern reg */
    OP_FINDB,   /* cur = offset of byte reg within imm bytes; fault if none */
    OP_SKIPB,   /* cur advances past a run of byte reg (at most imm) */
    OP_PASS,
    OP_DROP,    /* rule = reg */
    OP_COUNT,   /* rule = reg */
    OP_LOG,     /* imm bytes at cur into the event */
    OP_BAN,     /* rule = reg, ttl seconds = imm: mark the flow, drop */
    OP_RST,     /* rule = reg, ttl seconds = imm: mark the flow, answer with a RST */
    OP_FLOW,    /* cur = the flow's mark */
    OP_MARK,    /* mark = reg, ttl seconds = imm */
    OP_SLOAD,   /* cur = this flow's user state */
    OP_SSTORE,  /* this flow's user state = imm */
    OP_BUMP,    /* cur = ++this flow's hit counter (per-connection rate limiting) */
    OP_OR_I,    /* cur |= imm */
    OP_SHL_I,   /* cur <<= imm */
    OP_SHR_I,   /* cur >>= imm */
    OP_CIDR,    /* ZF = (cur in network/prefix); imm = net(low32, host order) | prefix<<32 */
    OP_RPUSH,   /* push cur onto this flow's ring */
    OP_RGET,    /* cur = ring entry at index cur (0 = newest); cur=0 + fault if out of range */
    OP_RLEN,    /* cur = this flow's ring length */
    OP_REDACT,  /* overwrite every match of pattern reg in [cur, end) with fill byte imm */
    OP_REPLACE, /* overwrite every match of pattern reg in [cur, end) with pattern imm (same length) */
    OP_DNAT,    /* rewrite dst IPv4 + port to imm (ip = low 32, port = bits 32..47), fix IP + L4 csums */
    OP_LPM,     /* ZF = cur (IPv4, host order) is in the lpm_trie CIDR set (longest-prefix match) */
    OP_HASH,    /* ZF = cur (low 32 bits) is a key in the `hashset` map (exact set membership) */
    OP_BLOOM,   /* ZF = cur (low 32 bits) is (probably) in the `bloom` filter */
    OP_LPM6,    /* ZF = the IPv6 source address is in the lpm6 CIDR set (longest-prefix) */
    OP_REDIRECT,/* forward the packet out ifindex imm (bpf_redirect -> XDP_REDIRECT); terminal on the pass path */
    OP_RATE,    /* token-bucket rate limit on the flow: imm = rate/sec (low 32) | burst (high 32); ZF = over the limit */
    OP_ARG,     /* cur = args[idx] if idx < argc else default; imm = idx (bits 32..47) | default (low 32) */
    OP_ARGC,    /* cur = argc (number of runtime args the host set) */
    OP_FARG,    /* push cur as the next numeric format argument (for console/printk) */
    OP_FARGS,   /* capture a %s string: cur is a packet offset, copy up to imm bytes */
    OP_CONSOLE, /* emit a console event to the host: imm = format id, args = the pushed fargs */
    OP_PRINTK,  /* bpf_trace_printk to the kernel trace pipe: imm = printk format id, up to 3 numeric fargs */
    OP_COUNT_OPCODES,
};

#define FL_ZF 1u
#define FL_CF 2u
#define FL_FF 4u /* fault */

enum pfw_verdict { V_NONE = 0, V_PASS, V_DROP, V_BAN, V_RST };
enum pfw_mark { MARK_NONE = 0, MARK_DROP = 1, MARK_RST = 2 }; /* user marks from 16 up */

struct pfw_op {
    __u32 code;
    __u32 reg;
    __u64 imm;
};

struct pfw_pat {
    __u32 len;
    __u8 bytes[PFW_PAT_CAP];
};

struct pfw_prog {
    __u32 nops;
    __u32 npats;
    __u32 nocase;
    __u32 gen; /* stamped on flows so a new program starts their automaton over */
    __u32 reasm;       /* 1 = run over the per-flow reassembled TCP stream, not the packet */
    __u32 reasm_dport; /* reassemble only flows to this TCP dport (0 = every TCP flow);
                        * keeps the server->client direction and other ports off the
                        * reassembler, whose fail-closed logic would reset them. */
    __u32 decode;      /* L7 decode over the reassembled stream before matching:
                        * DECODE_NONE, DECODE_H2, DECODE_HUFFMAN or DECODE_TRANSFORM. */
    __u32 transform_table; /* DECODE_TRANSFORM: which loaded tt_cells table (0..TT_NTABLES-1) */
    __u32 argc;            /* number of runtime args the host set in args[] (OP_ARG / OP_ARGC) */
    __u64 args[PFW_ARGC];  /* runtime scalar parameters, set from the host without recompiling */
    __u8 fmts[PFW_FMTS][PFW_FMT_CAP]; /* printk format strings (NUL-terminated), for bpf_trace_printk */
    struct pfw_op ops[PFW_MAX_OPS];
    struct pfw_pat pats[PFW_MAX_PATS];
};

struct flow_key {
    __u8 saddr[16];
    __u8 daddr[16];
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 family;
    __u16 _pad;
};

struct flow {
    __u32 mark;
    __u32 rule;
    __u64 expires;
    __u32 ac_state;
    __u32 gen;
    __u64 mask;
    __u32 user_state; /* a per-connection state the program sets and reads */
    __u32 hits;       /* per-connection hit counter, for rate limiting */
    __u64 state_expires; /* ktime ns when user_state reverts to 0 (0 = never) */
    __u64 rl_tokens;  /* OP_RATE token bucket: tokens scaled by RL_SCALE (1e6) */
    __u64 rl_ts;      /* OP_RATE last-refill ktime ns (0 = bucket not yet seeded) */
    /* Per-flow ring (P3): insertion-ordered, fixed capacity, newest-wins
     * indexing — rpush/rget/rlen. The shape of the HPACK dynamic table and of
     * per-identity rate-limit history. Fixed u32 entries for now. */
    __u32 ring[RING_CAP];
    __u32 ring_head;  /* next write slot (mod RING_CAP) */
    __u32 ring_count; /* live entries, saturating at RING_CAP */
    /* TCP reassembly, for reasm-mode programs. Each segment is placed at its
     * sequence offset with a fill bitmap, first-wins on overlap (the Linux
     * policy), and the interpreter runs over the contiguous prefix from the
     * base — so a pattern split or reordered across segments is seen the way
     * the server's TCP stack will see it, and reordered-but-legit flows pass. */
    __u32 reasm_base;    /* TCP seq of reasm[0] (client ISN + 1) */
    __u32 reasm_len;     /* contiguous bytes from base (the inspectable prefix) */
    __u64 reasm_total;   /* lifetime bytes placed (0 = nothing seen yet) */
    __u8  synned;        /* saw this flow's SYN: it is tracked from the start */
    __u8  _fpad[7];
    __u8  reasm[REASM_CAP];
    __u8  filled[REASM_CAP / 8]; /* 1 bit per buffered byte, for gap tracking */
};

struct pfw_event {
    __u64 ts;
    __u32 ifindex;
    __u32 rule;
    __u32 verdict;
    __u32 len;
    __u64 mask;
    __u8 family;
    __u8 proto;
    __u16 sport;
    __u16 dport;
    __u16 _pad;
    __u8 saddr[16];
    __u8 daddr[16];
    __u8 data[LOG_CAP];
};

/* A console() message: the format id, the numeric args, and the captured %s
 * strings. The host maps fmtid -> format string and prints it. */
struct pfw_console {
    __u64 ts;
    __u32 ifindex;
    __u32 fmtid;
    __u32 nnum;              /* numeric arg count */
    __u32 nstr;             /* %s string count */
    __u64 nums[FARGS_MAX];
    __u16 slen[FSTR_MAX];
    __u8 strs[FSTR_MAX][STRARG_CAP];
};

#endif
