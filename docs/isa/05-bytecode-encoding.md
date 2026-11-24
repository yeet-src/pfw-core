# 5. Bytecode encoding

### `struct pfw_op`

```c
struct pfw_op { __u32 code; __u32 reg; __u64 imm; };
```

`reg` is masked `& (NREGS - 1)` for register ops, `& (PFW_MAX_PATS - 1)` for
pattern ops, `& (PFW_NRULES - 1)` for rule ops. Multi-field operands pack into
`reg`/`imm`:

| op | encoding |
|---|---|
| `load` | `reg` = size `(0..15)` \| big-endian bit `16` |
| `cidr` | `imm` = net (low 32, host order) \| prefix `<< 32` |
| `dnat` | `imm` = ip (low 32, net order on the wire) \| port `<< 32` |
| `rate` | `reg` = scope (0 flow, 1 source); `imm` = rate/sec (low 32) \| burst `<< 32` |
| `scan` | `reg` bit 0 = fresh (`within`); `imm` = window length |
| `sload` / `bump` | `reg` = scope (0 flow, 1 source) |
| `arg` | `imm` = default (low 32) \| index `<< 32` (bits 32–47) |
| `redact` | `reg` = pat id \| regex bit `<< 15`; `imm` = fill byte (low 8) \| rlen `<< 8` |
| `replace` | `reg` = pat id \| regex bit `<< 15`; `imm` = repl pat id (low 6) \| rlen `<< 8` |
| `sstore` | `reg` = TTL seconds; `imm` = new state value (low 32) \| scope `<< 32` |
| `ban`/`rst`/`mark` | `reg` = rule / mark; `imm` = TTL seconds |
| `findb`/`skipb` | `reg` = byte (low 8); `imm` = window / max run |

### `struct pfw_prog`

The `programs[gen]` map value:

```c
struct pfw_prog {
    __u32 nops, npats, nocase, gen;
    __u32 reasm, reasm_dport, decode, transform_table;
    __u32 argc;  __u64 args[PFW_ARGC];
    __u8  fmts[PFW_FMTS][PFW_FMT_CAP];
    struct pfw_op  ops[PFW_MAX_OPS];     // 65536
    struct pfw_pat pats[PFW_MAX_PATS];   // 64 × {u32 len; u8 bytes[64]}
};
```

`serializeProgram(program, gen)` (host) produces this value; `build(patterns,
nocase)` produces the Aho-Corasick tables (`ac_goto`/`ac_fail`/`ac_accept`), and
the regex compiler produces the DFA tables (`re_goto`/`re_accept`). The loader
writes the program into `programs[gen]`, the automaton/DFA/transform tables and
the membership sets into their maps, patches the `active_gen`/`shadow` globals, then
attaches `pfw_xdp`. Two generations (`PFW_GENS = 2`) let an update write the idle
generation and flip `active_gen` atomically.

---
