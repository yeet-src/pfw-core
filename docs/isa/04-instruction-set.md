# 4. Instruction set

All **71 opcodes** (`OP_END = 0` … `OP_TLOAD = 70`). Every instruction is one
`struct pfw_op { u32 code; u32 reg; u64 imm; }` — see
[§5 Bytecode encoding](05-bytecode-encoding.md) for how operands pack into
`reg`/`imm`. Execution is forward-only: a program is a `bpf_loop` of at most
`MAX_OPS` steps over `pfw_step`, and label jumps only go forward (the one
exception is `ret`, which resumes at a popped return address — still bounded by
the step budget). Flags are `ZF` (zero/equal), `CF` (carry/less-than,
unsigned) and `FF` (fault); each entry states which it sets, consumes, or
preserves.

Full per-opcode detail — assembler syntax, exact `code`/`reg`/`imm` encoding,
kernel + host semantics, flags, faults, maps touched, and examples — lives in the
four category files:

- [Arithmetic, moves, and loads](instructions/01-arithmetic-and-loads.md) — `end`, moves, integer arithmetic (`mul`/`mod` included), `load`, and the flow hash.
- [Compare, branch, and scan](instructions/02-compare-branch-and-scan.md) — comparisons, the forward branches, and the match engine (`scan`/`mpos`/`cmpstr`/`findb`/`skipb`).
- [Verdicts, flow state, and membership](instructions/03-verdict-flow-and-membership.md) — `decide` verdicts, events, per-flow state and the ring, and set membership.
- [Rewrite, steering, arguments, observability, and the stack](instructions/04-rewrite-steer-args-and-stack.md) — `redact`/`replace`, `dnat`/`redirect`, `rate`, `argv`, `console`/`printk`, `push`/`pop`/`call`/`ret`, and the live `knob`/`knobhas` control plane.

## Quick reference — all 71 opcodes

(`summary` is the one-line semantics from `bpf/include/pfw.h`; follow the detail
link for the complete entry.)

| # | opcode | summary | detail |
|---:|---|---|---|
| 0 | `OP_END` | — | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 1 | `OP_MOV_RC` | cur = r[reg] | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 2 | `OP_MOV_CR` | r[reg] = cur | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 3 | `OP_ADD_I` | cur += imm | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 4 | `OP_SUB_I` | cur -= imm | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 5 | `OP_ADD_R` | cur += r[reg] | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 6 | `OP_SUB_R` | cur -= r[reg] | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 7 | `OP_AND_I` | cur &= imm | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 8 | `OP_LOAD` | cur = load(cur + imm, size = reg & 15, big-endian if reg & 16) | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 9 | `OP_CMP_I` | ZF = cur == imm; CF = cur < imm | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 10 | `OP_CMP_R` | ZF = cur == r[reg]; CF = cur < r[reg] | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 11 | `OP_TEST` | ZF = (r[R_M] & imm) == 0 | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 12 | `OP_JMP` | pc = imm (forward only) | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 13 | `OP_JE` | — | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 14 | `OP_JNE` | — | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 15 | `OP_JB` | — | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 16 | `OP_JAE` | — | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 17 | `OP_JA` | — | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 18 | `OP_JBE` | — | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 19 | `OP_JF` | jump if the fault flag is set | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 20 | `OP_SCAN` | run the automaton over imm bytes at cur | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 21 | `OP_MPOS` | cur = offset past the first match of pattern reg; fault if none | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 22 | `OP_CMPSTR` | ZF = bytes at cur equal pattern reg | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 23 | `OP_FINDB` | cur = offset of byte reg within imm bytes; fault if none | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 24 | `OP_SKIPB` | cur advances past a run of byte reg (at most imm) | [compare / branch / scan](instructions/02-compare-branch-and-scan.md) |
| 25 | `OP_PASS` | — | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 26 | `OP_DROP` | rule = reg | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 27 | `OP_COUNT` | rule = reg | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 28 | `OP_LOG` | imm bytes at cur into the event | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 29 | `OP_BAN` | rule = reg, ttl seconds = imm: ban the source address (and mark the flow), drop | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 30 | `OP_RST` | rule = reg, ttl seconds = imm: mark the flow, answer with a RST | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 31 | `OP_FLOW` | cur = the flow's mark | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 32 | `OP_MARK` | mark = reg, ttl seconds = imm | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 33 | `OP_SLOAD` | cur = user state; reg = scope (this flow / the source) | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 34 | `OP_SSTORE` | user state = imm low 32; reg = ttl; imm bit 32 = scope | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 35 | `OP_BUMP` | cur = ++hit counter; reg = scope (flow.count / src.count) | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 36 | `OP_OR_I` | cur \|= imm | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 37 | `OP_SHL_I` | cur <<= imm | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 38 | `OP_SHR_I` | cur >>= imm | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 39 | `OP_CIDR` | ZF = (cur in network/prefix); imm = net(low32, host order) \| prefix<<32 | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 40 | `OP_RPUSH` | push cur onto this flow's ring | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 41 | `OP_RGET` | cur = ring entry at index cur (0 = newest); cur=0 + fault if out of range | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 42 | `OP_RLEN` | cur = this flow's ring length | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 43 | `OP_REDACT` | overwrite every match of pattern reg in [cur, end) with fill byte imm | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 44 | `OP_REPLACE` | overwrite every match of pattern reg in [cur, end) with pattern imm (same length) | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 45 | `OP_DNAT` | rewrite dst IPv4 + port to imm (ip = low 32, port = bits 32..47), fix IP + L4 csums | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 46 | `OP_LPM` | ZF = cur (IPv4, host order) is in the lpm_trie CIDR set (longest-prefix match) | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 47 | `OP_HASH` | ZF = cur (low 32 bits) is a key in the `hashset` map (exact set membership) | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 48 | `OP_BLOOM` | ZF = cur (low 32 bits) is (probably) in the `bloom` filter | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 49 | `OP_LPM6` | ZF = the IPv6 source address is in the lpm6 CIDR set (longest-prefix) | [verdict / flow / membership](instructions/03-verdict-flow-and-membership.md) |
| 50 | `OP_REDIRECT` | forward the packet out ifindex imm (bpf_redirect -> XDP_REDIRECT); terminal on the pass path | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 51 | `OP_RATE` | token-bucket rate limit: imm = rate/sec (low 32) \| burst (high 32); reg = scope; ZF = over the limit | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 52 | `OP_ARG` | cur = args[idx] if idx < argc else default; imm = idx (bits 32..47) \| default (low 32) | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 53 | `OP_ARGC` | cur = argc (number of runtime args the host set) | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 54 | `OP_FARG` | push cur as the next numeric format argument (for console/printk) | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 55 | `OP_FARGS` | capture a %s string: cur is a packet offset, copy up to imm bytes | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 56 | `OP_CONSOLE` | emit a console event to the host: imm = format id, args = the pushed fargs | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 57 | `OP_PRINTK` | bpf_trace_printk to the kernel trace pipe: imm = printk format id, up to 3 numeric fargs | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 58 | `OP_PUSH` | push cur onto the data stack (stack map), sp++ | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 59 | `OP_POP` | sp--, cur = top of the data stack | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 60 | `OP_CALL` | push the return pc onto the data stack, jump to imm (subroutine) | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 61 | `OP_RET` | pop the data stack into pc (return from a subroutine) | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 62 | `OP_KNOB` | cur = knobs[imm] — a live host-set control value (the `knobs` map) | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 63 | `OP_KNOBHAS` | ZF = the live host-set string knob_strs[imm] occurs in the payload window | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 64 | `OP_MUL_I` | cur *= imm | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 65 | `OP_MUL_R` | cur *= r[reg] | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 66 | `OP_MOD_I` | cur %= imm; a zero divisor yields 0 and faults | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 67 | `OP_MOD_R` | cur %= r[reg]; a zero divisor yields 0 and faults | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 68 | `OP_FHASH` | cur = a 32-bit hash of the packet's addresses, ports and protocol | [arith / moves / loads](instructions/01-arithmetic-and-loads.md) |
| 69 | `OP_EMIT` | send the pushed fargs to the host as a typed event: imm = event id | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
| 70 | `OP_TLOAD` | cur = tables[base + cur] if cur < size, else 0 and fault; imm = base (low 32) \| size (high 32) | [rewrite / steer / args / stack](instructions/04-rewrite-steer-args-and-stack.md) |
