/* ISA conformance — rewrite, steering, rate, runtime arguments, observability,
 * and the data stack. Spec: docs/isa/instructions/04-rewrite-steer-args-and-stack.md.
 *
 * Several of these ops act outside the machine state a verdict can show: the
 * rewrite ops change the packet, console emits an event, dnat / redirect /
 * printk are kernel-only effects the host model treats as no-ops. Those are
 * checked through `frameOut` / `console`, or only for what they must NOT
 * disturb; their real effect belongs to the kernel tests. */
import { isa, li, OP, REG, V } from "./harness.mjs";

const t = isa("rewrite/args/stack");
const MAX = "0xffffffffffffffff";
const FAULT = `mov %end, %cur\nmovb 0(%cur), %cur`;
const FLAGS = `${li(4)}\ncmp $5, %cur`; // leaves ZF clear, CF set, %cur = 4
const SEC = 1_000_000_000;

/* ---- 43 REDACT / 44 REPLACE ----------------------------------------------- */
const RW = `.pat ssn, "123-45"\n.pat aa, "aa"\n.pat bb, "bb"\n.pat xyz, "xyz"`;
t("redact: overwrites a match with the fill byte", { asm: `${RW}\nredact $ssn, $'*'`, frame: "id=123-45;", frameOut: "id=******;" });
t("redact: every match in the payload", { asm: `${RW}\nredact $aa, $'#'`, frame: "aa.aa.aa", frameOut: "##.##.##" });
t("redact: no match leaves the packet alone", { asm: `${RW}\nredact $ssn, $'*'`, frame: "nothing", frameOut: "nothing" });
t("redact: covers the whole payload, not from the cursor", { asm: `${RW}\nmov %end, %cur\nredact $aa, $'#'`, frame: "aa..aa", frameOut: "##..##" });
t("redact: starts at %payload — headers are not rewritten", { asm: `${RW}\nredact $aa, $'#'`, frame: "aa|aa", payload: 3, frameOut: "aa|##" });
t("redact: matches do not overlap", { asm: `${RW}\nredact $aa, $'#'`, frame: "aaa", frameOut: "##a" });
t("redact: honours .nocase", { asm: `.nocase\n${RW}\nredact $xyz, $'-'`, frame: "XyZ", frameOut: "---" });
t("redact: not terminal; leaves %cur and the flags", { asm: `${RW}\n${FLAGS}\nredact $aa, $'#'`, frame: "aa", cur: 4, zf: false, cf: true, ff: false });
t("replace: overwrites a match with another pattern's bytes", { asm: `${RW}\nreplace $aa, $bb`, frame: "x aa y aa", frameOut: "x bb y bb" });
t("replace: no match leaves the packet alone", { asm: `${RW}\nreplace $aa, $bb`, frame: "x cc y", frameOut: "x cc y" });
t("replace: a different-length replacement is not applied", { asm: `${RW}\nreplace $aa, $xyz`, frame: "x aa y", frameOut: "x aa y" });
t("replace: not terminal; leaves %cur and the flags", { asm: `${RW}\n${FLAGS}\nreplace $aa, $bb`, frame: "aa", cur: 4, zf: false, cf: true, ff: false });

/* ---- 45 DNAT / 50 REDIRECT (kernel-only effects) -------------------------- */
t("dnat: not terminal; leaves %cur and the flags", { asm: `${FLAGS}\ndnat 127.0.0.2:8080`, cur: 4, zf: false, cf: true, ff: false });
t("dnat: the program still reaches its verdict", { asm: `dnat 127.0.0.2:8080\ndrop $1`, verdict: V.DROP });
t("redirect: not terminal; leaves %cur and the flags", { asm: `${FLAGS}\nredirect 3`, cur: 4, zf: false, cf: true, ff: false });
t("redirect: the program still reaches its verdict", { asm: `redirect 3\ndrop $1`, verdict: V.DROP });

/* ---- 51 RATE -------------------------------------------------------------- */
const BUCKET = { opts: { bucket: {} } };
t("rate: the first packet finds a full bucket — allowed", { asm: `rate $1, $3`, ...BUCKET, clock: [SEC], zf: false });
t("rate: the whole burst is allowed", { asm: `rate $1, $3`, ...BUCKET, clock: [SEC, SEC, SEC], zf: false });
t("rate: past the burst -> ZF (over the limit)", { asm: `rate $1, $3`, ...BUCKET, clock: [SEC, SEC, SEC, SEC], zf: true });
t("rate: an over-limit packet spends nothing; a second of refill buys one", { asm: `rate $1, $3`, ...BUCKET, clock: [SEC, SEC, SEC, SEC, SEC, 2 * SEC], zf: false });
t("rate: … and only one", { asm: `rate $1, $3`, ...BUCKET, clock: [SEC, SEC, SEC, SEC, 2 * SEC, 2 * SEC], zf: true });
t("rate: refill is proportional to the rate", { asm: `rate $10, $1`, ...BUCKET, clock: [SEC, SEC + SEC / 10], zf: false });
t("rate: less than one token's worth of time is still over", { asm: `rate $10, $1`, ...BUCKET, clock: [SEC, SEC + SEC / 20], zf: true });
t("rate: refill is capped at the burst", { asm: `rate $1, $2`, ...BUCKET, clock: [SEC, 100 * SEC, 100 * SEC, 100 * SEC], zf: true });
t("rate: a clock running backwards refills nothing", { asm: `rate $1, $1`, ...BUCKET, clock: [10 * SEC, 5 * SEC], zf: true });
t("rate: clears CF, preserves FF, leaves %cur", { asm: `${FAULT}\ncmp $1, %cur\nrate $1, $3`, frame: "", ...BUCKET, clock: [SEC], zf: false, cf: false, ff: true, cur: 0 });
t("srcrate: one bucket per source", { asm: `srcrate $1, $2`, opts: { source: {} }, clock: [SEC, SEC, SEC], zf: true });
t("srcrate: apart from the flow's bucket", { asm: `rate $1, $1\nsrcrate $1, $2`, opts: { bucket: {}, source: {} }, clock: [SEC, SEC], zf: false });
t("rate: zero rate or burst is refused", { asm: `rate $0, $3`, rejects: /positive u32/ });

/* ---- 52 ARG / 53 ARGC ----------------------------------------------------- */
t("arg: an unset argument reads its inline default", { asm: `arg $0, $80`, cur: 80 });
t("arg: the default defaults to 0", { asm: `${li(9)}\narg $0`, cur: 0 });
t("arg: a set argument wins over the default", { asm: `arg $0, $80`, opts: { argv: [5] }, cur: 5 });
t("arg: a set argument of 0 is still set", { asm: `arg $0, $80`, opts: { argv: [0] }, cur: 0 });
t("arg: indexes the argument vector", { asm: `arg $2, $80`, opts: { argv: [10, 20, 30] }, cur: 30 });
t("arg: an index at argc reads the default", { asm: `arg $2, $80`, opts: { argv: [10, 20] }, cur: 80 });
t("arg: arguments are 64-bit", { asm: `arg $0`, opts: { argv: [0x123456789abcn] }, cur: "0x123456789abc" });
t("arg: the default is 32-bit", { asm: `arg $1, $0xffffffff`, cur: 0xffffffff });
t("arg: the last slot", { asm: `arg $15, $7`, opts: { argv: Array.from({ length: 16 }, (_, i) => i * 3) }, cur: 45 });
t("arg: leaves the flags alone", { asm: `${FLAGS}\narg $0, $80`, zf: false, cf: true, ff: false });
t("arg: index 16 is out of range", { asm: `arg $16`, rejects: /arg index/ });
t("argc: 0 when the host set none", { asm: `${li(9)}\nargc`, cur: 0 });
t("argc: the number of arguments set", { asm: `argc`, opts: { argv: [10, 20, 30] }, cur: 3 });
t("argc: leaves the flags alone", { asm: `${FLAGS}\nargc`, zf: false, cf: true, ff: false });

/* ---- 62 KNOB / 63 KNOBHAS ------------------------------------------------- */
t("knob: an unset slot reads 0", { asm: `${li(9)}\nknob $0`, cur: 0 });
t("knob: cur = knobs[slot]", { asm: `knob $3`, opts: { knobs: [1, 2, 3, 44] }, cur: 44 });
t("knob: values are 64-bit", { asm: `knob $0`, opts: { knobs: [0xfedcba9876543210n] }, cur: "0xfedcba9876543210" });
t("knob: the last slot", { asm: `knob $31`, opts: { knobs: Array.from({ length: 32 }, (_, i) => i + 100) }, cur: 131 });
t("knob: the slot is masked to 5 bits", { ops: [[OP.KNOB, 0, 32 + 2]], opts: { knobs: [7, 8, 9] }, cur: 9 });
t("knob: leaves the flags alone", { asm: `${FLAGS}\nknob $0`, zf: false, cf: true, ff: false });
const KS = (...s) => ({ opts: { knobStrs: s } });
t("knobhas: the string occurs in the payload -> ZF", { asm: `knobhas $0`, frame: "GET /x?evil=1", ...KS("evil"), zf: true });
t("knobhas: absent clears ZF", { asm: `knobhas $0`, frame: "GET /x?evil=1", ...KS("nope"), zf: false });
t("knobhas: an unset slot never matches", { asm: `knobhas $1`, frame: "GET /x?evil=1", ...KS("evil"), zf: false });
t("knobhas: indexes the string slots", { asm: `knobhas $1`, frame: "GET /x?evil=1", ...KS("nope", "x?e"), zf: true });
t("knobhas: at the very start and the very end", { asm: `knobhas $0\nje a\njmp done\na: knobhas $1\ndone:`, frame: "abcdef", ...KS("ab", "ef"), zf: true });
t("knobhas: the whole payload", { asm: `knobhas $0`, frame: "abcdef", ...KS("abcdef"), zf: true });
t("knobhas: longer than the payload", { asm: `knobhas $0`, frame: "abc", ...KS("abcd"), zf: false });
t("knobhas: is case-sensitive", { asm: `knobhas $0`, frame: "EVIL", ...KS("evil"), zf: false });
t("knobhas: searches from %payload, not the cursor", { asm: `mov %end, %cur\nknobhas $0`, frame: "an evil one", ...KS("evil"), zf: true });
t("knobhas: does not look before %payload", { asm: `knobhas $0`, frame: "evil|clean", payload: 5, ...KS("evil"), zf: false });
t("knobhas: stops at %end", { asm: `${li(5)}\nmov %cur, %end\nknobhas $0`, frame: "an evil one", ...KS("evil"), zf: false });
t("knobhas: reaches the first 256 payload bytes", { asm: `knobhas $0`, frame: "x".repeat(252) + "evil", ...KS("evil"), zf: true });
t("knobhas: … and no further", { asm: `knobhas $0`, frame: "x".repeat(253) + "evil", ...KS("evil"), zf: false });
t("knobhas: clears CF, preserves FF, leaves %cur", { asm: `${FAULT}\ncmp $9, %cur\nknobhas $0`, frame: "evil", ...KS("evil"), zf: true, cf: false, ff: true, cur: 4 });

/* ---- 54 FARG / 55 FARGS / 56 CONSOLE / 57 PRINTK --------------------------- */
t("console: emits the format id with no arguments", { asm: `console $3`, console: [{ fmtid: 3 }] });
t("console: not terminal; leaves %cur and the flags", { asm: `${FLAGS}\nconsole $0`, cur: 4, zf: false, cf: true, ff: false });
t("farg: queues %cur as a numeric argument, in order", { asm: `${li(7)}\nfarg\n${li(9)}\nfarg\nconsole $1`, console: [{ fmtid: 1, nums: [7, 9] }] });
t("farg: arguments are 64-bit", { asm: `${li(MAX)}\nfarg\nconsole $0`, console: [{ fmtid: 0, nums: [MAX] }] });
t("farg: at most 4 — a fifth is dropped", { asm: `${[1, 2, 3, 4, 5].map((n) => `${li(n)}\nfarg`).join("\n")}\nconsole $0`, console: [{ fmtid: 0, nums: [1, 2, 3, 4] }] });
t("farg: leaves %cur and the flags", { asm: `${FLAGS}\nfarg`, cur: 4, zf: false, cf: true, ff: false });
t("fargs: captures up to imm bytes at the cursor", { asm: `${li(4)}\nfargs $5\nconsole $0`, frame: "GET /path HTTP", console: [{ fmtid: 0, strs: ["/path"] }] });
t("fargs: stops at %end", { asm: `${li(10)}\nfargs $64\nconsole $0`, frame: "GET /path HTTP", console: [{ fmtid: 0, strs: ["HTTP"] }] });
t("fargs: at %end captures an empty string", { asm: `mov %end, %cur\nfargs $8\nconsole $0`, frame: "abc", console: [{ fmtid: 0, strs: [""] }] });
t("fargs: at most 2 strings — a third is dropped", { asm: `fargs $1\nfargs $2\nfargs $3\nconsole $0`, frame: "abc", console: [{ fmtid: 0, strs: ["a", "ab"] }] });
t("fargs: leaves %cur and the flags", { asm: `${FLAGS}\nfargs $8`, cur: 4, zf: false, cf: true, ff: false });
t("console: flushes the queued numeric arguments", { asm: `${li(7)}\nfarg\nconsole $1\nconsole $2`, console: [{ fmtid: 1, nums: [7] }, { fmtid: 2 }] });
t("console: numbers and strings together", { asm: `fargs $3\n${li(42)}\nfarg\nconsole $5`, frame: "abcdef", console: [{ fmtid: 5, nums: [42], strs: ["abc"] }] });
t("printk: not terminal; leaves %cur and the flags", { asm: `${FLAGS}\nfarg\nprintk $0`, cur: 4, zf: false, cf: true, ff: false });
t("printk: consumes the queued numeric arguments", { asm: `${li(7)}\nfarg\nprintk $0\nconsole $1`, console: [{ fmtid: 1 }] });

/* ---- 58 PUSH / 59 POP ----------------------------------------------------- */
const pushN = (n, base = 100) => Array.from({ length: n }, (_, i) => `${li(base + i)}\npush`).join("\n");
t("push: stores %cur and increments %sp", { asm: `${li(42)}\npush`, cur: 42, regs: { sp: 1 } });
t("pop: decrements %sp and loads %cur", { asm: `${li(42)}\npush\nand $0, %cur\npop`, cur: 42, regs: { sp: 0 } });
t("stack: is last-in first-out", { asm: `${pushN(3)}\npop\nmov %cur, %s0\npop\nmov %cur, %s1\npop`, cur: 100, regs: { s0: 102, s1: 101, sp: 0 } });
t("stack: holds 64-bit values", { asm: `${li(MAX)}\npush\nand $0, %cur\npop`, cur: MAX });
t("pop: on an empty stack is a no-op", { asm: `${li(9)}\npop`, cur: 9, regs: { sp: 0 }, ff: false });
t("stack: holds 64 entries", { asm: `${pushN(64)}\npop`, cur: 163, regs: { sp: 63 } });
t("push: on a full stack is a no-op", { asm: `${pushN(65)}\nmov %sp, %cur`, cur: 64 });
t("push: … and does not clobber the top", { asm: `${pushN(65)}\npop`, cur: 163 });
t("push / pop: leave the flags alone", { asm: `${FLAGS}\npush\npop`, zf: false, cf: true, ff: false });
t("stack: %sp is an ordinary register — lowering it discards entries", { asm: `${pushN(3)}\n${li(1)}`, ops: [[OP.MOV_CR, REG.sp], [OP.POP]], cur: 100, regs: { sp: 0 } });
t("stack: %bp marks a frame to unwind to", {
  asm: `${pushN(1)}\nmov %sp, %cur`, ops: [[OP.MOV_CR, REG.bp], [OP.PUSH], [OP.PUSH], [OP.MOV_RC, REG.bp], [OP.MOV_CR, REG.sp], [OP.POP]], cur: 100, regs: { sp: 0, bp: 1 },
});

/* ---- 60 CALL / 61 RET ----------------------------------------------------- */
t("call: runs the subroutine, ret resumes after the call", { asm: `${li(1)}\ncall f\nadd $100, %cur\njmp done\nf: add $10, %cur\nret\ndone:`, cur: 111, regs: { sp: 0 } });
t("call: pushes the return pc onto the data stack", { asm: `${li(0)}\ncall f\nf: pop`, cur: 3, regs: { sp: 0 } });
t("call: the stack holds one entry inside the subroutine", { asm: `call f\njmp done\nf: mov %sp, %cur\nmov %cur, %s0\nret\ndone:`, regs: { s0: 1, sp: 0 } });
t("call: may target an earlier pc", { asm: `jmp main\nf: add $10, %cur\nret\nmain: ${li(1)}\ncall f\nadd $100, %cur`, cur: 111 });
t("call: nests", { asm: `${li(0)}\ncall f\njmp done\nf: add $1, %cur\ncall g\nadd $4, %cur\nret\ng: add $2, %cur\nret\ndone:`, cur: 7, regs: { sp: 0 } });
t("call: the same subroutine twice", { asm: `${li(0)}\ncall f\ncall f\njmp done\nf: add $5, %cur\nret\ndone:`, cur: 10 });
t("call: registers pass arguments and results", { asm: `${li(20)}`, ops: [[OP.MOV_CR, REG.a0], [OP.CALL, 0, (pc) => pc + 3], [OP.MOV_RC, REG.rv], [OP.JMP, 0, (pc) => pc + 5], [OP.MOV_RC, REG.a0], [OP.ADD_R, REG.a0], [OP.MOV_CR, REG.rv], [OP.RET]], cur: 40, regs: { a0: 20, rv: 40 } });
t("call / ret: leave the flags alone", { asm: `${FLAGS}\ncall f\njmp done\nf: ret\ndone:`, zf: false, cf: true, ff: false });
t("call: with the stack full does not jump", { asm: `${pushN(64)}\n${li(0)}\ncall f\nadd $1, %cur\njmp done\nf: add $50, %cur\ndone:`, cur: 1, regs: { sp: 64 } });
t("ret: with the stack empty falls through", { asm: `${li(1)}\nret\nadd $2, %cur`, cur: 3, regs: { sp: 0 } });
t("ret: returns to whatever was pushed", { asm: `${li(7)}\npush\n${li(0)}\nret\nadd $1, %cur\nadd $2, %cur`, cur: 2 });
t("ret: a subroutine must balance the stack — a stray push is taken for the return pc", { asm: `call f\ndrop $1\nf: ${li(8)}\npush\nret\ndrop $2\ndrop $3\nrst $4, $0`, verdict: V.RST, rule: 4 });
t("budget: a ret loop is cut off after MAX_OPS steps, with pass", { ops: [[OP.AND_I], [OP.PUSH], [OP.RET], [OP.DROP, 1]], verdict: V.PASS });
t("budget: a recursive call bottoms out when the stack fills", { asm: `${li(0)}\nf: add $1, %cur\ncall f`, cur: 65, regs: { sp: 64 } });

t.covers(OP.REDACT, OP.REPLACE, OP.DNAT, OP.REDIRECT, OP.RATE, OP.ARG, OP.ARGC, OP.FARG, OP.FARGS, OP.CONSOLE, OP.PRINTK, OP.PUSH, OP.POP, OP.CALL, OP.RET, OP.KNOB, OP.KNOBHAS);
