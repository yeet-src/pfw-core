/* ISA conformance — arithmetic, moves, and loads.
 * Spec: docs/isa/instructions/01-arithmetic-and-loads.md, docs/isa/02-registers.md. */
import { isa, li, OP, REG, V } from "./harness.mjs";

const t = isa("arith");
const MAX = "0xffffffffffffffff";
const TOP = "0x8000000000000000";

/* ---- 0 END ---------------------------------------------------------------- */
t("end: halts with pass; later ops never run", { ops: [[OP.END], [OP.DROP, 1]], verdict: V.PASS });
t("end: running off the program is a pass", { asm: `and $0, %cur`, verdict: V.PASS, rule: 0 });

/* ---- entry state ---------------------------------------------------------- */
t("entry: %cur starts at %payload", { ops: [], payload: 7, cur: 7, regs: { payload: 7 } });
t("entry: flags start clear", { ops: [], zf: false, cf: false, ff: false });
t("entry: packet registers", {
  ops: [], frame: new Uint8Array(40), payload: 12,
  opts: { proto: 17, sport: 5353, dport: 53, saddr: 0x0a000001 },
  regs: { end: 40, len: 28, proto: 17, sport: 5353, dport: 53, saddr: 0x0a000001, src: 0x0a000001 },
});
t("entry: program registers start at zero", {
  ops: [], regs: Object.fromEntries(["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "m", "sp", "bp", "a0", "a6", "rv"].map((r) => [r, 0])),
});

/* ---- 1 MOV_RC ------------------------------------------------------------- */
t("mov_rc: cur = r[reg]", { asm: `mov %dport, %cur`, opts: { dport: 8080 }, cur: 8080 });
t("mov_rc: overwrites all 64 bits of %cur", { asm: `${li(MAX)}\nmov %s0, %cur`, cur: 0 });
t("mov_rc: leaves ZF/CF alone", { asm: `${li(1)}\ncmp $1, %cur\nmov %dport, %cur`, zf: true, cf: false });
t("mov_rc: leaves CF alone", { asm: `${li(1)}\ncmp $2, %cur\nmov %dport, %cur`, zf: false, cf: true });
t("mov_rc: the register index is masked to 5 bits", {
  ops: [[OP.MOV_RC, 32 + REG.dport]], opts: { dport: 443 }, cur: 443,
});

/* ---- 2 MOV_CR ------------------------------------------------------------- */
for (const name of ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "bp", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "rv"]) {
  t(`mov_cr: writes %${name} and nothing else`, {
    asm: li(0x1234), ops: [[OP.MOV_CR, REG[name]]],
    cur: 0x1234, regs: { [name]: 0x1234, [name === "s0" ? "s1" : "s0"]: 0 },
  });
}
t("mov_cr: holds a full 64-bit value", { asm: `${li(MAX)}\nmov %cur, %s3\nand $0, %cur`, cur: 0, regs: { s3: MAX } });
t("mov_cr: leaves ZF/CF alone", { asm: `${li(1)}\ncmp $2, %cur\nmov %cur, %s0`, zf: false, cf: true });
t("mov_cr: writing %m feeds test", { asm: `${li(4)}\nmov %cur, %m\ntest $4, %m`, zf: false, regs: { m: 4 } });
t("mov_cr: writing %end narrows what a load can reach", {
  asm: `${li(2)}\nmov %cur, %end\nmovb 0(%cur), %cur`, frame: "\x11\x22\x33\x44", ff: true, cur: 2, regs: { end: 2 },
});
t("mov_cr: the register index is masked to 5 bits", {
  asm: li(9), ops: [[OP.MOV_CR, 32 + REG.s2]], regs: { s2: 9 },
});

/* ---- 3 ADD_I / 4 SUB_I ---------------------------------------------------- */
t("add_i: cur += imm", { asm: `${li(5)}\nadd $9, %cur`, cur: 14 });
t("add_i: a 64-bit immediate", { asm: `${li(1)}\nadd $0x123456789abcdef0, %cur`, cur: "0x123456789abcdef1" });
t("add_i: wraps mod 2^64", { asm: `${li(MAX)}\nadd $2, %cur`, cur: 1 });
t("add_i: touches no flag", { asm: `${li(1)}\ncmp $1, %cur\nadd $1, %cur`, zf: true, cf: false, ff: false });
t("add_i: a negative immediate assembles as sub_i", { asm: `${li(10)}\nadd $-3, %cur`, cur: 7 });
t("sub_i: cur -= imm", { asm: `${li(9)}\nsub $4, %cur`, cur: 5 });
t("sub_i: wraps below zero", { asm: `${li(0)}\nsub $1, %cur`, cur: MAX });
t("sub_i: touches no flag (no borrow into CF)", { asm: `${li(0)}\nsub $1, %cur`, zf: false, cf: false, ff: false });
t("sub_i: a negative immediate assembles as add_i", { asm: `${li(10)}\nsub $-3, %cur`, cur: 13 });

/* ---- 5 ADD_R / 6 SUB_R ---------------------------------------------------- */
const withS0 = (s0, cur, op) => `${li(s0)}\nmov %cur, %s0\n${li(cur)}\n${op}`;
t("add_r: cur += r[reg]", { asm: withS0(10, 3, "add %s0, %cur"), cur: 13, regs: { s0: 10 } });
t("add_r: wraps mod 2^64", { asm: withS0(MAX, 5, "add %s0, %cur"), cur: 4 });
t("add_r: %cur as the operand doubles it", { asm: `${li(21)}\nadd %cur, %cur`, cur: 42 });
t("add_r: reads an entry register", { asm: `${li(1)}\nadd %dport, %cur`, opts: { dport: 80 }, cur: 81 });
t("add_r: touches no flag", { asm: `${withS0(1, 1, "cmp $2, %cur")}\nadd %s0, %cur`, zf: false, cf: true });
t("sub_r: cur -= r[reg]", { asm: withS0(3, 10, "sub %s0, %cur"), cur: 7 });
t("sub_r: wraps below zero", { asm: withS0(10, 3, "sub %s0, %cur"), cur: "0xfffffffffffffff9" });
t("sub_r: %cur as the operand zeroes it", { asm: `${li(21)}\nsub %cur, %cur`, cur: 0 });
t("sub_r: touches no flag", { asm: `${withS0(1, 1, "cmp $1, %cur")}\nsub %s0, %cur`, zf: true, cf: false });

/* ---- 7 AND_I / 36 OR_I ---------------------------------------------------- */
t("and_i: cur &= imm", { asm: `${li(0xff)}\nand $0x0f, %cur`, cur: 0x0f });
t("and_i: masks the high word", { asm: `${li(MAX)}\nand $0xffffffff00000000, %cur`, cur: "0xffffffff00000000" });
t("and_i: $0 zeroes the accumulator", { asm: `mov %dport, %cur\nand $0, %cur`, opts: { dport: 80 }, cur: 0 });
t("and_i: a zero result does not set ZF", { asm: `${li(1)}\ncmp $2, %cur\nand $0, %cur`, zf: false, cf: true });
t("or_i: cur |= imm", { asm: `${li(0x10)}\nor $1, %cur`, cur: 0x11 });
t("or_i: sets the top bit", { asm: `${li(1)}\nor $${TOP}, %cur`, cur: "0x8000000000000001" });
t("or_i: touches no flag", { asm: `${li(1)}\ncmp $1, %cur\nor $6, %cur`, zf: true, cf: false });

/* ---- 37 SHL_I / 38 SHR_I -------------------------------------------------- */
t("shl_i: cur <<= imm", { asm: `${li(3)}\nshl $4, %cur`, cur: 48 });
t("shl_i: by 0 is the identity", { asm: `${li(3)}\nshl $0, %cur`, cur: 3 });
t("shl_i: by 63 reaches the top bit", { asm: `${li(1)}\nshl $63, %cur`, cur: TOP });
t("shl_i: bits shifted out of bit 63 are lost", { asm: `${li("0xc000000000000001")}\nshl $1, %cur`, cur: "0x8000000000000002" });
t("shl_i: the count is masked to 6 bits (64 -> 0)", { asm: `${li(3)}\nshl $64, %cur`, cur: 3 });
t("shl_i: the count is masked to 6 bits (65 -> 1)", { asm: `${li(3)}\nshl $65, %cur`, cur: 6 });
t("shl_i: touches no flag", { asm: `${li(1)}\ncmp $2, %cur\nshl $63, %cur\nshl $1, %cur`, zf: false, cf: true });
t("shr_i: cur >>= imm", { asm: `${li(48)}\nshr $4, %cur`, cur: 3 });
t("shr_i: is logical — the top bit does not smear", { asm: `${li(TOP)}\nshr $63, %cur`, cur: 1 });
t("shr_i: bits shifted out of bit 0 are lost", { asm: `${li(7)}\nshr $1, %cur`, cur: 3 });
t("shr_i: the count is masked to 6 bits (64 -> 0)", { asm: `${li(48)}\nshr $64, %cur`, cur: 48 });
t("shr_i: the count is masked to 6 bits (68 -> 4)", { asm: `${li(48)}\nshr $68, %cur`, cur: 3 });
t("shr_i: touches no flag", { asm: `${li(1)}\ncmp $1, %cur\nshr $1, %cur`, zf: true, cf: false });

/* ---- 8 LOAD --------------------------------------------------------------- */
const F = "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa";
t("load: movb", { asm: `movb 0(%cur), %cur`, frame: F, cur: 0x11 });
t("load: movw is little-endian", { asm: `movw 0(%cur), %cur`, frame: F, cur: 0x2211 });
t("load: movl is little-endian", { asm: `movl 0(%cur), %cur`, frame: F, cur: 0x44332211 });
t("load: movq is little-endian", { asm: `movq 0(%cur), %cur`, frame: F, cur: "0x8877665544332211" });
t("load: movbew is big-endian", { asm: `movbew 0(%cur), %cur`, frame: F, cur: 0x1122 });
t("load: movbel is big-endian", { asm: `movbel 0(%cur), %cur`, frame: F, cur: 0x11223344 });
t("load: movbeq is big-endian", { asm: `movbeq 0(%cur), %cur`, frame: F, cur: "0x1122334455667788" });
t("load: the BE bit is ignored for one byte", { ops: [[OP.LOAD, 1 | 16, 3]], frame: F, cur: 0x44 });
t("load: a narrow load zero-extends, clearing the old %cur", { asm: `${li(MAX)}\nand $1, %cur\nmovb 0(%cur), %cur`, frame: "\x00\xff", cur: 0xff });
t("load: the address is cur + displacement", { asm: `${li(2)}\nmovw 3(%cur), %cur`, frame: F, cur: 0x7766 });
t("load: a non-%cur base is moved into %cur first", { asm: `${li(99)}\nmovb 1(%payload), %cur`, frame: F, payload: 4, cur: 0x66 });
t("load: a negative displacement", { asm: `${li(4)}\nmovb -3(%cur), %cur`, frame: F, cur: 0x22 });
t("load: the last byte is readable", { asm: `movb 9(%cur), %cur`, frame: F, cur: 0xaa, ff: false });
t("load: a read ending exactly at %end succeeds", { asm: `movq 2(%cur), %cur`, frame: F, cur: "0xaa99887766554433", ff: false });
t("load: at %end faults and leaves %cur", { asm: `${li(10)}\nmovb 0(%cur), %cur`, frame: F, cur: 10, ff: true });
t("load: a multi-byte read straddling %end faults", { asm: `movl 7(%cur), %cur`, frame: F, cur: 0, ff: true });
t("load: movq straddling %end by one byte faults", { asm: `movq 3(%cur), %cur`, frame: F, cur: 0, ff: true });
t("load: honours a narrowed %end", { asm: `${li(4)}\nmov %cur, %end\nand $0, %cur\nmovq 0(%cur), %cur`, frame: F, cur: 0, ff: true });
t("load: offset 0xffff is still addressable", { asm: `${li(0xffff)}\nmovb 0(%cur), %cur`, frame: Uint8Array.from({ length: 0x10002 }, (_, i) => (i === 0xffff ? 0x5a : 0)), cur: 0x5a, ff: false });
t("load: offsets past 0xffff fault, whatever %end is", { asm: `${li(0x10000)}\nmovb 0(%cur), %cur`, frame: new Uint8Array(0x10002).fill(0x5a), cur: 0x10000, ff: true });
t("load: a fault leaves ZF/CF alone", { asm: `${li(10)}\ncmp $10, %cur\nmovb 0(%cur), %cur`, frame: F, zf: true, cf: false, ff: true });
t("load: a success leaves ZF/CF alone", { asm: `${li(0)}\ncmp $1, %cur\nmovb 0(%cur), %cur`, frame: F, zf: false, cf: true, ff: false });
t("load: FF is sticky — a later good load does not clear it", { asm: `${li(10)}\nmovb 0(%cur), %cur\nand $0, %cur\nmovb 0(%cur), %cur`, frame: F, cur: 0x11, ff: true });
t("load: the effective address wraps mod 2^64", {
  asm: `${li(MAX)}\nmovb 1(%cur), %cur`, frame: F, cur: 0x11, ff: false,
});
t("load: a size other than 1/2/4/8 faults", {
  asm: li(0), ops: [[OP.LOAD, 3, 0]], frame: F, cur: 0, ff: true,
});

t.covers(OP.END, OP.MOV_RC, OP.MOV_CR, OP.ADD_I, OP.SUB_I, OP.ADD_R, OP.SUB_R, OP.AND_I, OP.LOAD, OP.OR_I, OP.SHL_I, OP.SHR_I);
