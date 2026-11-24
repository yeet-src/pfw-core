/* ISA conformance — compare, branch, and the match engine.
 * Spec: docs/isa/instructions/02-compare-branch-and-scan.md, docs/isa/01-machine-model.md. */
import { LIMITS } from "#/isa.js";
import { isa, li, OP, V } from "./harness.mjs";

const { SKIP_CAP } = LIMITS;
const t = isa("cmp/branch/scan");
const MAX = "0xffffffffffffffff";
/* Raise FF without disturbing much: a one-byte load at %end. Leaves %cur = %end. */
const FAULT = `mov %end, %cur\nmovb 0(%cur), %cur`;

/* ---- 9 CMP_I / 10 CMP_R --------------------------------------------------- */
t("cmp_i: equal -> ZF, no CF", { asm: `${li(5)}\ncmp $5, %cur`, zf: true, cf: false, cur: 5 });
t("cmp_i: cur below imm -> CF, no ZF", { asm: `${li(4)}\ncmp $5, %cur`, zf: false, cf: true });
t("cmp_i: cur above imm -> neither", { asm: `${li(6)}\ncmp $5, %cur`, zf: false, cf: false });
t("cmp_i: is unsigned — 2^64-1 is above 1", { asm: `${li(MAX)}\ncmp $1, %cur`, zf: false, cf: false });
t("cmp_i: is unsigned — 0 is below 2^64-1", { asm: `${li(0)}\ncmp $${MAX}, %cur`, zf: false, cf: true });
t("cmp_i: compares all 64 bits", { asm: `${li("0x100000005")}\ncmp $5, %cur`, zf: false, cf: false });
t("cmp_i: recomputes both flags from scratch", { asm: `${li(5)}\ncmp $9, %cur\ncmp $5, %cur`, zf: true, cf: false });
t("cmp_i: preserves FF", { asm: `${FAULT}\ncmp $0, %cur`, frame: "", zf: true, ff: true });
t("cmp_r: equal -> ZF, no CF", { asm: `${li(7)}\nmov %cur, %s0\ncmp %s0, %cur`, zf: true, cf: false, cur: 7 });
t("cmp_r: cur below r[reg] -> CF", { asm: `${li(7)}\nmov %cur, %s0\n${li(6)}\ncmp %s0, %cur`, zf: false, cf: true });
t("cmp_r: cur above r[reg] -> neither", { asm: `${li(7)}\nmov %cur, %s0\n${li(8)}\ncmp %s0, %cur`, zf: false, cf: false });
t("cmp_r: is unsigned", { asm: `${li(MAX)}\nmov %cur, %s0\n${li(0)}\ncmp %s0, %cur`, zf: false, cf: true });
t("cmp_r: against an entry register", { asm: `${li(80)}\ncmp %dport, %cur`, opts: { dport: 80 }, zf: true });
t("cmp_r: %cur against itself is equal", { asm: `${li(3)}\ncmp %cur, %cur`, zf: true, cf: false });
t("cmp_r: preserves FF", { asm: `${FAULT}\ncmp %s0, %cur`, frame: "", zf: true, ff: true });

/* ---- 11 TEST -------------------------------------------------------------- */
t("test: an empty %m -> ZF", { asm: `test $0xff, %m`, zf: true });
t("test: any overlapping bit clears ZF", { asm: `test $0x6, %m`, flow: { mask: 0x4n }, zf: false });
t("test: disjoint bits -> ZF", { asm: `test $0x3, %m`, flow: { mask: 0x4n }, zf: true });
t("test: bit 63", { asm: `test $0x8000000000000000, %m`, flow: { mask: 1n << 63n }, zf: false });
t("test: a zero mask -> ZF", { asm: `test $0, %m`, flow: { mask: 0xffn }, zf: true });
t("test: reads %m, not %cur", { asm: `${li(0xff)}\ntest $0xff, %m`, zf: true, cur: 0xff });
t("test: clears CF", { asm: `${li(1)}\ncmp $2, %cur\ntest $1, %m`, zf: true, cf: false });
t("test: preserves FF", { asm: `${FAULT}\ntest $1, %m`, frame: "", ff: true });

/* ---- 12–18 the branches --------------------------------------------------- */
/* Truth table: each conditional branch after each outcome of `cmp $5, %cur`.
 * Taken lands on `rst $2`; not taken falls into `drop $1`. */
const OUTCOMES = { equal: 5, below: 4, above: 6 };
const TAKEN = {
  je: ["equal"], jne: ["below", "above"], jb: ["below"], jae: ["equal", "above"],
  ja: ["above"], jbe: ["equal", "below"],
};
for (const [jcc, when] of Object.entries(TAKEN)) {
  for (const [outcome, cur] of Object.entries(OUTCOMES)) {
    const taken = when.includes(outcome);
    t(`${jcc}: ${taken ? "taken" : "not taken"} when cur is ${outcome}`, {
      asm: `${li(cur)}\ncmp $5, %cur\n${jcc} hit\ndrop $1\nhit: rst $2, $0`,
      verdict: taken ? V.RST : V.DROP, rule: taken ? 2 : 1,
    });
  }
}
t("jz / jnz are je / jne", { asm: `${li(5)}\ncmp $5, %cur\njnz no\njz hit\nno: drop $1\nhit: rst $2, $0`, verdict: V.RST });
t("jmp: unconditional, skips what it jumps over", { asm: `jmp over\ndrop $1\nover: ${li(3)}`, cur: 3 });
t("jmp: lands exactly on its target", { asm: `${li(0)}\njmp l\nadd $1, %cur\nl: add $2, %cur\nadd $4, %cur`, cur: 6 });
t("branches: a taken branch leaves the flags as they were", { asm: `${li(4)}\ncmp $5, %cur\njb l\nl: and $0, %cur`, zf: false, cf: true });
t("branches: a not-taken branch leaves the flags as they were", { asm: `${li(5)}\ncmp $5, %cur\njne l\nl: and $0, %cur`, zf: true, cf: false });
t("branches: only jf consumes FF", { asm: `${FAULT}\ncmp $0, %cur\nje l\nl: jae m\nm: and $0, %cur`, frame: "", ff: true });

/* ---- 19 JF ---------------------------------------------------------------- */
t("jf: not taken while FF is clear", { asm: `jf hit\ndrop $1\nhit: rst $2, $0`, verdict: V.DROP });
t("jf: taken after a fault", { asm: `${FAULT}\njf hit\ndrop $1\nhit: rst $2, $0`, frame: "", verdict: V.RST });
t("jf: clears FF when taken", { asm: `${FAULT}\njf l\nl: and $0, %cur`, frame: "", ff: false });
t("jf: a second jf is not taken", { asm: `${FAULT}\njf a\na: jf hit\ndrop $1\nhit: rst $2, $0`, frame: "", verdict: V.DROP });
t("jf: leaves ZF/CF alone", { asm: `${FAULT}\ncmp $1, %cur\njf l\nl: and $0, %cur`, frame: "", zf: false, cf: true, ff: false });

/* ---- the forward-only rule (bytecode the assembler refuses to emit) -------- */
t("forward-only: a taken backward jump aborts with pass", { ops: [[OP.AND_I], [OP.JMP, 0, 0], [OP.DROP, 1]], verdict: V.PASS });
t("forward-only: a taken jump to itself aborts with pass", { ops: [[OP.JMP, 0, (pc) => pc], [OP.DROP, 1]], verdict: V.PASS });
t("forward-only: a taken conditional backward jump aborts with pass", { ops: [[OP.CMP_I, 0, 0], [OP.JE, 0, 0], [OP.DROP, 1]], payload: 0, verdict: V.PASS });
t("forward-only: a backward target is harmless when not taken", { ops: [[OP.CMP_I, 0, 1], [OP.JE, 0, 0], [OP.DROP, 1]], payload: 0, verdict: V.DROP, rule: 1 });
t("forward-only: a target past MAX_OPS aborts with pass", { ops: [[OP.JMP, 0, LIMITS.MAX_OPS + 1], [OP.DROP, 1]], verdict: V.PASS });
t("forward-only: a target past the program's end runs off it — pass", { ops: [[OP.JMP, 0, 100], [OP.DROP, 1]], verdict: V.PASS });
t("forward-only: the assembler rejects a backward label", { asm: `l: and $0, %cur\njmp l`, rejects: /jumps go forward only/ });

/* ---- 20 SCAN -------------------------------------------------------------- */
const PATS = `.pat get, "GET"\n.pat bot, "GPTBot"\n.pat curl, "curl"`; // ids 0, 1, 2
const REQ = "GET /x GPTBot/1.0";                                         // "GPTBot" is bytes [7, 13)
t("scan: a match sets the pattern's bit in %m", { asm: `${PATS}\nscan $64`, frame: "xx GPTBot xx", regs: { m: 0b010 } });
t("scan: every pattern is matched in one pass", { asm: `${PATS}\nscan $64`, frame: REQ, regs: { m: 0b011 } });
t("scan: no match leaves %m empty", { asm: `${PATS}\nscan $64`, frame: "nothing to see", regs: { m: 0 } });
t("scan: leaves %cur and the flags alone", { asm: `${PATS}\n${li(4)}\ncmp $5, %cur\nscan $64`, frame: REQ, cur: 4, zf: false, cf: true, ff: false });
t("scan: the window starts at the cursor", { asm: `${PATS}\n${li(1)}\nscan $64`, frame: REQ, regs: { m: 0b010 } });
t("scan: the window is imm bytes long", { asm: `${PATS}\nscan $13`, frame: REQ, regs: { m: 0b011 } });
t("scan: a match straddling the window's end is not seen", { asm: `${PATS}\nscan $12`, frame: REQ, regs: { m: 0b001 } });
t("scan: the window stops at %end", { asm: `${PATS}\n${li(12)}\nmov %cur, %end\nand $0, %cur\nscan $64`, frame: REQ, regs: { m: 0b001 } });
t("scan: an empty window (cursor at %end) matches nothing", { asm: `${PATS}\nmov %end, %cur\nscan $64`, frame: REQ, regs: { m: 0 }, ff: false });
t("scan: ORs into the %m it was given", { asm: `${PATS}\nscan $64`, frame: REQ, flow: { mask: 0b100000n }, regs: { m: 0b100011 } });
t("scan: two scans accumulate", { asm: `${PATS}\nscan $3\n${li(7)}\nscan $6`, frame: REQ, regs: { m: 0b011 } });
t("scan: the automaton carries across scans", { asm: `${PATS}\n${li(7)}\nscan $3\nadd $3, %cur\nscan $3`, frame: REQ, regs: { m: 0b010 } });
t("scan: suffix patterns all fire (failure links)", {
  asm: `.pat he, "he"\n.pat she, "she"\n.pat hers, "hers"\nscan $64`, frame: "ushers", regs: { m: 0b111 },
});
t("scan: is case-sensitive by default", { asm: `${PATS}\nscan $64`, frame: "gptbot GPTBOT", regs: { m: 0 } });
t("scan: .nocase folds the input", { asm: `.nocase\n${PATS}\nscan $64`, frame: "x gPtBoT x", regs: { m: 0b010 } });
t("scan: binary patterns", { asm: `.pat magic, 0x16 0x03 0x01\nscan $64`, frame: "\x00\x16\x03\x01\x02", regs: { m: 1 } });
t("fscan: clears %m first", { asm: `${PATS}\nfscan $64`, frame: REQ, flow: { mask: 0b100100n }, regs: { m: 0b011 } });
t("fscan: reports only what is inside this window", { asm: `${PATS}\nscan $3\n${li(7)}\nfscan $6`, frame: REQ, regs: { m: 0b010 } });
t("fscan: restarts the automaton", { asm: `${PATS}\n${li(7)}\nscan $3\nadd $3, %cur\nfscan $3`, frame: REQ, regs: { m: 0 } });

/* ---- 21 MPOS -------------------------------------------------------------- */
t("mpos: cur = one past the match's last byte", { asm: `${PATS}\nscan $64\nmpos $bot, %cur`, frame: REQ, cur: 13, ff: false });
t("mpos: the offset is absolute, not window-relative", { asm: `${PATS}\n${li(5)}\nscan $64\nmpos $bot, %cur`, frame: REQ, cur: 13 });
t("mpos: reports the first match, not a later one", { asm: `${PATS}\nscan $64\nmpos $get, %cur`, frame: "GET GET GET", cur: 3 });
t("mpos: each pattern has its own position", { asm: `${PATS}\nscan $64\nmpos $get, %cur\nmov %cur, %s0\nmpos $bot, %cur`, frame: REQ, cur: 13, regs: { s0: 3 } });
t("mpos: a pattern that never matched faults and leaves %cur", { asm: `${PATS}\n${li(2)}\nscan $64\nmpos $curl, %cur`, frame: REQ, cur: 2, ff: true });
t("mpos: with no scan at all, faults", { asm: `${PATS}\nmpos $get, %cur`, frame: REQ, cur: 0, ff: true });
t("mpos: leaves ZF/CF alone", { asm: `${PATS}\nscan $64\n${li(1)}\ncmp $2, %cur\nmpos $bot, %cur`, frame: REQ, zf: false, cf: true });
t("mpos: pattern ids above 31 keep their own position", {
  asm: `${Array.from({ length: 34 }, (_, i) => `.pat p${i}, "<${String.fromCharCode(65 + (i >> 4), 97 + (i & 15))}>"`).join("\n")}\nscan $64\nmpos $p33, %cur`,
  frame: "..<Ab>....<Cb>", cur: 14, regs: { m: (1n << 33n) | 2n },
});
t("mpos: survives a later fscan that misses", { asm: `${PATS}\nscan $64\nmov %end, %cur\nfscan $64\nmpos $bot, %cur`, frame: REQ, cur: 13, regs: { m: 0 } });

/* ---- 22 CMPSTR ------------------------------------------------------------ */
t("cmpstr: the bytes at the cursor equal the pattern -> ZF", { asm: `${PATS}\ncmpstr $get, (%cur)`, frame: REQ, zf: true, cur: 0 });
t("cmpstr: a mismatch clears ZF", { asm: `${PATS}\ncmpstr $bot, (%cur)`, frame: REQ, zf: false });
t("cmpstr: is anchored — not a search", { asm: `${PATS}\n${li(6)}\ncmpstr $bot, (%cur)`, frame: REQ, zf: false });
t("cmpstr: anchored at a moved cursor", { asm: `${PATS}\n${li(7)}\ncmpstr $bot, (%cur)`, frame: REQ, zf: true });
t("cmpstr: a mismatch in the last byte", { asm: `${PATS}\ncmpstr $bot, (%cur)`, frame: "GPTBox", zf: false });
t("cmpstr: a pattern running past %end is not equal", { asm: `${PATS}\ncmpstr $bot, (%cur)`, frame: "GPTBo", zf: false, ff: false });
t("cmpstr: a pattern ending exactly at %end is equal", { asm: `${PATS}\ncmpstr $bot, (%cur)`, frame: "GPTBot", zf: true });
t("cmpstr: with the cursor at %end is not equal", { asm: `${PATS}\nmov %end, %cur\ncmpstr $get, (%cur)`, frame: REQ, zf: false, ff: false });
t("cmpstr: is case-sensitive by default", { asm: `${PATS}\ncmpstr $get, (%cur)`, frame: "get /", zf: false });
t("cmpstr: .nocase folds both sides", { asm: `.nocase\n${PATS}\ncmpstr $get, (%cur)`, frame: "gEt /", zf: true });
t("cmpstr: clears CF", { asm: `${PATS}\n${li(0)}\ncmp $1, %cur\ncmpstr $get, (%cur)`, frame: REQ, zf: true, cf: false });
t("cmpstr: preserves FF", { asm: `${PATS}\n${FAULT}\nand $0, %cur\ncmpstr $get, (%cur)`, frame: REQ, zf: true, ff: true });
t("cmpstr: does not touch %m", { asm: `${PATS}\ncmpstr $get, (%cur)`, frame: REQ, regs: { m: 0 } });
t("cmpstr: an undeclared pattern slot just clears ZF/CF", {
  asm: `${PATS}\n${li(0)}\ncmp $0, %cur`, ops: [[OP.CMPSTR, 9]], frame: REQ, zf: false, cf: false,
});

/* ---- 23 FINDB ------------------------------------------------------------- */
t("findb: cur = the absolute offset of the byte", { asm: `findb $' ', $16`, frame: "ab cd", cur: 2, ff: false });
t("findb: offsets are absolute from a moved cursor", { asm: `${li(3)}\nfindb $' ', $16`, frame: "ab cd ef", cur: 5 });
t("findb: finds the first occurrence", { asm: `findb $'/', $16`, frame: "a/b/c", cur: 1 });
t("findb: a hit at the cursor itself", { asm: `${li(2)}\nfindb $' ', $16`, frame: "ab cd", cur: 2, ff: false });
t("findb: a miss faults and leaves %cur", { asm: `${li(1)}\nfindb $'!', $16`, frame: "ab cd", cur: 1, ff: true });
t("findb: the window is imm bytes long", { asm: `findb $' ', $2`, frame: "ab cd", cur: 0, ff: true });
t("findb: the last byte of the window is searched", { asm: `findb $' ', $3`, frame: "ab cd", cur: 2, ff: false });
t("findb: the window stops at %end", { asm: `${li(2)}\nmov %cur, %end\nand $0, %cur\nfindb $' ', $16`, frame: "ab cd", cur: 0, ff: true });
t("findb: with the cursor at %end, faults", { asm: `mov %end, %cur\nfindb $0, $16`, frame: "ab", cur: 2, ff: true });
t("findb: byte 0x00 and 0xff are ordinary bytes", { asm: `findb $0xff, $16\nmov %cur, %s0\nfindb $0, $16`, frame: "a\x00b\xff\x00", cur: 4, regs: { s0: 3 } });
t("findb: a hit clears a fault that was already pending", { asm: `${FAULT}\nand $0, %cur\nfindb $' ', $16`, frame: "ab cd", cur: 2, ff: false });
t("findb: leaves ZF/CF alone", { asm: `${li(0)}\ncmp $1, %cur\nfindb $' ', $16`, frame: "ab cd", zf: false, cf: true });

/* ---- 24 SKIPB ------------------------------------------------------------- */
t("skipb: advances past a run of the byte", { asm: `skipb $' '`, frame: "   X", cur: 3 });
t("skipb: no run leaves the cursor, and never faults", { asm: `skipb $' '`, frame: "X   ", cur: 0, ff: false });
t("skipb: from a moved cursor", { asm: `${li(2)}\nskipb $'-'`, frame: "ab---c", cur: 5 });
t("skipb: stops at $MAX", { asm: `skipb $' ', $2`, frame: "     X", cur: 2 });
t("skipb: stops at %end", { asm: `skipb $' '`, frame: "    ", cur: 4, ff: false });
t("skipb: with the cursor at %end does nothing", { asm: `mov %end, %cur\nskipb $' '`, frame: "    ", cur: 4, ff: false });
t("skipb: the default cap is SKIP_CAP", { asm: `skipb $' '`, frame: " ".repeat(SKIP_CAP + 6) + "X", cur: SKIP_CAP });
t("skipb: a cap above SKIP_CAP is SKIP_CAP", { asm: `skipb $' ', $${SKIP_CAP + 136}`, frame: " ".repeat(SKIP_CAP + 6) + "X", cur: SKIP_CAP });
t("skipb: a cap of exactly SKIP_CAP", { asm: `skipb $' ', $${SKIP_CAP}`, frame: " ".repeat(SKIP_CAP) + "X", cur: SKIP_CAP });
t("skipb: leaves the flags alone", { asm: `${li(0)}\ncmp $1, %cur\nskipb $' '`, frame: "   X", zf: false, cf: true, ff: false });

t.covers(OP.CMP_I, OP.CMP_R, OP.TEST, OP.JMP, OP.JE, OP.JNE, OP.JB, OP.JAE, OP.JA, OP.JBE, OP.JF, OP.SCAN, OP.MPOS, OP.CMPSTR, OP.FINDB, OP.SKIPB);
