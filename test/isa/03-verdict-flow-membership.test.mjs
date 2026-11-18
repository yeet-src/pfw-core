/* ISA conformance — verdicts, per-flow / per-source state, the ring, membership.
 * Spec: docs/isa/instructions/03-verdict-flow-and-membership.md, docs/isa/03-memory-model.md. */
import { isa, li, OP, V } from "./harness.mjs";

const t = isa("verdict/flow/member");
const FAULT = `mov %end, %cur\nmovb 0(%cur), %cur`;
const ip = (a, b, c, d) => ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;

/* ---- 25–30 verdicts ------------------------------------------------------- */
t("pass: terminal", { asm: `pass\ndrop $1`, verdict: V.PASS, rule: 0 });
t("drop: terminal, records the rule", { asm: `drop $3\nrst $4, $0`, verdict: V.DROP, rule: 3 });
t("ban: terminal, records the rule", { asm: `ban $5, $60\ndrop $1`, verdict: V.BAN, rule: 5 });
t("rst: terminal, records the rule", { asm: `rst $6, $60\ndrop $1`, verdict: V.RST, rule: 6 });
t("ban / rst: the ttl is optional", { asm: `ban $7`, verdict: V.BAN, rule: 7 });
t("drop: the highest rule id", { asm: `drop $63`, verdict: V.DROP, rule: 63 });
t("drop: the rule id is masked to 6 bits", { ops: [[OP.DROP, 64 + 5]], verdict: V.DROP, rule: 5 });
t("rst: the rule id is masked to 6 bits", { ops: [[OP.RST, 128 + 9]], verdict: V.RST, rule: 9 });
t("count: not terminal — execution continues", { asm: `count $2\ndrop $1`, verdict: V.DROP, rule: 1 });
t("count: leaves %cur and the flags alone", { asm: `${li(4)}\ncmp $5, %cur\ncount $2`, cur: 4, zf: false, cf: true, ff: false });
t("log: not terminal — execution continues", { asm: `log $16\ndrop $1`, verdict: V.DROP });
t("log: leaves %cur and the flags alone", { asm: `${li(4)}\ncmp $5, %cur\nlog $16`, cur: 4, zf: false, cf: true, ff: false });
t("shadow: an enforcement verdict is reported as pass", { asm: `drop $3`, opts: { shadow: true }, verdict: V.PASS, rule: 3 });
t("shadow: %shadow reads 1", { ops: [], opts: { shadow: true }, regs: { shadow: 1 } });
t("shadow: %shadow reads 0 when enforcing", { ops: [], regs: { shadow: 0 } });

/* ---- 31 FLOW / 32 MARK ---------------------------------------------------- */
t("flow: cur = the flow's mark", { asm: `flow %cur`, flow: { mark: 16 }, cur: 16 });
t("flow: an untracked flow reads 0", { asm: `${li(9)}\nflow %cur`, cur: 0 });
t("flow: leaves the flags alone", { asm: `${li(4)}\ncmp $5, %cur\nflow %cur`, zf: false, cf: true });
t("mark: the write is deferred — flow still reads the entry value", { asm: `mark $17\nflow %cur`, flow: { mark: 16 }, cur: 16 });
t("mark: visible on the next packet", { asm: `mark $17\nflow %cur`, packets: 2, cur: 17 });
t("mark: the last mark of a packet wins", { asm: `flow %cur\nmark $17\nmark $18`, packets: 2, cur: 18 });
t("mark: not terminal, leaves %cur", { asm: `${li(4)}\nmark $17`, cur: 4 });
t("mark: values below 16 are reserved", { asm: `mark $2`, rejects: /user marks start at 16/ });

/* ---- 33 SLOAD / 34 SSTORE ------------------------------------------------- */
t("sload: cur = the flow's user state", { asm: `sload %cur`, flow: { userState: 7 }, cur: 7 });
t("sload: a fresh flow reads 0", { asm: `${li(9)}\nsload %cur`, cur: 0 });
t("sload: leaves the flags alone", { asm: `${li(4)}\ncmp $5, %cur\nsload %cur`, zf: false, cf: true });
t("sstore: the write is deferred — sload still reads the entry value", { asm: `sstore $9\nsload %cur`, flow: { userState: 7 }, cur: 7 });
t("sstore: visible on the next packet", { asm: `sload %cur\nsstore $9`, packets: 2, cur: 9 });
t("sstore: the last store of a packet wins", { asm: `sload %cur\nsstore $9\nsstore $10`, packets: 2, cur: 10 });
t("sstore: without a store the state carries over", { asm: `sload %cur`, flow: { userState: 7 }, packets: 3, cur: 7 });
t("sstore: keeps the low 32 bits", { asm: `sload %cur`, ops: [[OP.SSTORE, 0, 0xffffffffn]], packets: 2, cur: 0xffffffff });
t("sstore: not terminal, leaves %cur and the flags", { asm: `${li(4)}\ncmp $5, %cur\nsstore $9`, cur: 4, zf: false, cf: true });
t("sstore: flow scope does not write the source", { asm: `srcload %cur\nsstore $9`, opts: { source: {} }, packets: 2, cur: 0 });
t("srcload: cur = the source's state", { asm: `srcload %cur`, opts: { source: { userState: 5 } }, cur: 5 });
t("srcstore: deferred, visible on the next packet", { asm: `srcload %cur\nsrcstore $9`, opts: { source: {} }, packets: 2, cur: 9 });
t("srcstore: deferred within the packet", { asm: `srcstore $9\nsrcload %cur`, opts: { source: { userState: 5 } }, cur: 5 });
t("srcstore: source scope does not write the flow", { asm: `sload %cur\nsrcstore $9`, opts: { source: {} }, packets: 2, cur: 0 });

/* ---- 35 BUMP -------------------------------------------------------------- */
t("bump: cur = the incremented hit counter", { asm: `${li(9)}\nbump %cur`, cur: 1 });
t("bump: counts from the flow's stored value", { asm: `bump %cur`, flow: { hits: 41 }, cur: 42 });
t("bump: every execution counts", { asm: `bump %cur\nbump %cur\nbump %cur`, cur: 3 });
t("bump: persists across packets", { asm: `bump %cur`, packets: 4, cur: 4 });
t("bump: wraps at 32 bits", { asm: `bump %cur`, flow: { hits: 0xffffffff }, cur: 0 });
t("bump: leaves the flags alone", { asm: `${li(4)}\ncmp $5, %cur\nbump %cur`, zf: false, cf: true });
t("srcbump: counts per source, apart from the flow", { asm: `bump %cur\nsrcbump %cur\nsrcbump %cur`, opts: { source: { hits: 10 } }, cur: 12 });
t("srcbump: persists across packets", { asm: `srcbump %cur`, opts: { source: {} }, packets: 3, cur: 3 });

/* ---- 39 CIDR -------------------------------------------------------------- */
const cidr = (addr, net) => `${li(addr)}\ncidr ${net}`;
t("cidr: an address inside the network -> ZF", { asm: cidr(ip(10, 1, 2, 3), "10.0.0.0/8"), zf: true });
t("cidr: an address outside clears ZF", { asm: cidr(ip(11, 0, 0, 1), "10.0.0.0/8"), zf: false });
t("cidr: /0 matches everything", { asm: cidr(ip(203, 0, 113, 9), "0.0.0.0/0"), zf: true });
t("cidr: /32 matches exactly one address", { asm: cidr(ip(192, 168, 1, 7), "192.168.1.7/32"), zf: true });
t("cidr: /32 rejects its neighbour", { asm: cidr(ip(192, 168, 1, 6), "192.168.1.7/32"), zf: false });
t("cidr: a prefix off the octet boundary — last address in", { asm: cidr(ip(172, 31, 255, 255), "172.16.0.0/12"), zf: true });
t("cidr: a prefix off the octet boundary — first address out", { asm: cidr(ip(172, 32, 0, 0), "172.16.0.0/12"), zf: false });
t("cidr: /31 holds two addresses", { asm: cidr(ip(10, 0, 0, 3), "10.0.0.2/31"), zf: true });
t("cidr: /1 splits on the top bit", { asm: cidr(ip(128, 0, 0, 0), "0.0.0.0/1"), zf: false });
t("cidr: host bits in the network literal are ignored", { asm: cidr(ip(10, 9, 9, 9), "10.1.2.3/8"), zf: true });
t("cidr: only the low 32 bits of %cur are the address", { asm: cidr("0xdeadbeef0a000001", "10.0.0.0/8"), zf: true });
t("cidr: a prefix above 32 behaves as /32", { asm: li(ip(10, 0, 0, 1)), ops: [[OP.CIDR, 0, (40n << 32n) | BigInt(ip(10, 0, 0, 1))]], zf: true });
t("cidr: tests %cur, typically loaded from %saddr", { asm: `mov %saddr, %cur\ncidr 127.0.0.0/8`, opts: { saddr: ip(127, 0, 0, 1) }, zf: true, cur: ip(127, 0, 0, 1) });
t("cidr: clears CF", { asm: `${li(0)}\ncmp $1, %cur\ncidr 10.0.0.0/8`, zf: false, cf: false });
t("cidr: preserves FF", { asm: `${FAULT}\ncidr 0.0.0.0/0`, frame: "", zf: true, ff: true });

/* ---- 40 RPUSH / 41 RGET / 42 RLEN ----------------------------------------- */
const pushes = (n, base = 100) => Array.from({ length: n }, (_, i) => `${li(base + i)}\nrpush %cur`).join("\n");
const rget = (i) => `${li(i)}\nrget %cur`;
t("rlen: an empty ring is 0", { asm: `${li(9)}\nrlen %cur`, cur: 0 });
t("rpush: grows the ring, leaves %cur", { asm: `${li(99)}\nrpush %cur\nmov %cur, %s0\nrlen %cur`, cur: 1, regs: { s0: 99 } });
t("rget: index 0 is the newest entry", { asm: `${pushes(3)}\n${rget(0)}`, cur: 102, ff: false });
t("rget: higher indices go back in time", { asm: `${pushes(3)}\n${rget(2)}`, cur: 100, ff: false });
t("rget: one past the oldest faults and reads 0", { asm: `${pushes(3)}\n${rget(3)}`, cur: 0, ff: true });
t("rget: an empty ring faults and reads 0", { asm: rget(0), cur: 0, ff: true });
t("rget: a stored 0 is told from absent by FF", { asm: `${li(0)}\nrpush %cur\n${rget(0)}`, cur: 0, ff: false });
t("rget: the index is the low 32 bits of %cur", { asm: `${pushes(2)}\n${li("0x100000001")}\nrget %cur`, cur: 100, ff: false });
t("rget: leaves ZF/CF alone", { asm: `${pushes(1)}\n${li(0)}\ncmp $1, %cur\nrget %cur`, zf: false, cf: true });
t("rpush: stores the low 32 bits", { asm: `${li("0xabcdef0123456789")}\nrpush %cur\n${rget(0)}`, cur: 0x23456789 });
t("rpush: touches no flag", { asm: `${li(4)}\ncmp $5, %cur\nrpush %cur`, zf: false, cf: true, ff: false });
t("ring: holds 16 entries", { asm: `${pushes(16)}\n${rget(15)}`, cur: 100, ff: false });
t("ring: rlen saturates at 16", { asm: `${pushes(20)}\nrlen %cur`, cur: 16 });
t("ring: the 17th push overwrites the oldest", { asm: `${pushes(17)}\n${rget(15)}`, cur: 101, ff: false });
t("ring: newest stays at index 0 after wrapping", { asm: `${pushes(17)}\n${rget(0)}`, cur: 116 });
t("ring: index 16 always faults", { asm: `${pushes(20)}\n${rget(16)}`, cur: 0, ff: true });
t("ring: persists across the flow's packets", { asm: `rlen %cur\nmov %cur, %s0\n${li(7)}\nrpush %cur`, packets: 3, regs: { s0: 2 } });

/* ---- 46 LPM / 47 HASH / 48 BLOOM / 49 LPM6 --------------------------------- */
const SET = [{ net: BigInt(ip(10, 0, 0, 0)), mask: 0xff000000n }, { net: BigInt(ip(192, 168, 4, 0)), mask: 0xffffff00n }];
t("lpm: an address under a prefix in the set -> ZF", { asm: `${li(ip(192, 168, 4, 200))}\nlpm`, opts: { set: SET }, zf: true });
t("lpm: an address under no prefix clears ZF", { asm: `${li(ip(192, 168, 5, 1))}\nlpm`, opts: { set: SET }, zf: false });
t("lpm: an empty set matches nothing", { asm: `${li(ip(10, 0, 0, 1))}\nlpm`, zf: false });
t("lpm: clears CF, preserves FF, leaves %cur", { asm: `${FAULT}\ncmp $1, %cur\nlpm`, frame: "", opts: { set: SET }, zf: false, cf: false, ff: true, cur: 0 });
t("hash: a member -> ZF", { asm: `${li(31337)}\nhash`, opts: { hashset: [22, 31337] }, zf: true });
t("hash: a non-member clears ZF", { asm: `${li(80)}\nhash`, opts: { hashset: [22, 31337] }, zf: false });
t("hash: an empty set matches nothing", { asm: `${li(0)}\nhash`, zf: false });
t("hash: the key is the low 32 bits of %cur", { asm: `${li("0x700000016")}\nhash`, opts: { hashset: [22] }, zf: true });
t("hash: clears CF, preserves FF, leaves %cur", { asm: `${FAULT}\ncmp $1, %cur\nhash`, frame: "", opts: { hashset: [0] }, zf: true, cf: false, ff: true, cur: 0 });
t("bloom: a member -> ZF (never a false negative)", { asm: `${li(1234)}\nbloom`, opts: { bloom: [1234] }, zf: true });
t("bloom: an empty filter matches nothing", { asm: `${li(1234)}\nbloom`, zf: false });
t("bloom: the element is the low 32 bits of %cur", { asm: `${li("0x1000004d2")}\nbloom`, opts: { bloom: [1234] }, zf: true });
t("bloom: clears CF, preserves FF", { asm: `${FAULT}\ncmp $1, %cur\nbloom`, frame: "", zf: false, cf: false, ff: true });
const V6 = (hi) => BigInt(hi) << 96n;
const SET6 = [{ net: V6(0x20010db8), mask: V6(0xffffffff) }];
t("lpm6: the IPv6 source under a prefix in the set -> ZF", { asm: `lpm6`, opts: { src6: V6(0x20010db8) | 1n, set6: SET6 }, zf: true });
t("lpm6: a source under no prefix clears ZF", { asm: `lpm6`, opts: { src6: V6(0x20010db9) | 1n, set6: SET6 }, zf: false });
t("lpm6: tests the source address, not %cur", { asm: `${li("0x20010db8")}\nlpm6`, opts: { src6: 1n, set6: SET6 }, zf: false, cur: 0x20010db8 });
t("lpm6: an empty set matches nothing", { asm: `lpm6`, opts: { src6: 1n }, zf: false });

/* ---- 72 FLOAD / 73 FSTORE -------------------------------------------------- */
/* The default frame is 64 bytes with %payload at 0, so a packet is 64 bytes of payload. */
t("fload: a flow register starts at zero", { asm: `fload $0`, cur: 0 });
t("fload: reads what the flow held at entry", { asm: `fload $2`, flow: { ureg: [0n, 0n, 77n, 0n] }, cur: 77 });
t("fstore: a store is read back in the same run", { asm: `${li(9)}\nfstore $1\n${li(0)}\nfload $1`, cur: 9 });
t("fstore: and on the next packet", { asm: `fload $1\nmov %cur, %s0\n${li(9)}\nfstore $1\nmov %s0, %cur`, packets: 2, cur: 9 });
t("fstore: writes one register and not its neighbours", { asm: `${li(9)}\nfstore $1\nfload $0\nmov %cur, %s0\nfload $2\nadd %s0, %cur`, cur: 0 });
t("fstore: holds a full 64-bit value across packets", { asm: `fload $3\nmov %cur, %s0\n${li("0xffffffffffffffff")}\nfstore $3\nmov %s0, %cur`, packets: 2, cur: "0xffffffffffffffff" });
t("fstore: a counter kept by the program — add one each packet", { asm: `fload $0\nadd $1, %cur\nfstore $0`, packets: 5, cur: 5 });
t("fstore: without a store the registers carry over", { asm: `fload $2`, flow: { ureg: [0n, 0n, 5n, 0n] }, packets: 3, cur: 5 });
t("fstore: the register index is masked to 2 bits", { asm: li(4), ops: [[OP.FSTORE, 4 + 1], [OP.FLOAD, 1]], cur: 4 });
t("fload/fstore: touch no flag", { asm: `${li(1)}\ncmp $1, %cur\nfstore $0\nfload $0`, zf: true, cf: false, ff: false });
t("fload bytes: this packet's payload is already counted", { asm: `fload $bytes`, cur: 64 });
t("fload bytes: sums the payload of the flow's packets", { asm: `fload $bytes`, packets: 3, cur: 192 });
t("fload bytes: on top of what the flow had", { asm: `fload $bytes`, flow: { bytes: 1000n }, cur: 1064 });
t("fload bytes: counts payload, not headers", { asm: `fload $bytes`, frame: new Uint8Array(40), payload: 30, packets: 2, cur: 20 });
t("fload packets: this packet is the first", { asm: `fload $packets`, cur: 1 });
t("fload packets: counts every packet of the flow", { asm: `fload $packets`, packets: 4, cur: 4 });
t("fload: the assembler refuses a register past 3", { asm: `fload $6`, rejects: /flow register/ });
t("fstore: the assembler refuses to store to the counts", { asm: `fstore $bytes`, rejects: /0–3/ });

t.covers(OP.FLOAD, OP.FSTORE);
t.covers(OP.PASS, OP.DROP, OP.COUNT, OP.LOG, OP.BAN, OP.RST, OP.FLOW, OP.MARK, OP.SLOAD, OP.SSTORE, OP.BUMP, OP.CIDR, OP.RPUSH, OP.RGET, OP.RLEN, OP.LPM, OP.HASH, OP.BLOOM, OP.LPM6);
