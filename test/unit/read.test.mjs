/* Direct reads — u8(p), be16(p), ... : one field of the packet at a pointer,
 * without a one-record `frame` to carry it. */
import { fromC, V } from "./helpers.mjs";
import { compile } from "#/clang";

const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const run = (src, bytes, opts = {}) => fromC(src).run(Uint8Array.from(bytes), {}, opts).verdict;

yeet.test("each width and byte order reads what the bytes say", () => {
  const b = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
  const is = (expr, want) => eq(run(`filter { if (${expr} == ${want}) decide drop("y"); decide pass; }`, b), V.DROP, `${expr} == ${want}`);
  is("u8(payload)", "0x12");
  is("u8(payload + 7)", "0xf0");
  is("u16(payload)", "0x3412");
  is("be16(payload)", "0x1234");
  is("be16(payload + 6)", "0xdef0");
  is("be24(payload)", "0x123456");
  is("u32(payload)", "0x78563412");
  is("be32(payload + 4)", "0x9abcdef0");
  is("be64(payload)", "0x123456789abcdef0");
  is("u64(payload)", "0xf0debc9a78563412");
});

yeet.test("a read is a value: in a let, in arithmetic, on either side of a comparison", () => {
  const b = [3, 0, 7, 9];
  eq(run(`filter { let n = u8(payload) + u8(payload + 2); if (n == 10) decide drop("y"); decide pass; }`, b), V.DROP, "sum of two reads");
  eq(run(`filter { let p = payload + u8(payload); if (u8(p) == 9) decide drop("y"); decide pass; }`, b), V.DROP, "a read as an offset");
  eq(run(`filter { let seven = 7; if (seven == u8(payload + 2)) decide drop("y"); decide pass; }`, b), V.DROP, "on the right of ==");
  eq(run(`filter { let fl = u8(payload + 2) & 6; if (fl != 6) decide pass; decide drop("y"); }`, b), V.DROP, "masked, as TCP flags are");
});

yeet.test("a read past the end is 0, not the address and not a crash", () => {
  const b = [1, 2, 3];
  eq(run(`filter { if (u8(payload + 3) == 0) decide drop("zero"); decide pass; }`, b), V.DROP, "one past the end");
  eq(run(`filter { if (be32(payload) == 0) decide drop("zero"); decide pass; }`, b), V.DROP, "four bytes where three remain");
  eq(run(`filter { if (be16(payload + 1) == 0x0203) decide drop("fits"); decide pass; }`, b), V.DROP, "the last two bytes are readable");
  eq(run(`filter { if (be24(payload) == 0x010203) decide drop("fits"); decide pass; }`, b), V.DROP, "be24 of exactly three bytes");
});

yeet.test("a fault left by an earlier find does not zero a read that works", () => {
  // find('!') fails and leaves the fault flag set; the read after it is fine.
  const s = `filter { ptr z = find(payload, '!', 4); if (u8(payload + 1) == 0x62) decide drop("read"); decide pass; }`;
  eq(run(s, [0x61, 0x62, 0x63, 0x64]), V.DROP, "the read is not poisoned");
});

yeet.test("reads see a frame's narrowed end", () => {
  // Two records of [len, bytes...]. Inside the first, a read one past its
  // last byte is past the end, even though the packet goes on.
  const s = `filter { frame (len = u8 @ 0, head = 1) up to 1 { if (u8(frame.data + 2) == 0) decide drop("clipped"); } decide pass; }`;
  eq(run(s, [2, 0xaa, 0xbb, 1, 0xcc]), V.DROP, "the next record's length byte is not visible");
});

yeet.test("TCP flags, the case this replaces a frame for", () => {
  // A 20-byte TCP header at offset 0; flags are byte 13.
  const tcp = (flags) => { const h = new Array(24).fill(0); h[13] = flags; return h; };
  const s = `filter { let opening = u8(l4 + 13) & 18; if (opening == 2) decide drop("syn"); decide pass; }`;
  eq(run(s, tcp(0x02)), V.DROP, "SYN");
  eq(run(s, tcp(0x12)), V.PASS, "SYN+ACK");
  eq(run(s, tcp(0x10)), V.PASS, "ACK");
});

yeet.test("a read needs its parentheses and one argument", () => {
  eq(compile(`filter { let u8 = 3; if (u8 == 3) decide drop("y"); decide pass; }`).ok, true, "u8 alone is still a name");
  eq(compile(`filter { let x = u8(payload, 2); decide pass; }`).ok, false, "two arguments");
});
