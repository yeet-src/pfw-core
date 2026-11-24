/* The range pool the loader lays programs out with (src/pool.js). */
import { Pool, PoolError } from "#/pool.js";

const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const throws = (fn, m) => { try { fn(); } catch (e) { if (e instanceof PoolError) return e; throw e; } throw new Error(`${m}: did not throw`); };

yeet.test("ranges are consecutive, first fit, and do not overlap", () => {
  const p = new Pool(100);
  eq(p.take(10).base, 0, "first");
  eq(p.take(20).base, 10, "second");
  eq(p.take(70).base, 30, "the rest");
  eq(p.free, 0, "full");
  throws(() => p.take(1), "a full pool");
});

yeet.test("a range given back is reused, and joins its neighbours", () => {
  const p = new Pool(100);
  const a = p.take(10), b = p.take(10), c = p.take(10);
  p.give(b);
  const b2 = p.take(10);
  eq(b2.base, b.base, "the gap is reused");
  p.give(a); p.give(c);
  eq(p.largest, 80, "c joined the 70 free above it; a stands alone below");
  p.give(b2);
  eq(p.largest, 100, "all one range again");
  eq(p.take(100).base, 0, "and it can be taken whole");
});

yeet.test("the largest program and its replacement fit side by side", () => {
  const p = new Pool(2 * 4096);
  const old = p.take(4096), next = p.take(4096);
  eq(old.base !== next.base, true, "two ranges");
  p.give(old);
  eq(p.take(4096).base, old.base, "and the next replacement takes the first one's place");
});

yeet.test("an empty range takes nothing, and giving it back frees nothing", () => {
  const p = new Pool(4);
  const none = p.take(0);
  eq(none.base, 0, "it sits at 0");
  const all = p.take(4);
  eq(all.base, 0, "where a real range may begin");
  p.give(none);
  eq(p.free, 0, "the real range at 0 is still held");
  p.give(all);
  eq(p.free, 4, "until its own owner gives it back");
});

yeet.test("fragmentation is reported, not hidden", () => {
  const p = new Pool(30);
  const a = p.take(10); p.take(10); const c = p.take(10);
  p.give(a); p.give(c);
  eq(p.free, 20, "twenty free");
  const e = throws(() => p.take(15), "no gap of fifteen");
  if (!/20 of 30 free/.test(e.message) || !/largest gap 10/.test(e.message)) throw new Error("unhelpful: " + e.message);
});

yeet.test("giving back twice, or a range from elsewhere, changes nothing", () => {
  const p = new Pool(10), other = new Pool(10);
  const a = p.take(4);
  p.give(a); p.give(a);
  eq(p.free, 10, "whole");
  p.take(10);
  p.give(other.take(10));
  p.give({ base: 0, len: 10 });
  eq(p.free, 0, "another pool's range, or a look-alike, frees nothing here");
  throws(() => p.take(-1), "a negative length");
  throws(() => p.take(1.5), "a fractional length");
});
