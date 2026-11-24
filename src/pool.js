/* A pool of consecutive slots that several owners share: each takes a range and
 * gives it back. The kernel's program tables are pools (instructions, automaton
 * states, table cells, rule counters), and a program's share of each is a base
 * and a length.
 *
 *   const pool = new Pool(1024, "rules");
 *   const range = pool.take(12);    // { base, len }: 12 consecutive slots, first fit
 *   pool.give(range);               // all 12 back
 *
 * What comes back from take() is the range itself, and give() wants that same
 * object: an empty range sits at base 0, where somebody else's real one may
 * begin, and a bare number could not tell the two apart. Ranges never move, so
 * a base handed out stays valid until its range is given back.
 */
export class PoolError extends Error {}

export class Pool {
  #free;                 // [base, len], sorted by base, no two adjacent
  #taken = new Set();    // the ranges handed out and not yet given back

  constructor(size, name = "pool") {
    this.size = size;
    this.name = name;
    this.#free = size > 0 ? [[0, size]] : [];
  }

  /** Slots not taken. */
  get free() { return this.#free.reduce((n, [, len]) => n + len, 0); }

  /** The largest range `take` could hand out now. */
  get largest() { return this.#free.reduce((n, [, len]) => Math.max(n, len), 0); }

  /** A range of `len` consecutive slots, as `{ base, len }`. Throws PoolError
   *  if no gap is that long. */
  take(len) {
    if (!Number.isInteger(len) || len < 0) throw new PoolError(`${this.name}: a range is a whole number of slots, not ${len}`);
    let base = 0;
    if (len > 0) {
      const i = this.#free.findIndex(([, have]) => have >= len);
      if (i < 0) throw new PoolError(`${this.name}: no room for ${len} (${this.free} of ${this.size} free, the largest gap ${this.largest})`);
      const have = this.#free[i][1];
      base = this.#free[i][0];
      if (have === len) this.#free.splice(i, 1);
      else this.#free[i] = [base + len, have - len];
    }
    const range = Object.freeze({ base, len });
    this.#taken.add(range);
    return range;
  }

  /** Give back a range `take` returned. One already given back, or one this
   *  pool never handed out, is left alone. */
  give(range) {
    if (!this.#taken.delete(range) || range.len === 0) return;
    const { base, len } = range;
    let i = this.#free.findIndex(([b]) => b > base);
    if (i < 0) i = this.#free.length;
    this.#free.splice(i, 0, [base, len]);
    // Join it to the neighbour above, then the one below.
    if (i + 1 < this.#free.length && this.#free[i][0] + this.#free[i][1] === this.#free[i + 1][0]) { this.#free[i][1] += this.#free[i + 1][1]; this.#free.splice(i + 1, 1); }
    if (i > 0 && this.#free[i - 1][0] + this.#free[i - 1][1] === this.#free[i][0]) { this.#free[i - 1][1] += this.#free[i][1]; this.#free.splice(i, 1); }
  }
}
