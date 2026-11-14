/* Aho-Corasick over the program's patterns, as the sparse tables the
 * kernel reads: explicit trie edges in `ac_goto[state*256 + byte]`,
 * failure links in `ac_fail[state]`, and a u64 accept mask per state in
 * `ac_accept[state]` with suffix patterns propagated down the failure
 * links at build time. The kernel follows the failure chain per byte,
 * so the goto table stays at ~states entries rather than states × 256.
 *
 * build(patterns, nocase) → { edges, fails, accepts, count }
 *   edges   [[state*256+byte, next]]   next ≥ 1 (0 means no edge)
 *   fails   [[state, fail]]            non-root links only
 *   accepts [[state, mask]]            BigInt masks, non-zero only
 */
import { LIMITS } from "#/isa.js";

export function build(patterns, nocase = false) {
  const go = [new Map()];
  const accept = [0n];
  const fold = (b) => (nocase && b >= 65 && b <= 90 ? b + 32 : b);

  for (const { id, bytes, kind } of patterns) {
    if (kind === "regex") continue; /* regex patterns are matched by the DFA, not the automaton */
    let s = 0;
    for (const raw of bytes) {
      const b = fold(raw);
      let next = go[s].get(b);
      if (next === undefined) {
        next = go.length;
        if (next >= LIMITS.AC_STATES) throw new Error(`automaton needs more than ${LIMITS.AC_STATES} states`);
        go[s].set(b, next);
        go.push(new Map());
        accept.push(0n);
      }
      s = next;
    }
    accept[s] |= 1n << BigInt(id);
  }

  const fail = new Array(go.length).fill(0);
  const queue = [];
  for (const [, c] of go[0]) queue.push(c);
  for (let qi = 0; qi < queue.length; qi++) {
    const r = queue[qi];
    for (const [b, u] of go[r]) {
      let s = fail[r];
      while (s !== 0 && !go[s].has(b)) s = fail[s];
      const f = go[s].get(b);
      fail[u] = f !== undefined && f !== u ? f : 0;
      accept[u] |= accept[fail[u]];
      queue.push(u);
    }
  }

  const edges = [];
  for (let s = 0; s < go.length; s++) for (const [b, next] of go[s]) edges.push([s * 256 + b, next]);
  const fails = [];
  for (let s = 1; s < go.length; s++) if (fail[s]) fails.push([s, fail[s]]);
  const accepts = [];
  for (let s = 0; s < go.length; s++) if (accept[s]) accepts.push([s, accept[s]]);
  return { edges, fails, accepts, count: go.length };
}

/** Run the automaton in JS over `bytes`, for tests: the mask of patterns seen. */
export function scan(tables, bytes, nocase = false) {
  const goto = new Map(tables.edges);
  const failOf = new Map(tables.fails);
  const acceptOf = new Map(tables.accepts);
  let s = 0;
  let mask = 0n;
  for (const raw of bytes) {
    const b = nocase && raw >= 65 && raw <= 90 ? raw + 32 : raw;
    for (;;) {
      const next = goto.get(s * 256 + b);
      if (next) {
        s = next;
        break;
      }
      if (s === 0) break;
      s = failOf.get(s) ?? 0;
    }
    mask |= acceptOf.get(s) ?? 0n;
  }
  return mask;
}
