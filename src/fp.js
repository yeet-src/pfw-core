/* Functional combinators over the dsl.js value builder: compose rules from
 * higher-order functions and closures instead of listing statements. A condition
 * is a value; a "guard" is a (condition -> statement); a rule fragment is just a
 * statement (or a closure that returns one, capturing its parameters). Because
 * everything is still a plain AST value, fragments compose freely and a
 * parameterized fragment is an ordinary closure.
 *
 *   import * as C from "pfw-core/dsl";
 *   import { when, guard, allOf } from "pfw-core/fp";
 *
 *   // a reusable fragment — a closure capturing the pattern + verdict
 *   const blockUA = (pat, verdict) => guard(C.band(C.scan(C.payload, 1460), pat), verdict);
 *
 *   C.program(
 *     C.nocase(), C.pattern("gptbot", "GPTBot"), C.pattern("claudebot", "ClaudeBot"),
 *     C.filter(
 *       guard(C.ne(C.dport, 80), C.pass()),
 *       blockUA("gptbot", C.rst("crawler", 60)),
 *       blockUA("claudebot", C.rst("crawler", 60)),
 *       C.pass(),
 *     ),
 *   );
 */
import * as C from "#/dsl.js";

/* ---- condition combinators (fold a list of conditions) ---- */
export const allOf = (...conds) => conds.flat().reduce((a, b) => C.and(a, b));
export const anyOf = (...conds) => conds.flat().reduce((a, b) => C.or(a, b));
export const none = (...conds) => C.not(anyOf(...conds));

/* ---- guards (condition -> statement) ---- */
/** `guard(cond, stmt)` — run stmt when cond holds (one statement). */
export const guard = (cond, stmt) => C.iff(cond, stmt);
/** `when(cond)(...body)` — curried: a block that runs when cond holds. */
export const when = (cond) => (...body) => C.iff(cond, C.block(...body.flat()));
/** `unless(cond)(...body)` — the negation. */
export const unless = (cond) => (...body) => C.iff(C.not(cond), C.block(...body.flat()));

/* ---- a matcher as a small fluent value (scan once, test many ways) ---- */
/** `match(C.scan(payload, n))` → { any, all, seq } building conditions. */
export const match = (windowOrMask) => ({
  any: (...pats) => C.any(windowOrMask, ...pats),
  all: (...pats) => C.all(windowOrMask, ...pats),
  seq: (...pats) => C.seq(windowOrMask, ...pats),
  has: (pat) => C.band(windowOrMask, pat),
});

/* ---- composition helpers ---- */
/** Flatten nested fragment lists into a filter body (fragments may be arrays). */
export const rules = (...frags) => C.filter(...frags.flat(Infinity));
/** map a list of inputs to fragments with a closure, as one spreadable group. */
export const each = (xs, f) => xs.map(f);
