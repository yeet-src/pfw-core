/* The restricted-regex -> DFA compiler (src/regex.js): compile several regexes
 * into one DFA with a per-regex accept bit, then walk it over strings (the same
 * one-byte-per-step match the kernel will do). Covers char classes, quantifiers,
 * alternation, anchoring-anywhere, and that each regex's bit is independent. */
import { compileRegexes, runDFA } from "#/regex.js";

const enc = (s) => [...new TextEncoder().encode(s)];
const has = (dfa, s, bit) => ((runDFA(dfa, enc(s)) >> BigInt(bit)) & 1n) === 1n;
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("PII patterns: SSN / email / card, each on its own bit", () => {
  const dfa = compileRegexes([
    { src: "\\d{3}-\\d{2}-\\d{4}", bit: 0 },
    { src: "[a-z0-9._]+@[a-z0-9.]+\\.[a-z]+", bit: 1 },
    { src: "\\d{13,16}", bit: 2 },
  ]);
  eq(has(dfa, "ssn 123-45-6789 here", 0), true, "ssn");
  eq(has(dfa, "123-456-789", 0), false, "ssn wrong shape");
  eq(has(dfa, "mail bob@example.com", 1), true, "email");
  eq(has(dfa, "ssn 123-45-6789", 1), false, "ssn is not email");
  eq(has(dfa, "card 4111111111111111", 2), true, "16-digit card");
  eq(has(dfa, "pin 1234", 2), false, "too short for card");
});

yeet.test("char classes and negation", () => {
  const d = compileRegexes([{ src: "[^@ ]+@", bit: 0 }]);
  eq(has(d, "user@", 0), true, "run then @");
  eq(has(d, "@", 0), false, "needs >=1 before @");
  const w = compileRegexes([{ src: "\\w+\\s\\d", bit: 0 }]);
  eq(has(w, "abc 5", 0), true, "\\w+ space digit");
  eq(has(w, "abc5", 0), false, "needs a space");
});

yeet.test("quantifiers ? * + {n} {n,m}", () => {
  const d = compileRegexes([{ src: "ab?c", bit: 0 }]);
  eq(has(d, "ac", 0), true, "b optional absent"); eq(has(d, "abc", 0), true, "b present");
  const star = compileRegexes([{ src: "ab*c", bit: 0 }]);
  eq(has(star, "ac", 0), true, "zero b"); eq(has(star, "abbbbc", 0), true, "many b");
  const plus = compileRegexes([{ src: "ab+c", bit: 0 }]);
  eq(has(plus, "ac", 0), false, "+ needs >=1"); eq(has(plus, "abc", 0), true, "one b");
  const nm = compileRegexes([{ src: "x{2,4}y", bit: 0 }]);
  eq(has(nm, "xy", 0), false, "min 2 (1 x fails)"); eq(has(nm, "xxy", 0), true, "2 x's"); eq(has(nm, "xxxxy", 0), true, "4 x's");
});

yeet.test("alternation and groups", () => {
  const d = compileRegexes([{ src: "(cat|dog)s?", bit: 0 }]);
  eq(has(d, "cat", 0), true, "cat"); eq(has(d, "dogs", 0), true, "dogs"); eq(has(d, "fish", 0), false, "neither");
});

yeet.test("matches anywhere in the input (unanchored)", () => {
  const d = compileRegexes([{ src: "\\d{3}", bit: 0 }]);
  eq(has(d, "abc123def", 0), true, "mid-string"); eq(has(d, "123", 0), true, "at start"); eq(has(d, "xx12", 0), false, "only 2 digits");
});
