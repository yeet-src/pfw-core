/* The restricted-regex -> DFA compiler (src/regex.js): compile several regexes
 * into a few DFAs with a per-regex accept bit, then walk them over strings (the
 * same one-byte-per-step match the kernel will do). Covers char classes, quantifiers,
 * alternation, anchoring-anywhere, and that each regex's bit is independent. */
import { LIMITS } from "#/isa.js";
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

/* Nine detectors of the kind a DLP program carries. As one DFA they pass 65536
 * states with the fifth; grouped, the states add. */
const DLP = [
  "\\d{3}-\\d{2}-\\d{4}", "[a-z0-9._]+@[a-z0-9.]+\\.[a-z]+", "\\d{13,16}", "AKIA[A-Z0-9]{16}",
  "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}", "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
  "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "ghp_[A-Za-z0-9]{36}", "xox[bap]-[0-9]{10,12}-[A-Za-z0-9]{24}",
].map((src, bit) => ({ src, bit }));
/* Compiled once a case: nine regexes take a second or two. */
const compiled = new Map();
const dlp = (nocase = false) => { if (!compiled.has(nocase)) compiled.set(nocase, compileRegexes(DLP, nocase)); return compiled.get(nocase); };
const HITS = [
  "123-45-6789", "bob@example.com", "4111111111111111", "AKIAIOSFODNN7EXAMPLE",
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", "10.20.30.40",
  "123e4567-e89b-12d3-a456-426614174000", "ghp_" + "a1B2".repeat(9), "xoxb-1234567890-" + "aB3d".repeat(6),
];

yeet.test("regexes that would multiply in one DFA are split across a few", () => {
  for (const nocase of [false, true]) {
    const dfa = dlp(nocase);
    if (dfa.starts.length < 2 || dfa.starts.length > LIMITS.RE_GROUPS) throw new Error(`${dfa.starts.length} DFAs`);
    if (dfa.nstates > 8192) throw new Error(`${dfa.nstates} states: the sizes are multiplying, not adding`);
    eq(dfa.starts[0], 0, "the first DFA starts at state 0");
    for (const { bit } of DLP) if (!dfa.starts.includes(dfa.startOf[bit])) throw new Error(`regex ${bit} has no DFA`);
  }
});

yeet.test("the DFAs together report what each regex reports alone", () => {
  /* A small deterministic generator: fragments of real hits, cut and glued, so
   * near-misses and overlaps are common. */
  let seed = 0x9e3779b9;
  const rnd = (n) => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % n; };
  const piece = () => { const h = HITS[rnd(HITS.length)]; const a = rnd(h.length); return h.slice(a, a + 1 + rnd(h.length - a)); };
  for (const nocase of [false, true]) {
    const all = dlp(nocase), alone = DLP.map((re) => compileRegexes([re], nocase));
    const fold = (s) => (nocase ? s.toLowerCase() : s); // the kernel folds the input before the DFA sees it
    const check = (text) => {
      const want = alone.reduce((m, d) => m | runDFA(d, enc(fold(text))), 0n);
      const got = runDFA(all, enc(fold(text)));
      if (got !== want) throw new Error(`${JSON.stringify(text)} (nocase=${nocase}): got ${got.toString(2)}, want ${want.toString(2)}`);
    };
    for (const h of HITS) check(`x ${h} y`);
    for (let i = 0; i < 400; i++) check(Array.from({ length: 1 + rnd(5) }, piece).join(rnd(2) ? " " : ""));
  }
});

yeet.test("every hit is found by its own regex, and only a whole one", () => {
  const dfa = dlp();
  HITS.forEach((h, bit) => {
    eq(has(dfa, `-- ${h} --`, bit), true, `regex ${bit} on its hit`);
    eq(has(dfa, `-- ${h.slice(0, 6)} --`, bit), false, `regex ${bit} on a stub`);
  });
});

yeet.test("a DFA is minimised: equivalent spellings cost the same", () => {
  const a = compileRegexes([{ src: "ab|ac|ad", bit: 0 }]), b = compileRegexes([{ src: "a[bcd]", bit: 0 }]);
  eq(a.nstates, b.nstates, "states");
});
