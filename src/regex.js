/* A restricted regex -> DFA compiler, for verifier-safe fuzzy matching (SSNs,
 * emails, cards). The DFA is matched one byte per step through a transition
 * table, exactly like the Aho-Corasick automaton — so it runs in the kernel with
 * no backtracking. Several regexes compile into a few DFAs, each regex with its
 * own accept bit, mirroring how `scan` sets a bit in %m per matched pattern.
 *
 * Supported: literals, `.`, char classes (\d \w \s and their negations, [a-z],
 * [^...]), groups, alternation `|`, and quantifiers `?` `*` `+` `{n}` `{n,m}`
 * `{n,}` (bounded: * and {n,}'s open end are capped at STAR_CAP repeats).
 * `(?i)` or `(?-i)` first sets that regex's case, over the program's `nocase`.
 * NOT supported: backreferences, lookaround — they need backtracking.
 *
 * Matching is unanchored (finds the pattern anywhere in the window) via an
 * implicit `.*` prefix, the same "match anywhere" semantics as scan.
 */
import { LIMITS } from "#/isa.js";

/* ---- parse: regex string -> AST ----------------------------------------- */
/* AST nodes: {t:"char",set:Set<byte>|null(any)} {t:"cat",a,b} {t:"alt",a,b}
 *            {t:"rep",a,min,max} {t:"empty"} */

const DIGIT = (s) => { for (let c = 48; c <= 57; c++) s.add(c); };
const WORD = (s) => { for (let c = 48; c <= 57; c++) s.add(c); for (let c = 65; c <= 90; c++) s.add(c); for (let c = 97; c <= 122; c++) s.add(c); s.add(95); };
const SPACE = (s) => { for (const c of [32, 9, 10, 13, 11, 12]) s.add(c); };
const negate = (set) => { const n = new Set(); for (let c = 0; c < 256; c++) if (!set.has(c)) n.add(c); return n; };

/* Under `nocase` the matcher folds every INPUT byte to lower case before it
 * steps the DFA (interp.js / the kernel's fold()), so the regex itself has to be
 * case-insensitive too or an upper-case literal or class (`AKIA[A-Z0-9]{16}`)
 * could never match. Each literal and each class member is closed over ASCII
 * case here, BEFORE a `[^...]` is negated — so `[^a-z]` excludes both cases. */
const caseClose = (set) => {
  for (const c of [...set]) {
    if (c >= 65 && c <= 90) set.add(c + 32);
    else if (c >= 97 && c <= 122) set.add(c - 32);
  }
  return set;
};

/* A regex may say its own case, ahead of everything else: `(?i)` ignores it,
 * `(?-i)` does not, whatever the program's `nocase` says. So one rule of a
 * case-insensitive program can still ask for `POST`, and not `post` in prose. */
const CASE_FLAG = /^\(\?(-?)i\)/;

function parse(src, nocase = false) {
  const flag = CASE_FLAG.exec(src);
  if (flag) { nocase = flag[1] !== "-"; src = src.slice(flag[0].length); }
  const bytes = [...new TextEncoder().encode(src)];
  const cc = (set) => (nocase ? caseClose(set) : set);
  let i = 0;
  const peek = () => bytes[i];
  const eof = () => i >= bytes.length;

  /* a class token after a backslash: returns a Set or null if not a class escape */
  const classEscape = (c) => {
    const s = new Set();
    if (c === 100) { DIGIT(s); return s; }                 // \d
    if (c === 119) { WORD(s); return s; }                  // \w
    if (c === 115) { SPACE(s); return s; }                 // \s
    if (c === 68) { DIGIT(s); return negate(s); }          // \D
    if (c === 87) { WORD(s); return negate(s); }           // \W
    if (c === 83) { SPACE(s); return negate(s); }          // \S
    return null;
  };
  const escChar = (c) => ({ 110: 10, 114: 13, 116: 9, 48: 0 }[c] ?? c); // \n \r \t \0 else literal

  const parseClass = () => { // after '['
    let neg = false;
    if (peek() === 94) { neg = true; i++; } // ^
    const set = new Set();
    while (!eof() && peek() !== 93) { // ]
      let lo;
      if (peek() === 92) { i++; const e = classEscape(peek()); if (e) { i++; for (const c of e) set.add(c); continue; } lo = escChar(bytes[i++]); }
      else lo = bytes[i++];
      if (peek() === 45 && bytes[i + 1] !== 93 && i + 1 < bytes.length) { // range a-z
        i++; let hi; if (peek() === 92) { i++; hi = escChar(bytes[i++]); } else hi = bytes[i++];
        for (let c = lo; c <= hi; c++) set.add(c);
      } else set.add(lo);
    }
    if (peek() === 93) i++; else throw new Error("unterminated [");
    cc(set);
    return neg ? negate(set) : set;
  };

  const parseAtom = () => {
    const c = peek();
    if (c === 40) { i++; const e = parseAlt(); if (peek() === 41) i++; else throw new Error("unterminated ("); return e; } // ( )
    if (c === 91) { i++; return { t: "char", set: parseClass() }; } // [ ]
    if (c === 46) { i++; return { t: "char", set: null }; } // .  (any)
    if (c === 92) { i++; const e = classEscape(peek()); if (e) { i++; return { t: "char", set: e }; } return { t: "char", set: cc(new Set([escChar(bytes[i++])])) }; }
    if (c === 124 || c === 41 || c === undefined) return { t: "empty" };
    i++; return { t: "char", set: cc(new Set([c])) };
  };

  const parseQuant = () => {
    let a = parseAtom();
    for (;;) {
      const c = peek();
      if (c === 42) { i++; a = { t: "rep", a, min: 0, max: Infinity }; }       // *
      else if (c === 43) { i++; a = { t: "rep", a, min: 1, max: Infinity }; }  // +
      else if (c === 63) { i++; a = { t: "rep", a, min: 0, max: 1 }; }         // ?
      else if (c === 123) { // {n} {n,m} {n,}
        const save = i; i++;
        let n = ""; while (peek() >= 48 && peek() <= 57) n += String.fromCharCode(bytes[i++]);
        let m = n;
        if (peek() === 44) { i++; m = ""; while (peek() >= 48 && peek() <= 57) m += String.fromCharCode(bytes[i++]); }
        if (peek() === 125 && n !== "") { i++; a = { t: "rep", a, min: Number(n), max: m === "" ? Infinity : Number(m) }; }
        else { i = save; break; } // not a quantifier, treat { literally next round
      } else break;
    }
    return a;
  };

  function parseCat() {
    let e = { t: "empty" };
    while (!eof() && peek() !== 124 && peek() !== 41) e = e.t === "empty" ? parseQuant() : { t: "cat", a: e, b: parseQuant() };
    return e;
  }
  function parseAlt() {
    let e = parseCat();
    while (peek() === 124) { i++; e = { t: "alt", a: e, b: parseCat() }; }
    return e;
  }
  const e = parseAlt();
  if (!eof()) throw new Error(`unexpected \`${String.fromCharCode(peek())}\` at ${i}`);
  return e;
}

/* The exact match length of a regex if it is the same for every match, else null
 * (variable-length). Used by redact/replace, which overwrite a span in place: a
 * fixed length means the match end (the DFA accept position) fixes the start too,
 * so the existing AC fill machinery applies. `.`/char class = 1, concatenation
 * sums, alternation must agree, `{n}` = n*inner; `* + ? {n,m} {n,}` are variable. */
export function fixedLength(src) {
  let ast;
  try { ast = parse(src); } catch { return null; }
  const fx = (n) => {
    switch (n.t) {
      case "empty": return 0;
      case "char": return 1;
      case "cat": { const a = fx(n.a), b = fx(n.b); return a == null || b == null ? null : a + b; }
      case "alt": { const a = fx(n.a), b = fx(n.b); return a == null || b == null || a !== b ? null : a; }
      case "rep": { if (n.min !== n.max || n.max === Infinity) return null; const a = fx(n.a); return a == null ? null : a * n.min; }
      default: return null;
    }
  };
  return fx(ast);
}

/* ---- AST -> NFA (Thompson), fragments of {start, accepts:[state]} -------- */
function buildNFA(ast) {
  const states = []; // each: { eps:[idx], edges:[{set,to}] }  set=null means any byte
  const mk = () => (states.push({ eps: [], edges: [] }), states.length - 1);
  const frag = (node) => {
    switch (node.t) {
      case "empty": { const s = mk(); return { start: s, accept: s }; }
      case "char": { const s = mk(), a = mk(); states[s].edges.push({ set: node.set, to: a }); return { start: s, accept: a }; }
      case "cat": { const x = frag(node.a), y = frag(node.b); states[x.accept].eps.push(y.start); return { start: x.start, accept: y.accept }; }
      case "alt": { const s = mk(), a = mk(); const x = frag(node.a), y = frag(node.b); states[s].eps.push(x.start, y.start); states[x.accept].eps.push(a); states[y.accept].eps.push(a); return { start: s, accept: a }; }
      case "rep": {
        const s = mk(), a = mk();
        let cur = s;
        for (let k = 0; k < node.min; k++) { const f = frag(node.a); states[cur].eps.push(f.start); cur = f.accept; } // required copies
        if (node.max === Infinity) {                       // ... then a star loop (unbounded; the DFA stays finite)
          const loop = mk(), f = frag(node.a);
          states[cur].eps.push(loop); states[loop].eps.push(f.start, a); states[f.accept].eps.push(loop);
        } else {                                           // ... or (max - min) optional copies
          for (let k = node.min; k < node.max; k++) { const f = frag(node.a); states[cur].eps.push(f.start, a); cur = f.accept; }
          states[cur].eps.push(a);
        }
        return { start: s, accept: a };
      }
    }
  };
  const f = frag(ast);
  return { states, start: f.start, accept: f.accept };
}

/* ---- regexes -> DFAs ------------------------------------------------------ */
/* One DFA over several regexes, by subset construction, or null when it would
 * pass `cap` states. Unanchored: the start state loops on any byte (implicit
 * .*) and also enters each regex; a DFA state's accept mask ORs the bits of the
 * regex accepts it contains. State 0 is the start, and a byte nothing consumes
 * leads back to it. */
function buildDFA(regexes, nocase, cap) {
  const states = []; // merged NFA
  const mk = () => (states.push({ eps: [], edges: [] }), states.length - 1);
  const start = mk();
  states[start].edges.push({ set: null, to: start }); // .* self-loop (match anywhere)
  const acceptBit = new Map(); // nfa accept state -> bit
  for (const { src, bit } of regexes) {
    const nfa = buildNFA(parse(src, nocase));
    const base = states.length;
    for (const st of nfa.states) states.push({ eps: st.eps.map((e) => e + base), edges: st.edges.map((e) => ({ set: e.set, to: e.to + base })) });
    states[start].eps.push(nfa.start + base);
    acceptBit.set(nfa.accept + base, bit);
  }
  const closure = (setArr) => {
    const seen = new Set(setArr), stack = [...setArr];
    while (stack.length) { const s = stack.pop(); for (const e of states[s].eps) if (!seen.has(e)) { seen.add(e); stack.push(e); } }
    return [...seen].sort((a, b) => a - b);
  };
  const keyOf = (arr) => arr.join(",");
  const trans = [], accept = [];
  const dstates = new Map(); // key -> dfa id
  const order = [];
  const intern = (nfaSet) => { const k = keyOf(nfaSet); if (dstates.has(k)) return dstates.get(k); const id = order.length; dstates.set(k, id); order.push(nfaSet); trans.push(new Uint16Array(256)); let m = 0n; for (const s of nfaSet) if (acceptBit.has(s)) m |= 1n << BigInt(acceptBit.get(s)); accept.push(m); return id; };
  /* Bytes no edge tells apart move every state alike: the work is done once a
   * class of them, not once a byte. A handful of classes is typical. */
  const sets = [...new Set(states.flatMap((st) => st.edges.map((e) => e.set)).filter(Boolean))];
  const classOf = new Map(), classes = []; // membership signature -> class; class -> its bytes
  for (let b = 0; b < 256; b++) {
    const k = sets.map((set) => (set.has(b) ? "1" : "0")).join("");
    if (!classOf.has(k)) { classOf.set(k, classes.length); classes.push([]); }
    classes[classOf.get(k)].push(b);
  }
  intern(closure([start]));
  for (let id = 0; id < order.length; id++) {
    const nfaSet = order[id];
    for (const bytes of classes) {
      const b = bytes[0], move = [];
      for (const s of nfaSet) for (const e of states[s].edges) if (e.set === null || e.set.has(b)) move.push(e.to);
      const to = move.length ? intern(closure(move)) : 0;
      for (const x of bytes) trans[id][x] = to;
    }
    if (order.length > cap) return null;
  }
  return { nstates: order.length, trans, accept };
}

/* The smallest DFA that reports the same accept masks, byte for byte: states
 * are told apart by their mask, then by where each byte leads, until nothing
 * splits (Moore). The start state stays 0. */
function minimise(dfa) {
  const n = dfa.nstates;
  let cls = new Int32Array(n), ncls = 0;
  const byMask = new Map();
  for (let s = 0; s < n; s++) { const k = dfa.accept[s]; if (!byMask.has(k)) byMask.set(k, ncls++); cls[s] = byMask.get(k); }
  const sig = new Uint16Array(257);
  for (;;) {
    const next = new Int32Array(n), ids = new Map();
    for (let s = 0; s < n; s++) {
      sig[0] = cls[s];
      const row = dfa.trans[s];
      for (let b = 0; b < 256; b++) sig[b + 1] = cls[row[b]];
      const k = String.fromCharCode.apply(null, sig);
      let id = ids.get(k);
      if (id === undefined) { id = ids.size; ids.set(k, id); }
      next[s] = id;
    }
    const grew = ids.size !== ncls;
    cls = next; ncls = ids.size;
    if (!grew) break;
  }
  // Classes are numbered by first appearance, and state 0 appears first.
  const trans = Array.from({ length: ncls }, () => null), accept = new Array(ncls);
  for (let s = 0; s < n; s++) {
    const c = cls[s];
    if (trans[c]) continue;
    trans[c] = Uint16Array.from(dfa.trans[s], (t) => cls[t]);
    accept[c] = dfa.accept[s];
  }
  return { nstates: ncls, trans, accept };
}

/* A regex joins a group when the DFA they share is no more than this many
 * times the two apart: regexes that do not interact cost about their sum, and
 * ones that do multiply. */
const MERGE_SLACK = 2;

/* regexes: [{ src, bit }]; `nocase` is the case of a regex that does not say its
 * own (see parse). The DFAs read the bytes as they are — a case-insensitive
 * regex accepts both cases of each letter itself — so regexes of either kind
 * share a DFA.
 *
 * One DFA over every regex is one table lookup a byte, but its states remember
 * where each regex stands at once, so their sizes multiply: an AWS key id beside
 * an email address is 7400 states, and neither alone is 2500. So the regexes are
 * packed into at most RE_GROUPS DFAs, walked side by side — a lookup each a
 * byte, and sizes that add. Regexes that share a DFA cheaply still do, and a
 * program whose regexes all do pays for one lookup, as before.
 *
 * The groups share one state space, each in its own range, so the kernel's
 * tables keep their shape. Returns
 *   { nstates, trans:[Uint16Array(256)], accept:[BigInt],   every group's states
 *     starts:[state],        where each group begins, and restarts
 *     startOf:{bit: state} } the start of the group that matches regex `bit` */
export function compileRegexes(regexes, nocase = false) {
  const { RE_STATES, RE_GROUPS } = LIMITS;
  const tooLarge = () => new Error(`regex DFA too large: more than ${RE_STATES} states (the kernel table's size) — narrow a class or shorten a counted repeat`);
  const groups = [], homeless = [];
  for (const re of regexes) {
    const solo = buildDFA([re], nocase, RE_STATES);
    if (!solo) throw tooLarge();
    const home = groups.find((g) => {
      const both = buildDFA([...g.members, re], nocase, Math.min(RE_STATES, MERGE_SLACK * (g.dfa.nstates + solo.nstates)));
      if (both) { g.members.push(re); g.dfa = both; }
      return both;
    });
    if (home) continue;
    if (groups.length < RE_GROUPS) groups.push({ members: [re], dfa: solo });
    else homeless.push(re);
  }
  /* Every group is taken and this regex is cheap beside none of them: it goes
   * where it grows the total least, if the table can hold that. */
  for (const re of homeless) {
    const total = groups.reduce((n, g) => n + g.dfa.nstates, 0);
    let best = null;
    for (const g of groups) {
      const both = buildDFA([...g.members, re], nocase, RE_STATES - (total - g.dfa.nstates));
      if (both && (!best || both.nstates - g.dfa.nstates < best.both.nstates - best.g.dfa.nstates)) best = { g, both };
    }
    if (!best) throw tooLarge();
    best.g.members.push(re); best.g.dfa = best.both;
  }

  const trans = [], accept = [], starts = [], startOf = {};
  for (const g of groups) {
    const dfa = minimise(g.dfa), base = trans.length;
    if (base + dfa.nstates > RE_STATES) throw tooLarge();
    starts.push(base);
    for (const { bit } of g.members) startOf[bit] = base;
    for (let s = 0; s < dfa.nstates; s++) { trans.push(dfa.trans[s].map((t) => t + base)); accept.push(dfa.accept[s]); }
  }
  return { nstates: trans.length, trans, accept, starts, startOf };
}

/* Reference matcher (host): does any regex match within `bytes`? Returns the
 * accept bitmask seen over the walk (bits set for every regex that matched). */
export function runDFA(dfa, bytes) {
  let mask = 0n;
  for (let s of dfa.starts) {
    for (let k = 0; k < bytes.length; k++) {
      s = dfa.trans[s][bytes[k]];
      mask |= dfa.accept[s];
    }
  }
  return mask;
}
