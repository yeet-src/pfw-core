/* A restricted regex -> DFA compiler, for verifier-safe fuzzy matching (SSNs,
 * emails, cards). The DFA is matched one byte per step through a transition
 * table, exactly like the Aho-Corasick automaton — so it runs in the kernel with
 * no backtracking. Several regexes compile into ONE DFA (alternation) with a
 * per-regex accept bit, mirroring how `scan` sets a bit in %m per matched pattern.
 *
 * Supported: literals, `.`, char classes (\d \w \s and their negations, [a-z],
 * [^...]), groups, alternation `|`, and quantifiers `?` `*` `+` `{n}` `{n,m}`
 * `{n,}` (bounded: * and {n,}'s open end are capped at STAR_CAP repeats).
 * NOT supported: backreferences, lookaround — they need backtracking.
 *
 * Matching is unanchored (finds the pattern anywhere in the window) via an
 * implicit `.*` prefix, the same "match anywhere" semantics as scan.
 */

/* ---- parse: regex string -> AST ----------------------------------------- */
/* AST nodes: {t:"char",set:Set<byte>|null(any)} {t:"cat",a,b} {t:"alt",a,b}
 *            {t:"rep",a,min,max} {t:"empty"} */

const DIGIT = (s) => { for (let c = 48; c <= 57; c++) s.add(c); };
const WORD = (s) => { for (let c = 48; c <= 57; c++) s.add(c); for (let c = 65; c <= 90; c++) s.add(c); for (let c = 97; c <= 122; c++) s.add(c); s.add(95); };
const SPACE = (s) => { for (const c of [32, 9, 10, 13, 11, 12]) s.add(c); };
const negate = (set) => { const n = new Set(); for (let c = 0; c < 256; c++) if (!set.has(c)) n.add(c); return n; };

function parse(src) {
  const bytes = [...new TextEncoder().encode(src)];
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
    return neg ? negate(set) : set;
  };

  const parseAtom = () => {
    const c = peek();
    if (c === 40) { i++; const e = parseAlt(); if (peek() === 41) i++; else throw new Error("unterminated ("); return e; } // ( )
    if (c === 91) { i++; return { t: "char", set: parseClass() }; } // [ ]
    if (c === 46) { i++; return { t: "char", set: null }; } // .  (any)
    if (c === 92) { i++; const e = classEscape(peek()); if (e) { i++; return { t: "char", set: e }; } return { t: "char", set: new Set([escChar(bytes[i++])]) }; }
    if (c === 124 || c === 41 || c === undefined) return { t: "empty" };
    i++; return { t: "char", set: new Set([c]) };
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

/* ---- combine regexes + subset-construct to a DFA ------------------------- */
/* regexes: [{ src, bit }]. Returns { nstates, trans:[Uint16Array(256)], accept:[BigInt] }.
 * Unanchored: a start state loops on any byte (implicit .*) and also enters each
 * regex; a DFA state's accept mask ORs the bits of the regex-accepts it contains. */
export function compileRegexes(regexes) {
  const states = []; // merged NFA
  const mk = () => (states.push({ eps: [], edges: [] }), states.length - 1);
  const start = mk();
  states[start].edges.push({ set: null, to: start }); // .* self-loop (match anywhere)
  const acceptBit = new Map(); // nfa accept state -> bit
  for (const { src, bit } of regexes) {
    const nfa = buildNFA(parse(src));
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
  intern(closure([start]));
  for (let id = 0; id < order.length; id++) {
    const nfaSet = order[id];
    for (let b = 0; b < 256; b++) {
      const move = [];
      for (const s of nfaSet) for (const e of states[s].edges) if (e.set === null || e.set.has(b)) move.push(e.to);
      trans[id][b] = move.length ? intern(closure(move)) : 0; // 0 = start (which has the .* loop) — keeps matching anywhere
    }
    if (order.length > 4096) throw new Error("regex DFA too large (>4096 states)");
  }
  return { nstates: order.length, trans, accept };
}

/* Reference matcher (host): does any regex match within `bytes`? Returns the
 * accept bitmask seen over the walk (bits set for every regex that matched). */
export function runDFA(dfa, bytes) {
  let s = 0; let mask = 0n;
  for (let k = 0; k < bytes.length; k++) {
    s = dfa.trans[s][bytes[k]];
    mask |= dfa.accept[s];
  }
  return mask;
}
