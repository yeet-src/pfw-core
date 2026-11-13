/* pfw-C: a small C-style language that compiles to pfw assembly.
 *
 * It is the language the console edits; the assembly (asm.js) is its
 * compiled output, shown in the editor's Assembly tab and then loaded
 * into the kernel. The compiler emits assembly text and hands it to the
 * assembler, so the two always agree.
 *
 *   nocase;
 *   pattern gptbot = "GPTBot", claudebot = "ClaudeBot";
 *
 *   filter {
 *     if (dport != 8080) return pass;
 *     if (scan(payload, 1460) & (gptbot | claudebot)) {
 *       log(96);
 *       return rst("crawler", 60);
 *     }
 *     return pass;
 *   }
 *
 * Reads (ints): payload sport dport proto len l3 l4 end ifindex
 * Verdicts (return): pass | drop(rule) | count(rule) | ban(rule, ttl) | rst(rule, ttl)
 * Statements: if/else, log(n), skip(ptr, 'c'), and the declarations
 *   mask m = scan(ptr, len);   ptr p = after(pat) | find(ptr, 'c', len) | payload;
 * Calls: scan(ptr,len)->mask, starts(ptr, pat|"lit")->bool, after(pat)->ptr,
 *   find(ptr,'c',len)->ptr
 *
 * Locals (`ptr` and `let` variables, plus the compiler's own temporaries)
 * are emitted against virtual registers (%v0, %v1, ...) and mapped onto
 * the eight scratch registers afterwards by live range, so a program may
 * declare as many locals as it likes as long as no more than eight are
 * live at once. Jumps are forward-only, so a local's live range is simply
 * the span from its first write to its last read in emission order.
 */
import { assemble } from "#/asm.js";
import { TRANSFORM_TABLES } from "#/transform.js";

const REGISTERS = new Set(["payload", "sport", "dport", "proto", "len", "l3", "l4", "end", "ifindex", "frame", "src"]);
const VERDICTS = new Set(["pass", "drop", "count", "ban", "rst"]);

class CError extends Error {
  constructor(msg, line) {
    super(msg);
    this.line = line;
  }
}

/* ---- lexer --------------------------------------------------------------- */

const PUNCT = ["==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "<", ">", "!", "&", "|", "+", "-", "(", ")", "{", "}", ";", ",", "=", ".", "@"];

function lex(src) {
  const toks = [];
  let i = 0;
  let line = 1;
  const push = (type, value) => toks.push({ type, value, line });
  while (i < src.length) {
    const c = src[i];
    if (c === "\n") {
      line++;
      i++;
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") {
      i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) {
        if (src[i] === "\n") line++;
        i++;
      }
      i += 2;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let raw = "";
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\\") {
          raw += src[j] + (src[j + 1] ?? "");
          j += 2;
        } else raw += src[j++];
      }
      if (src[j] !== '"') throw new CError("unterminated string", line);
      push("string", raw);
      i = j + 1;
      continue;
    }
    if (c === "'") {
      let j = i + 1;
      let raw = "";
      if (src[j] === "\\") {
        raw = src[j] + (src[j + 1] ?? "");
        j += 2;
      } else {
        raw = src[j];
        j += 1;
      }
      if (src[j] !== "'") throw new CError("unterminated character literal", line);
      push("char", raw);
      i = j + 1;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i;
      if (c === "0" && (src[i + 1] === "x" || src[i + 1] === "X")) {
        j = i + 2;
        while (j < src.length && /[0-9a-fA-F]/.test(src[j])) j++;
      } else {
        while (j < src.length && /[0-9]/.test(src[j])) j++;
      }
      push("number", src.slice(i, j));
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      push("ident", src.slice(i, j));
      i = j;
      continue;
    }
    const p = PUNCT.find((p) => src.startsWith(p, i));
    if (!p) throw new CError(`unexpected \`${c}\``, line);
    push("punct", p);
    i += p.length;
  }
  push("eof", null);
  return toks;
}

/* ---- parser -------------------------------------------------------------- */

function parse(toks) {
  let pos = 0;
  const peek = () => toks[pos];
  const next = () => toks[pos++];
  const atEnd = () => peek().type === "eof";
  const err = (msg) => {
    throw new CError(msg, peek().line);
  };
  const eat = (type, value) => {
    const t = peek();
    if (t.type !== type || (value !== undefined && t.value !== value)) {
      err(`expected ${value ?? type}, found \`${t.value ?? t.type}\``);
    }
    return next();
  };
  const isP = (v) => peek().type === "punct" && peek().value === v;
  const isKw = (v) => peek().type === "ident" && peek().value === v;

  const patterns = [];
  const macros = [];
  let nocase = false;
  let reasm = false;
  let reasmDport = 0;
  let decode = null; // null | "h2" | "huffman"
  let body = null;

  const parseBytes = () => {
    eat("punct", "{");
    const bytes = [];
    while (!isP("}")) {
      const t = next();
      if (t.type === "number") bytes.push({ kind: "num", text: t.value });
      else if (t.type === "char") bytes.push({ kind: "char", text: t.value });
      else err("pattern bytes are numbers or 'c' characters");
      if (isP(",")) next();
    }
    eat("punct", "}");
    return bytes;
  };

  const parsePatternDecl = () => {
    eat("ident", "pattern");
    for (;;) {
      const name = eat("ident").value;
      eat("punct", "=");
      let def;
      if (peek().type === "string") def = { kind: "string", text: next().value };
      else if (isP("{")) def = { kind: "bytes", bytes: parseBytes() };
      else err("pattern is a \"string\" or a { byte list }");
      patterns.push({ name, def });
      if (isP(",")) {
        next();
        continue;
      }
      break;
    }
    eat("punct", ";");
  };

  /* expressions: ||, &&, !, comparisons, mask tests, calls, atoms */
  const parsePrimary = () => {
    const t = peek();
    if (isP("(")) {
      next();
      const e = parseExpr();
      eat("punct", ")");
      return e;
    }
    if (isP("!")) {
      next();
      return { kind: "not", e: parsePrimary(), line: t.line };
    }
    if (t.type === "number") {
      next();
      return { kind: "num", text: t.value, line: t.line };
    }
    if (t.type === "char") {
      next();
      return { kind: "char", text: t.value, line: t.line };
    }
    if (t.type === "string") {
      next();
      return { kind: "string", text: t.value, line: t.line };
    }
    if (t.type === "ident") {
      const name = next().value;
      if (name === "flow" && isP(".")) {
        next();
        const member = eat("ident").value;
        if (member !== "state" && member !== "count")
          err(`flow has no member \`${member}\` (only \`state\` and \`count\`)`);
        return { kind: member === "count" ? "flowcount" : "flowstate", line: t.line };
      }
      if (name === "frame" && isP(".")) {
        next();
        const member = eat("ident").value;
        if (member !== "len" && member !== "type" && member !== "data")
          err(`frame has no member \`${member}\` (only \`len\`, \`type\`, \`data\`)`);
        return { kind: "framefield", field: member, line: t.line };
      }
      if (name === "ring" && isP(".")) {
        next();
        const member = eat("ident").value;
        if (member === "len") return { kind: "ringlen", line: t.line };
        if (member === "get") {
          eat("punct", "(");
          const idx = parseExpr();
          eat("punct", ")");
          return { kind: "ringget", idx, line: t.line };
        }
        err(`ring has no value member \`${member}\` (read: \`ring.len\`, \`ring.get(i)\`; write: \`ring.push(v);\`)`);
      }
      if (isP("(")) return parseCall(name, t.line);
      return { kind: "ref", name, line: t.line };
    }
    err(`unexpected \`${t.value ?? t.type}\``);
  };

  const parseCall = (name, line) => {
    eat("punct", "(");
    const args = [];
    while (!isP(")")) {
      args.push(parseExpr());
      if (isP(",")) next();
      else break;
    }
    eat("punct", ")");
    return { kind: "call", name, args, line };
  };

  /* pattern-mask sub-expression: `a | b | c` of pattern refs */
  const parseMaskOperand = () => {
    let e = parsePrimary();
    while (isP("|")) {
      next();
      e = { kind: "por", a: e, b: parsePrimary(), line: e.line };
    }
    return e;
  };

  const CMP = { "==": 1, "!=": 1, "<": 1, ">": 1, "<=": 1, ">=": 1 };
  const parseCompare = () => {
    let e = parseMaskOperand();
    if (peek().type === "ident" && peek().value === "in") {
      next();
      if (peek().type !== "string") err('`in` wants a "A.B.C.D/PREFIX" literal');
      const cidr = next().value;
      return { kind: "incidr", a: e, cidr, line: e.line };
    }
    if (isP("&")) {
      next();
      const m = parseMaskOperand();
      e = { kind: "band", a: e, b: m, line: e.line };
    }
    if (peek().type === "punct" && CMP[peek().value]) {
      const op = next().value;
      const rhs = parseMaskOperand();
      e = { kind: "cmp", op, a: e, b: rhs, line: e.line };
    }
    return e;
  };

  const parseAnd = () => {
    let e = parseCompare();
    while (isP("&&")) {
      next();
      e = { kind: "and", a: e, b: parseCompare(), line: e.line };
    }
    return e;
  };
  /* Arithmetic over values: left-assoc chain of + - & | << >>. Only used
   * where a plain integer is wanted (let / assignment), never a mask test. */
  const ARITH = ["+", "-", "&", "|", "<<", ">>"];
  const parseArith = () => {
    let e = parsePrimary();
    while (peek().type === "punct" && ARITH.includes(peek().value)) {
      const op = next().value;
      e = { kind: "arith", op, a: e, b: parsePrimary(), line: e.line };
    }
    return e;
  };

  const parseExpr = () => {
    let e = parseAnd();
    while (isP("||")) {
      next();
      e = { kind: "or", a: e, b: parseAnd(), line: e.line };
    }
    return e;
  };

  const parseStmt = () => {
    const t = peek();
    if (isP("{")) {
      next();
      const stmts = [];
      while (!isP("}")) stmts.push(parseStmt());
      eat("punct", "}");
      return { kind: "block", stmts, line: t.line };
    }
    if (isKw("if")) {
      next();
      eat("punct", "(");
      const cond = parseExpr();
      eat("punct", ")");
      const then = parseStmt();
      let els = null;
      if (isKw("else")) {
        next();
        els = parseStmt();
      }
      return { kind: "if", cond, then, els, line: t.line };
    }
    if (isKw("return")) {
      next();
      const name = eat("ident").value;
      if (!VERDICTS.has(name)) err(`\`${name}\` is not a verdict (pass, drop, count, ban, rst)`);
      let args = [];
      if (isP("(")) args = parseCall(name, t.line).args;
      eat("punct", ";");
      return { kind: "return", verdict: name, args, line: t.line };
    }
    if (isKw("mask") || isKw("ptr")) {
      const type = next().value;
      const name = eat("ident").value;
      eat("punct", "=");
      const init = parseExpr();
      eat("punct", ";");
      return { kind: "decl", type, name, init, line: t.line };
    }
    if (isKw("repeat")) {
      next();
      eat("punct", "(");
      const n = eat("number").value;
      eat("punct", ")");
      const body = parseStmt();
      return { kind: "repeat", count: n, body, line: t.line };
    }
    /* frame [at PTR] (len = TYPE @ OFF, type = TYPE @ OFF, head = N) up to MAX { }
     * Walk up to MAX length-prefixed records. Each record is a `head`-byte header
     * (its fields read by name+offset) then `len` payload bytes; the cursor
     * advances head+len each time. In the body, frame.len / frame.type are the
     * parsed fields and frame.data is a pointer to this record's payload. */
    if (isKw("frame")) {
      next();
      let start = null;
      if (isKw("at")) { next(); start = parsePrimary(); }
      eat("punct", "(");
      const fields = {};
      for (;;) {
        const fname = eat("ident").value;
        eat("punct", "=");
        if (fname === "head") {
          fields.head = Number(eat("number").value);
        } else if (fname === "len" || fname === "type") {
          const ftype = eat("ident").value;
          eat("punct", "@");
          fields[fname] = { ftype, off: Number(eat("number").value), line: t.line };
        } else err(`frame field is len, type or head, not \`${fname}\``);
        if (isP(",")) { next(); continue; }
        break;
      }
      eat("punct", ")");
      if (!isKw("up")) err("frame (...) up to N { }");
      next();
      if (!isKw("to")) err("expected `to` in `up to N`");
      next();
      const max = Number(eat("number").value);
      const body = parseStmt();
      return { kind: "frame", start, fields, max, body, line: t.line };
    }
    /* let NAME = EXPR; — a named integer local kept in a scratch register */
    if (isKw("let")) {
      next();
      const name = eat("ident").value;
      eat("punct", "=");
      const init = parseArith();
      eat("punct", ";");
      return { kind: "let", name, init, line: t.line };
    }
    /* ring.push(EXPR); — append to this connection's ring */
    if (t.type === "ident" && t.value === "ring") {
      next();
      eat("punct", ".");
      const member = eat("ident").value;
      if (member !== "push") err(`ring statement is \`ring.push(v);\` (read with ring.get/ring.len), not \`${member}\``);
      eat("punct", "(");
      const value = parseExpr();
      eat("punct", ")");
      eat("punct", ";");
      return { kind: "ringpush", value, line: t.line };
    }
    /* flow.state = N; — set this connection's state */
    if (t.type === "ident" && t.value === "flow") {
      next();
      eat("punct", ".");
      const member = eat("ident").value;
      if (member !== "state") err(`flow has no member \`${member}\` (assignable: state)`);
      eat("punct", "=");
      const value = parseExpr();
      let ttl = null;
      if (isKw("for")) {
        next();
        ttl = parseExpr();
      }
      eat("punct", ";");
      return { kind: "setstate", value, ttl, line: t.line };
    }
    /* a bare call statement: log(...), skip(...) — or `name = EXPR;` */
    if (t.type === "ident") {
      const name = next().value;
      if (isP("=")) {
        next();
        const init = parseArith();
        eat("punct", ";");
        return { kind: "assign", name, init, line: t.line };
      }
      if (isP(";")) {
        next();
        return { kind: "macrocall", name, line: t.line };
      }
      const call = parseCall(name, t.line);
      eat("punct", ";");
      return { kind: "exprstmt", call, line: t.line };
    }
    err(`unexpected \`${t.value ?? t.type}\``);
  };

  while (!atEnd()) {
    if (isKw("nocase")) {
      next();
      eat("punct", ";");
      nocase = true;
    } else if (isKw("reassemble")) {
      next();
      if (peek().type === "number") reasmDport = Number(next().value);
      eat("punct", ";");
      reasm = true;
    } else if (isKw("decode")) {
      next();
      const kind = peek().type === "ident" ? peek().value : null;
      // h2 and huffman are built-in front-ends; any other name is a loaded
      // transform table (TRANSFORM_TABLES), decoded by the general stage.
      if (kind !== "h2" && kind !== "huffman" && !(kind in TRANSFORM_TABLES))
        err(`decode h2|huffman|<table> [PORT]; — no table \`${kind}\` (have: ${Object.keys(TRANSFORM_TABLES).join(", ")})`);
      next();
      if (peek().type === "number") reasmDport = Number(next().value);
      eat("punct", ";");
      decode = kind; reasm = true;
    } else if (isKw("pattern")) {
      parsePatternDecl();
    } else if (isKw("macro")) {
      next();
      const name = eat("ident").value;
      eat("punct", "{");
      const stmts = [];
      while (!isP("}")) stmts.push(parseStmt());
      eat("punct", "}");
      macros.push({ name, stmts });
    } else if (isKw("filter")) {
      next();
      eat("punct", "{");
      const stmts = [];
      while (!isP("}")) stmts.push(parseStmt());
      eat("punct", "}");
      body = stmts;
    } else {
      err(`expected \`pattern\`, \`nocase\`, \`reassemble\` or \`filter\`, found \`${peek().value ?? peek().type}\``);
    }
  }
  if (!body) throw new CError("a program needs a `filter { … }` block", 0);
  return { patterns, macros, nocase, reasm, reasmDport, decode, body };
}

/* ---- codegen: AST → assembly text ---------------------------------------- */

function codegen(ast) {
  const out = [];
  const emit = (s) => out.push("        " + s);
  const label = (l) => out.push(l + ":");
  let nLabel = 0;
  const fresh = () => `L${nLabel++}`;

  const declared = new Set(ast.patterns.map((p) => p.name));
  const extraPats = [];
  let nStr = 0;
  let nTmp = 0;
  const scratch = new Map(); // local name → virtual register vN
  const vregs = []; // vN → { name, line }, for the allocator's diagnostics
  const masks = new Set(); // mask var names
  const macroMap = new Map((ast.macros ?? []).map((m) => [m.name, m]));
  const expanding = new Set(); // macros mid-expansion, to catch recursion
  const frameScope = []; // stack of { len, type, data } scratch regs, for frame.X

  const die = (msg, line) => {
    throw new CError(msg, line);
  };

  /* A character literal → its byte number as an asm immediate. */
  const charImm = (text) => {
    const map = { "\\n": 10, "\\r": 13, "\\t": 9, "\\0": 0, "\\\\": 92, "\\'": 39, "\\\"": 34 };
    if (text in map) return map[text];
    if (text.startsWith("\\x")) return parseInt(text.slice(2), 16);
    return text.charCodeAt(0);
  };

  const patArg = (e) => {
    if (e.kind === "ref") {
      if (!declared.has(e.name)) die(`no pattern \`${e.name}\``, e.line);
      return e.name;
    }
    if (e.kind === "string") {
      const name = `__s${nStr++}`;
      extraPats.push(`.pat  ${name}, "${e.text}"`);
      declared.add(name);
      return name;
    }
    die("expected a pattern name or a \"string\"", e.line);
  };

  /* Pattern-mask term `a | b` → `$a|$b` for `test`. */
  const maskTerm = (e) => {
    if (e.kind === "por") return `${maskTerm(e.a)}|${maskTerm(e.b)}`;
    if (e.kind === "ref" && declared.has(e.name)) return `$${e.name}`;
    die("expected a pattern name", e.line);
  };

  /* any(...) / all(...) / seq(...): the first argument is scan(...) or a
   * mask variable (so %m holds a scan result); the rest are patterns.
   * Returns the validated pattern names. */
  const matchGroup = (e, min) => {
    const args = e.args;
    if (!args.length) die(`${e.name}(...) needs a scan or mask, then patterns`, e.line);
    const first = args[0];
    if (first.kind === "call" && first.name === "scan") doScan(first);
    else if (!(first.kind === "ref" && masks.has(first.name)))
      die(`first argument of ${e.name}(...) must be scan(...) or a mask variable`, e.line);
    const pats = args.slice(1).map((a) => patArg(a));
    if (pats.length < min)
      die(`${e.name}(...) needs at least ${min} pattern${min > 1 ? "s" : ""}`, e.line);
    return pats;
  };

  const imm = (e) => {
    if (e.kind === "num") return e.text;
    if (e.kind === "char") return String(charImm(e.text));
    die("expected a number", e.line);
  };

  /* The scratch register for frame.len/type/data at the current nesting, or a
   * compile error if used outside a frame body or for an undeclared field. */
  const frameReg = (field, line) => {
    const fr = frameScope[frameScope.length - 1];
    if (!fr) die(`frame.${field} is only valid inside a \`frame\` body`, line);
    if (!fr[field]) die(`this frame has no \`${field}\` field`, line);
    return fr[field];
  };

  /* Leave a pointer/offset value in %cur. */
  const loadPtr = (e) => {
    if (e.kind === "framefield") return emit(`mov     %${frameReg(e.field, e.line)}, %cur`);
    if (e.kind === "ref") {
      if (REGISTERS.has(e.name)) return emit(`mov     %${e.name}, %cur`);
      if (scratch.has(e.name)) return emit(`mov     %${scratch.get(e.name)}, %cur`);
      die(`\`${e.name}\` is not a pointer`, e.line);
    }
    if (e.kind === "call" && e.name === "after") {
      if (e.args.length !== 1) die("after(pattern)", e.line);
      return emit(`mpos    $${patArg(e.args[0])}, %cur`);
    }
    if (e.kind === "call" && e.name === "find") {
      if (e.args.length !== 3) die("find(ptr, 'c', len)", e.line);
      loadPtr(e.args[0]);
      return emit(`findb   $${imm(e.args[1])}, $${imm(e.args[2])}`);
    }
    die("expected a pointer (payload, a ptr variable, after(...), find(...))", e.line);
  };

  /* Emit a scan and leave the mask in %m. */
  const doScan = (e) => {
    if (e.args.length !== 2) die("scan(ptr, len)", e.line);
    loadPtr(e.args[0]);
    emit(`scan    $${imm(e.args[1])}, (%cur)`);
  };

  /* A fresh virtual register for a local. The real register is picked
   * after codegen (see allocRegs), once every live range is known. */
  const allocScratch = (name, line) => {
    const reg = `v${vregs.length}`;
    vregs.push({ name, line });
    scratch.set(name, reg);
    return reg;
  };

  /* A frame header field → the ops that leave its value in %cur (cursor at the
   * record start). Big-endian on-the-wire sizes, plus little-endian u16/u32. */
  const FIELD_LOAD = {
    u8: (o) => [`movb    ${o}(%cur), %cur`],
    u16: (o) => [`movw    ${o}(%cur), %cur`],
    u32: (o) => [`movl    ${o}(%cur), %cur`],
    be16: (o) => [`movbew  ${o}(%cur), %cur`],
    be24: (o) => [`movbel  ${o}(%cur), %cur`, `shr     $8, %cur`], // top 3 of 4 bytes
    be32: (o) => [`movbel  ${o}(%cur), %cur`],
  };

  /* Lower a `frame` by unrolling the body up to MAX times — forward-only, so the
   * ISA's termination guarantee holds by construction and no backward jump or
   * kernel loop is needed. Each copy: stop if the header runs past %end, read
   * the fields into scratch (frame.len / .type / .data), run the body, then
   * advance the cursor head+len to the next record. */
  const frameLower = (s) => {
    const f = s.fields;
    if (!f.len) die("frame needs a `len` field, e.g. `len = be16 @ 0`", s.line);
    if (f.head === undefined) die("frame needs `head = N` (the header byte count)", s.line);
    if (!FIELD_LOAD[f.len.ftype]) die(`frame len type \`${f.len.ftype}\` (u8|u16|u32|be16|be24|be32)`, s.line);
    if (f.type && !FIELD_LOAD[f.type.ftype]) die(`frame type field \`${f.type.ftype}\` (u8|u16|u32|be16|be24|be32)`, s.line);
    if (!Number.isInteger(f.head) || f.head < 1 || f.head > 255) die("frame `head` is 1..255", s.line);
    const max = Number(s.max);
    if (!Number.isInteger(max) || max < 1 || max > 64) die("frame `up to N` is 1..64", s.line);

    /* Save the real end first (this clobbers the cursor), then position the
     * cursor at the first record. Each record narrows %end to its own extent so
     * the body's scans/loads stay inside the record, then restores it. The
     * cursor holds the record start at the top of every iteration — from the
     * start expression on the first, from the previous advance after. */
    const realend = allocScratch(`__fe${nTmp++}`, s.line);
    emit(`mov     %end, %cur`);
    emit(`mov     %cur, %${realend}`);
    if (s.start) loadPtr(s.start);
    else emit(`mov     %payload, %cur`);

    const done = fresh();
    for (let i = 0; i < max; i++) {
      const rec = allocScratch(`__fr${nTmp}`, s.line);
      const flen = allocScratch(`__fl${nTmp}`, s.line);
      const ftype = f.type ? allocScratch(`__ft${nTmp}`, s.line) : null;
      const fdata = allocScratch(`__fd${nTmp++}`, s.line);
      emit(`mov     %cur, %${rec}`);           // record start
      emit(`add     $${f.head}, %cur`);
      emit(`cmp     %${realend}, %cur`);
      emit(`ja      ${done}`);                 // header runs past the data: stop
      emit(`mov     %cur, %${fdata}`);         // frame.data = rec + head
      emit(`mov     %${rec}, %cur`);
      FIELD_LOAD[f.len.ftype](f.len.off).forEach(emit);
      emit(`mov     %cur, %${flen}`);          // frame.len
      if (f.type) {
        emit(`mov     %${rec}, %cur`);
        FIELD_LOAD[f.type.ftype](f.type.off).forEach(emit);
        emit(`mov     %cur, %${ftype}`);       // frame.type
      }
      // narrow %end to this record's end = min(rec+head+len, realend)
      emit(`mov     %${fdata}, %cur`);
      emit(`add     %${flen}, %cur`);
      const okEnd = fresh();
      emit(`cmp     %${realend}, %cur`);
      emit(`jbe     ${okEnd}`);
      emit(`mov     %${realend}, %cur`);
      label(okEnd);
      emit(`mov     %cur, %end`);
      frameScope.push({ len: flen, type: ftype, data: fdata });
      stmt(s.body);
      frameScope.pop();
      emit(`mov     %${realend}, %cur`);       // restore the real end
      emit(`mov     %cur, %end`);
      emit(`mov     %${rec}, %cur`);           // advance to the next record
      emit(`add     $${f.head}, %cur`);
      emit(`add     %${flen}, %cur`);
    }
    label(done);
  };

  /* condition → forward jumps. One of jumpIfFalse / jumpIfTrue. */
  const INV = { "==": "jne", "!=": "je", "<": "jae", ">": "jbe", "<=": "ja", ">=": "jb" };
  const DIR = { "==": "je", "!=": "jne", "<": "jb", ">": "ja", "<=": "jbe", ">=": "jae" };

  const value = (e) => {
    /* a comparable integer value into %cur */
    if (e.kind === "flowstate") return emit(`sload   %cur`);
    if (e.kind === "flowcount") return emit(`bump    %cur`);
    if (e.kind === "ringlen") return emit(`rlen    %cur`);
    if (e.kind === "ringget") { value(e.idx); return emit(`rget    %cur`); }
    if (e.kind === "framefield") return emit(`mov     %${frameReg(e.field, e.line)}, %cur`);
    if (e.kind === "num" || e.kind === "char") return loadConst(imm(e));
    if (e.kind === "ref" && REGISTERS.has(e.name)) return emit(`mov     %${e.name}, %cur`);
    if (e.kind === "ref" && scratch.has(e.name)) return emit(`mov     %${scratch.get(e.name)}, %cur`);
    die(`\`${e.kind === "ref" ? e.name : e.kind}\` is not a readable value`, e.line);
  };

  /* Put an integer constant into %cur: zero it, then add. */
  const loadConst = (n) => {
    emit(`and     $0, %cur`);
    if (String(n) !== "0") emit(`add     $${n}, %cur`);
  };

  /* The immediate form of each value operator. */
  const ARITH_I = { "+": "add", "-": "sub", "&": "and", "|": "or", "<<": "shl", ">>": "shr" };
  /* The register form — only + and - have one. */
  const ARITH_R = { "+": "add", "-": "sub" };

  /* Materialize any value (register, state, counter, constant, a pointer
   * expression, or an arithmetic expression) into %cur — used by `let`
   * and assignment. Arithmetic folds left to right: no precedence, so
   * parenthesize if you mean otherwise. */
  const materialize = (e) => {
    if (e.kind === "arith") {
      materialize(e.a);
      const op = e.op;
      if (e.b.kind === "num" || e.b.kind === "char") {
        return emit(`${ARITH_I[op]}     $${imm(e.b)}, %cur`);
      }
      const rb = stableReg(e.b);
      if (rb) {
        if (!ARITH_R[op])
          die(`\`${op}\` needs a constant on the right (only + and - take a register)`, e.line);
        return emit(`${ARITH_R[op]}     %${rb}, %cur`);
      }
      /* RHS needs %cur (e.g. flow.count or a nested expression). Only +
       * is commutative enough to combine without a reversed op. */
      if (op !== "+")
        die(`\`${op}\` needs a constant or a plain register on the right`, e.line);
      const tmp = allocScratch(`__a${nTmp++}`, e.line);
      emit(`mov     %cur, %${tmp}`);
      materialize(e.b);
      return emit(`add     %${tmp}, %cur`);
    }
    if (e.kind === "flowstate" || e.kind === "flowcount" || e.kind === "ringlen" || e.kind === "ringget" || e.kind === "num" || e.kind === "char")
      return value(e);
    if (e.kind === "ref" && REGISTERS.has(e.name)) return emit(`mov     %${e.name}, %cur`);
    if (e.kind === "ref" && scratch.has(e.name)) return emit(`mov     %${scratch.get(e.name)}, %cur`);
    /* otherwise treat as a pointer/offset expression */
    return loadPtr(e);
  };

  /* Name of a register holding a stable value, or null if it needs %cur. */
  const stableReg = (e) => {
    if (e.kind === "ref" && REGISTERS.has(e.name)) return e.name;
    if (e.kind === "ref" && scratch.has(e.name)) return scratch.get(e.name);
    return null;
  };

  const cmpToFlags = (e) => {
    /* integer comparison: LHS into %cur, then cmp against the RHS. */
    if (e.b.kind === "num" || e.b.kind === "char") {
      value(e.a);
      return emit(`cmp     $${imm(e.b)}, %cur`);
    }
    const rb = stableReg(e.b);
    if (rb) {
      value(e.a);
      return emit(`cmp     %${rb}, %cur`);
    }
    /* RHS needs %cur (flow.count/flow.state or an expression): compute it
     * into a temp local first, then the LHS, then compare. */
    const tmp = allocScratch(`__cmp${nTmp++}`, e.line);
    materialize(e.b);
    emit(`mov     %cur, %${tmp}`);
    value(e.a);
    emit(`cmp     %${tmp}, %cur`);
  };

  const jumpIfFalse = (e, L) => {
    switch (e.kind) {
      case "not":
        return jumpIfTrue(e.e, L);
      case "and":
        jumpIfFalse(e.a, L);
        jumpIfFalse(e.b, L);
        return;
      case "or": {
        const cont = fresh();
        jumpIfTrue(e.a, cont);
        jumpIfFalse(e.b, L);
        label(cont);
        return;
      }
      case "cmp":
        cmpToFlags(e);
        return emit(`${INV[e.op]}     ${L}`);
      case "incidr":
        value(e.a);
        emit(`cidr    ${e.cidr}`);
        return emit(`jne     ${L}`); // not in the network → ZF clear
      case "band":
        if (e.a.kind === "call" && e.a.name === "scan") doScan(e.a);
        else if (!(e.a.kind === "ref" && masks.has(e.a.name))) die("left of & must be scan(...) or a mask variable", e.line);
        emit(`test    ${maskTerm(e.b)}, %m`);
        return emit(`je      ${L}`);
      case "call":
        if (e.name === "any") {
          const pats = matchGroup(e, 1);
          emit(`test    ${pats.map((p) => "$" + p).join("|")}, %m`);
          return emit(`je      ${L}`);
        }
        if (e.name === "all") {
          const pats = matchGroup(e, 1);
          for (const p of pats) {
            emit(`test    $${p}, %m`);
            emit(`je      ${L}`);
          }
          return;
        }
        if (e.name === "seq") {
          const pats = matchGroup(e, 2);
          for (const p of pats) {            // every pattern must be present
            emit(`test    $${p}, %m`);
            emit(`je      ${L}`);
          }
          let prev = allocScratch(`__seq${nTmp++}`, e.line);
          emit(`mpos    $${pats[0]}, %cur`); // end-offset of the first match
          emit(`mov     %cur, %${prev}`);
          for (let i = 1; i < pats.length; i++) {
            const curReg = allocScratch(`__seq${nTmp++}`, e.line);
            emit(`mpos    $${pats[i]}, %cur`);
            emit(`mov     %cur, %${curReg}`);
            emit(`mov     %${prev}, %cur`);
            emit(`cmp     %${curReg}, %cur`); // CF = prev < this
            emit(`jae     ${L}`);             // not strictly increasing → fail
            prev = curReg;
          }
          return;
        }
        if (e.name === "starts") {
          if (e.args.length !== 2) die("starts(ptr, pattern|\"lit\")", e.line);
          loadPtr(e.args[0]);
          emit(`cmpstr  $${patArg(e.args[1])}, (%cur)`);
          return emit(`jne     ${L}`);
        }
        die(`\`${e.name}(...)\` is not a condition`, e.line);
        return;
      default:
        die("not a condition", e.line);
    }
  };

  const jumpIfTrue = (e, L) => {
    switch (e.kind) {
      case "not":
        return jumpIfFalse(e.e, L);
      case "or":
        jumpIfTrue(e.a, L);
        jumpIfTrue(e.b, L);
        return;
      case "and": {
        const cont = fresh();
        jumpIfFalse(e.a, cont);
        jumpIfTrue(e.b, L);
        label(cont);
        return;
      }
      case "cmp":
        cmpToFlags(e);
        return emit(`${DIR[e.op]}      ${L}`);
      case "incidr":
        value(e.a);
        emit(`cidr    ${e.cidr}`);
        return emit(`je      ${L}`); // in the network → ZF set
      case "band":
        if (e.a.kind === "call" && e.a.name === "scan") doScan(e.a);
        else if (!(e.a.kind === "ref" && masks.has(e.a.name))) die("left of & must be scan(...) or a mask variable", e.line);
        emit(`test    ${maskTerm(e.b)}, %m`);
        return emit(`jne     ${L}`);
      case "call":
        if (e.name === "any") {
          const pats = matchGroup(e, 1);
          emit(`test    ${pats.map((p) => "$" + p).join("|")}, %m`);
          return emit(`jne     ${L}`);
        }
        if (e.name === "all" || e.name === "seq") {
          const cont = fresh();          // jump to L only if the whole thing holds
          jumpIfFalse(e, cont);
          emit(`jmp     ${L}`);
          label(cont);
          return;
        }
        if (e.name === "starts") {
          loadPtr(e.args[0]);
          emit(`cmpstr  $${patArg(e.args[1])}, (%cur)`);
          return emit(`je      ${L}`);
        }
        die(`\`${e.name}(...)\` is not a condition`, e.line);
        return;
      default:
        die("not a condition", e.line);
    }
  };

  const verdict = (s) => {
    const r = (i) => {
      const a = s.args[i];
      if (!a) die(`${s.verdict} needs a rule name`, s.line);
      if (a.kind === "string") return a.text;
      if (a.kind === "ref") return a.name;
      die("rule is a name or \"string\"", s.line);
    };
    switch (s.verdict) {
      case "pass":
        return emit("pass");
      case "drop":
        return emit(`drop    $${r(0)}`);
      case "count":
        return emit(`count   $${r(0)}`);
      case "ban":
        return emit(`ban     $${r(0)}, $${imm(s.args[1])}`);
      case "rst":
        return emit(`rst     $${r(0)}, $${imm(s.args[1])}`);
    }
  };

  const stmt = (s) => {
    switch (s.kind) {
      case "block":
        return s.stmts.forEach(stmt);
      case "if": {
        if (s.els) {
          const lElse = fresh();
          const lEnd = fresh();
          jumpIfFalse(s.cond, lElse);
          stmt(s.then);
          emit(`jmp     ${lEnd}`);
          label(lElse);
          stmt(s.els);
          label(lEnd);
        } else {
          const lEnd = fresh();
          jumpIfFalse(s.cond, lEnd);
          stmt(s.then);
          label(lEnd);
        }
        return;
      }
      case "return":
        return verdict(s);
      case "macrocall": {
        const m = macroMap.get(s.name);
        if (!m) die(`\`${s.name}\` is not a macro or a statement`, s.line);
        if (expanding.has(s.name)) die(`macro \`${s.name}\` is recursive`, s.line);
        expanding.add(s.name);
        m.stmts.forEach(stmt);
        expanding.delete(s.name);
        return;
      }
      case "setstate":
        return emit(s.ttl ? `sstore  $${imm(s.value)}, $${imm(s.ttl)}` : `sstore  $${imm(s.value)}`);
      case "ringpush":
        materialize(s.value);
        return emit(`rpush   %cur`);
      case "let": {
        if (REGISTERS.has(s.name) || declared.has(s.name) || masks.has(s.name))
          die(`\`${s.name}\` is already a register, pattern, or mask`, s.line);
        /* A second `let` of the same name (say, in both arms of an if, or
         * inside repeat) rebinds the same local rather than minting a new one. */
        const reg = scratch.get(s.name) ?? allocScratch(s.name, s.line);
        materialize(s.init);
        return emit(`mov     %cur, %${reg}`);
      }
      case "assign": {
        if (!scratch.has(s.name))
          die(`\`${s.name}\` is not a local (declare it with \`let\`)`, s.line);
        materialize(s.init);
        return emit(`mov     %cur, %${scratch.get(s.name)}`);
      }
      case "repeat": {
        const n = Number(s.count);
        if (!Number.isInteger(n) || n < 0 || n > 1024) die("repeat count is 0..1024", s.line);
        for (let k = 0; k < n; k++) stmt(s.body);
        return;
      }
      case "frame":
        return frameLower(s);
      case "decl": {
        if (s.type === "mask") {
          if (!(s.init.kind === "call" && s.init.name === "scan")) die("a mask is assigned from scan(...)", s.line);
          doScan(s.init);
          masks.add(s.name);
        } else {
          allocScratch(s.name, s.line);
          loadPtr(s.init);
          emit(`mov     %cur, %${scratch.get(s.name)}`);
        }
        return;
      }
      case "exprstmt": {
        const c = s.call;
        if (c.name === "log") return emit(`log     $${imm(c.args[0])}`);
        if (c.name === "count") return emit(`count   $${c.args[0].kind === "string" ? c.args[0].text : c.args[0].name}`);
        if (c.name === "skip") {
          const p = c.args[0];
          if (!(p.kind === "ref" && scratch.has(p.name))) die("skip(ptrVariable, 'c')", s.line);
          emit(`mov     %${scratch.get(p.name)}, %cur`);
          emit(`skipb   $${imm(c.args[1])}`);
          return emit(`mov     %cur, %${scratch.get(p.name)}`);
        }
        die(`\`${c.name}(...)\` is not a statement`, s.line);
        return;
      }
      default:
        die("bad statement", s.line);
    }
  };

  const pats = ast.patterns.map((p) => {
    if (p.def.kind === "string") return `.pat  ${p.name}, "${p.def.text}"`;
    const bytes = p.def.bytes
      .map((b) => (b.kind === "num" ? b.text : `'${b.text.replace(/^'|'$/g, "")}'`))
      .join(" ");
    return `.pat  ${p.name}, ${bytes}`;
  });

  ast.body.forEach(stmt);
  emit("pass"); // the fall-through verdict

  const header = [];
  if (ast.nocase) header.push(".nocase");
  if (ast.decode === "h2" || ast.decode === "huffman")
    header.push(ast.reasmDport ? `.decode ${ast.decode}, ${ast.reasmDport}` : `.decode ${ast.decode}`);
  else if (ast.decode) { // a loaded transform table, by name
    const id = TRANSFORM_TABLES[ast.decode].id;
    header.push(ast.reasmDport ? `.transform ${id}, ${ast.reasmDport}` : `.transform ${id}`);
  }
  else if (ast.reasm) header.push(ast.reasmDport ? `.reasm ${ast.reasmDport}` : ".reasm");
  header.push(...pats, ...extraPats);
  return [...header, "", ...allocRegs(out, vregs)].join("\n");
}

/* ---- register allocation ------------------------------------------------- */

const NSCRATCH = 8; // %s0..%s7

/* Map the virtual registers in the emitted body onto the scratch file.
 *
 * Linear scan over live intervals. Every jump in the ISA is forward, so
 * there are no loops and a virtual register is live exactly from its
 * first mention to its last in emission order: nothing before the first
 * write can read it, and nothing after the last read can. Two locals
 * whose intervals do not overlap share a register. Only when more than
 * NSCRATCH are live at the same instruction does the program not fit,
 * and that is reported at the local that failed to get a register. */
function allocRegs(lines, vregs) {
  const VREG = /%v(\d+)\b/g;
  const first = new Map();
  const last = new Map();
  lines.forEach((l, i) => {
    for (const m of l.matchAll(VREG)) {
      const v = Number(m[1]);
      if (!first.has(v)) first.set(v, i);
      last.set(v, i);
    }
  });
  const intervals = [...first.keys()]
    .map((v) => ({ v, start: first.get(v), end: last.get(v) }))
    .sort((a, b) => a.start - b.start || a.end - b.end);

  const free = Array.from({ length: NSCRATCH }, (_, i) => `s${i}`);
  const active = []; // intervals holding a register, any order
  const phys = new Map(); // vN → sN
  for (const iv of intervals) {
    for (let i = active.length - 1; i >= 0; i--) {
      if (active[i].end < iv.start) {
        free.push(phys.get(active[i].v));
        active.splice(i, 1);
      }
    }
    if (!free.length) {
      const held = active.map((a) => vregs[a.v].name).filter((n) => !n.startsWith("__"));
      const who = vregs[iv.v];
      const what = who.name.startsWith("__") ? "a compiler temporary" : `\`${who.name}\``;
      throw new CError(
        `too many locals live at once: ${what} needs a register but all ${NSCRATCH} are held` +
          (held.length ? ` (by ${held.map((n) => `\`${n}\``).join(", ")})` : "") +
          `; narrow a live range or drop a local`,
        who.line,
      );
    }
    /* Lowest-numbered free register first, for stable, readable output. */
    free.sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
    phys.set(iv.v, free.shift());
    active.push(iv);
  }
  return lines.map((l) => l.replace(VREG, (_, n) => `%${phys.get(Number(n))}`));
}

/* ---- the pipeline -------------------------------------------------------- */

/** Compile pfw-C to assembly text. { ok, errors:[{line,text}], asm } */
export function compileToAsm(source) {
  try {
    const ast = parse(lex(source));
    const asm = codegen(ast);
    return { ok: true, errors: [], asm };
  } catch (e) {
    if (e instanceof CError) return { ok: false, errors: [{ line: e.line, text: e.message }], asm: "" };
    throw e;
  }
}

/** Compile pfw-C all the way to ops, via assembly. Returns the asm too. */
export function compile(source) {
  const c = compileToAsm(source);
  if (!c.ok) return { ok: false, errors: c.errors, asm: "" };
  const a = assemble(c.asm);
  if (!a.ok) {
    /* The assembler rejected generated code: a compiler bug, surfaced
     * rather than hidden. */
    return { ok: false, errors: a.errors.map((e) => ({ line: 0, text: `internal: ${e.text}` })), asm: c.asm };
  }
  return { ok: true, errors: [], asm: c.asm, program: a.program, patterns: a.patterns, rules: a.rules, listing: a.listing, nocase: a.nocase };
}
