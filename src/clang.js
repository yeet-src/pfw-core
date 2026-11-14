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
import { Builder, opText } from "#/builder.js";
import { DECODE, REG } from "#/isa.js";
import { TRANSFORM_TABLES } from "#/transform.js";
import { compileRegexes } from "#/regex.js";

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
      if (peek().type === "string") return { kind: "incidr", a: e, cidr: next().value, line: e.line };
      if (peek().type === "ident" && peek().value === "set") { next(); return { kind: "inset", a: e, line: e.line }; }
      if (peek().type === "ident" && peek().value === "hash") { next(); return { kind: "inhash", a: e, line: e.line }; }
      if (peek().type === "ident" && peek().value === "bloom") { next(); return { kind: "inbloom", a: e, line: e.line }; }
      if (peek().type === "ident" && peek().value === "set6") { next(); return { kind: "inset6", a: e, line: e.line }; }
      err('`in` wants a "A.B.C.D/PREFIX" literal, `set`, `set6`, `hash`, or `bloom`');
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
    } else if (isKw("regex")) {
      next();
      const name = eat("ident").value;
      eat("punct", "=");
      if (peek().type !== "string") err('regex is `regex NAME = "..."`');
      patterns.push({ name, def: { kind: "regex", src: next().value } });
      eat("punct", ";");
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

/* ---- codegen: AST → ops, via the shared Builder ------------------------- */

const ESC = { "\\n": 10, "\\r": 13, "\\t": 9, "\\0": 0, "\\\\": 92, "\\'": 39, '\\"': 34 };

/* Decode a pfw-C string literal's inner text to bytes (for a pattern). */
function unescapeStr(body) {
  const out = [];
  for (let i = 0; i < body.length; i++) {
    if (body[i] !== "\\") { out.push(body.charCodeAt(i) & 0xff); continue; }
    const two = body.slice(i, i + 2);
    if (body[i + 1] === "x") { out.push(parseInt(body.slice(i + 2, i + 4), 16)); i += 3; }
    else if (two in ESC) { out.push(ESC[two]); i += 1; }
    else { out.push(body.charCodeAt(i + 1) & 0xff); i += 1; }
  }
  return out;
}

function codegen(ast) {
  const bld = new Builder();
  let nLabel = 0, nStr = 0, nTmp = 0;
  const fresh = () => `L${nLabel++}`;
  const declared = new Set(ast.patterns.map((p) => p.name));
  const scratch = new Map(); // local name → virtual-register token from bld.vreg()
  const masks = new Set();
  const macroMap = new Map((ast.macros ?? []).map((m) => [m.name, m]));
  const expanding = new Set();
  const frameScope = []; // stack of { len, type, data } vreg tokens, for frame.X

  const die = (msg, line) => { throw new CError(msg, line); };
  const charImm = (text) => {
    const map = { "\\n": 10, "\\r": 13, "\\t": 9, "\\0": 0, "\\\\": 92, "\\'": 39, '\\"': 34 };
    if (text in map) return map[text];
    if (text.startsWith("\\x")) return parseInt(text.slice(2), 16);
    return text.charCodeAt(0);
  };
  const immVal = (e) => {
    if (e.kind === "num") return BigInt(e.text);
    if (e.kind === "char") return BigInt(charImm(e.text));
    die("expected a number", e.line);
  };

  /* Register every declared pattern with the Builder up front, so patId works
   * wherever the body references one. */
  for (const p of ast.patterns) {
    if (p.def.kind === "regex") { bld.repat(p.name, p.def.src); continue; }
    const bytes = p.def.kind === "string"
      ? unescapeStr(p.def.text)
      : p.def.bytes.map((b) => (b.kind === "num" ? Number(b.text.startsWith("0x") ? parseInt(b.text, 16) : b.text) : charImm(b.text.replace(/^'|'$/g, ""))));
    bld.pat(p.name, bytes);
  }

  /* A string-literal pattern used inline: declare it on the fly, return its name. */
  const patArg = (e) => {
    if (e.kind === "ref") { if (!declared.has(e.name)) die(`no pattern \`${e.name}\``, e.line); return e.name; }
    if (e.kind === "string") { const name = `__s${nStr++}`; bld.pat(name, unescapeStr(e.text)); declared.add(name); return name; }
    die('expected a pattern name or a "string"', e.line);
  };
  const patBit = (name) => 1n << BigInt(bld.patId(name));
  const maskBits = (e) => {
    if (e.kind === "por") return maskBits(e.a) | maskBits(e.b);
    if (e.kind === "ref" && declared.has(e.name)) return patBit(e.name);
    die("expected a pattern name", e.line);
  };

  const matchGroup = (e, min) => {
    const args = e.args;
    if (!args.length) die(`${e.name}(...) needs a scan or mask, then patterns`, e.line);
    const first = args[0];
    if (first.kind === "call" && first.name === "scan") doScan(first);
    else if (!(first.kind === "ref" && masks.has(first.name))) die(`first argument of ${e.name}(...) must be scan(...) or a mask variable`, e.line);
    const pats = args.slice(1).map((a) => patArg(a));
    if (pats.length < min) die(`${e.name}(...) needs at least ${min} pattern${min > 1 ? "s" : ""}`, e.line);
    return pats;
  };

  const frameReg = (field, line) => {
    const fr = frameScope[frameScope.length - 1];
    if (!fr) die(`frame.${field} is only valid inside a \`frame\` body`, line);
    if (!fr[field]) die(`this frame has no \`${field}\` field`, line);
    return fr[field];
  };
  const allocScratch = (name, line) => { const t = bld.vreg(name, line); scratch.set(name, t); return t; };
  /* A register name or local → its index / vreg token for a Builder call. */
  const regOf = (name) => (REGISTERS.has(name) ? REG[name] : scratch.get(name));

  /* Leave a pointer/offset in %cur. */
  const loadPtr = (e) => {
    if (e.kind === "framefield") return bld.movToCur(frameReg(e.field, e.line));
    if (e.kind === "ref") {
      if (REGISTERS.has(e.name)) return bld.movToCur(REG[e.name]);
      if (scratch.has(e.name)) return bld.movToCur(scratch.get(e.name));
      die(`\`${e.name}\` is not a pointer`, e.line);
    }
    if (e.kind === "call" && e.name === "after") { if (e.args.length !== 1) die("after(pattern)", e.line); return bld.mpos(bld.patId(patArg(e.args[0]))); }
    if (e.kind === "call" && e.name === "find") { if (e.args.length !== 3) die("find(ptr, 'c', len)", e.line); loadPtr(e.args[0]); return bld.findb(Number(immVal(e.args[1])), immVal(e.args[2])); }
    die("expected a pointer (payload, a ptr variable, after(...), find(...))", e.line);
  };
  const doScan = (e) => { if (e.args.length !== 2) die("scan(ptr, len)", e.line); loadPtr(e.args[0]); bld.scan(immVal(e.args[1])); };

  /* Frame header field → the Builder ops that leave its value in %cur. */
  const FIELD_LOAD = {
    u8: (o) => bld.load(1, false, BigInt(o)),
    u16: (o) => bld.load(2, false, BigInt(o)),
    u32: (o) => bld.load(4, false, BigInt(o)),
    be16: (o) => bld.load(2, true, BigInt(o)),
    be24: (o) => { bld.load(4, true, BigInt(o)); bld.shrImm(8n); }, // top 3 of 4 bytes
    be32: (o) => bld.load(4, true, BigInt(o)),
  };

  /* `frame` unrolled up to MAX times (forward-only ⇒ termination by construction),
   * narrowing %end to each record so a body scan/load stays inside it. */
  const frameLower = (s) => {
    const f = s.fields;
    if (!f.len) die("frame needs a `len` field, e.g. `len = be16 @ 0`", s.line);
    if (f.head === undefined) die("frame needs `head = N` (the header byte count)", s.line);
    if (!FIELD_LOAD[f.len.ftype]) die(`frame len type \`${f.len.ftype}\` (u8|u16|u32|be16|be24|be32)`, s.line);
    if (f.type && !FIELD_LOAD[f.type.ftype]) die(`frame type field \`${f.type.ftype}\``, s.line);
    if (!Number.isInteger(f.head) || f.head < 1 || f.head > 255) die("frame `head` is 1..255", s.line);
    const max = Number(s.max);
    if (!Number.isInteger(max) || max < 1 || max > 64) die("frame `up to N` is 1..64", s.line);

    const realend = allocScratch(`__fe${nTmp++}`, s.line);
    bld.movToCur(REG.end);
    bld.movFromCur(realend);
    if (s.start) loadPtr(s.start); else bld.movToCur(REG.payload);

    const done = fresh();
    for (let i = 0; i < max; i++) {
      const rec = allocScratch(`__fr${nTmp}`, s.line);
      const flen = allocScratch(`__fl${nTmp}`, s.line);
      const ftype = f.type ? allocScratch(`__ft${nTmp}`, s.line) : null;
      const fdata = allocScratch(`__fd${nTmp++}`, s.line);
      bld.movFromCur(rec);                 // record start
      bld.addImm(BigInt(f.head));
      bld.cmpReg(realend);
      bld.ja(done);                        // header runs past the data: stop
      bld.movFromCur(fdata);               // frame.data = rec + head
      bld.movToCur(rec);
      FIELD_LOAD[f.len.ftype](f.len.off);
      bld.movFromCur(flen);                // frame.len
      if (f.type) { bld.movToCur(rec); FIELD_LOAD[f.type.ftype](f.type.off); bld.movFromCur(ftype); }
      // narrow %end to min(rec + head + len, realend)
      bld.movToCur(fdata);
      bld.addReg(flen);
      const okEnd = fresh();
      bld.cmpReg(realend);
      bld.jbe(okEnd);
      bld.movToCur(realend);
      bld.label(okEnd);
      bld.movFromCur(REG.end);
      frameScope.push({ len: flen, type: ftype, data: fdata });
      stmt(s.body);
      frameScope.pop();
      bld.movToCur(realend);               // restore the real end
      bld.movFromCur(REG.end);
      bld.movToCur(rec);                   // advance to the next record
      bld.addImm(BigInt(f.head));
      bld.addReg(flen);
    }
    bld.label(done);
  };

  const INV = { "==": "jne", "!=": "je", "<": "jae", ">": "jbe", "<=": "ja", ">=": "jb" };
  const DIR = { "==": "je", "!=": "jne", "<": "jb", ">": "ja", "<=": "jbe", ">=": "jae" };
  const ARITH_I = { "+": "addImm", "-": "subImm", "&": "andImm", "|": "orImm", "<<": "shlImm", ">>": "shrImm" };
  const ARITH_R = { "+": "addReg", "-": "subReg" };

  const cidrParts = (text, line) => {
    const m = String(text).replace(/^\$/, "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
    if (!m) die(`bad CIDR \`${text}\``, line);
    const oct = m.slice(1, 5).map(Number), prefix = Number(m[5]);
    if (oct.some((x) => x > 255) || prefix > 32) die(`bad CIDR \`${text}\``, line);
    return { net: ((oct[0] << 24) | (oct[1] << 16) | (oct[2] << 8) | oct[3]) >>> 0, prefix };
  };

  const value = (e) => {
    if (e.kind === "flowstate") return bld.sload();
    if (e.kind === "flowcount") return bld.bump();
    if (e.kind === "ringlen") return bld.rlen();
    if (e.kind === "ringget") { value(e.idx); return bld.rget(); }
    if (e.kind === "framefield") return bld.movToCur(frameReg(e.field, e.line));
    if (e.kind === "num" || e.kind === "char") return loadConst(immVal(e));
    if (e.kind === "ref" && REGISTERS.has(e.name)) return bld.movToCur(REG[e.name]);
    if (e.kind === "ref" && scratch.has(e.name)) return bld.movToCur(scratch.get(e.name));
    die(`\`${e.kind === "ref" ? e.name : e.kind}\` is not a readable value`, e.line);
  };
  const loadConst = (n) => { bld.andImm(0n); if (n !== 0n) bld.addImm(n); };

  const stableReg = (e) => {
    if (e.kind === "ref" && REGISTERS.has(e.name)) return REG[e.name];
    if (e.kind === "ref" && scratch.has(e.name)) return scratch.get(e.name);
    return null;
  };

  const materialize = (e) => {
    if (e.kind === "arith") {
      materialize(e.a);
      const op = e.op;
      if (e.b.kind === "num" || e.b.kind === "char") return bld[ARITH_I[op]](immVal(e.b));
      const rb = stableReg(e.b);
      if (rb !== null) { if (!ARITH_R[op]) die(`\`${op}\` needs a constant on the right (only + and - take a register)`, e.line); return bld[ARITH_R[op]](rb); }
      if (op !== "+") die(`\`${op}\` needs a constant or a plain register on the right`, e.line);
      const tmp = allocScratch(`__a${nTmp++}`, e.line);
      bld.movFromCur(tmp); materialize(e.b); return bld.addReg(tmp);
    }
    if (["flowstate", "flowcount", "ringlen", "ringget", "num", "char"].includes(e.kind)) return value(e);
    if (e.kind === "ref" && REGISTERS.has(e.name)) return bld.movToCur(REG[e.name]);
    if (e.kind === "ref" && scratch.has(e.name)) return bld.movToCur(scratch.get(e.name));
    return loadPtr(e);
  };

  const cmpToFlags = (e) => {
    if (e.b.kind === "num" || e.b.kind === "char") { value(e.a); return bld.cmpImm(immVal(e.b)); }
    const rb = stableReg(e.b);
    if (rb !== null) { value(e.a); return bld.cmpReg(rb); }
    const tmp = allocScratch(`__cmp${nTmp++}`, e.line);
    materialize(e.b); bld.movFromCur(tmp); value(e.a); bld.cmpReg(tmp);
  };

  const bandTest = (e) => {
    if (e.a.kind === "call" && e.a.name === "scan") doScan(e.a);
    else if (!(e.a.kind === "ref" && masks.has(e.a.name))) die("left of & must be scan(...) or a mask variable", e.line);
    bld.test(maskBits(e.b));
  };

  const jumpIfFalse = (e, L) => {
    switch (e.kind) {
      case "not": return jumpIfTrue(e.e, L);
      case "and": jumpIfFalse(e.a, L); jumpIfFalse(e.b, L); return;
      case "or": { const cont = fresh(); jumpIfTrue(e.a, cont); jumpIfFalse(e.b, L); bld.label(cont); return; }
      case "cmp": cmpToFlags(e); return bld[INV[e.op]](L);
      case "incidr": { value(e.a); const { net, prefix } = cidrParts(e.cidr, e.line); bld.cidr(net, prefix); return bld.jne(L); }
      case "inset": { value(e.a); bld.lpm(); return bld.jne(L); }
      case "inhash": { value(e.a); bld.hash(); return bld.jne(L); }
      case "inbloom": { value(e.a); bld.bloom(); return bld.jne(L); }
      case "inset6": { bld.lpm6(); return bld.jne(L); }
      case "band": bandTest(e); return bld.je(L);
      case "call":
        if (e.name === "any") { const pats = matchGroup(e, 1); bld.test(pats.reduce((m, p) => m | patBit(p), 0n)); return bld.je(L); }
        if (e.name === "all") { const pats = matchGroup(e, 1); for (const p of pats) { bld.test(patBit(p)); bld.je(L); } return; }
        if (e.name === "seq") {
          const pats = matchGroup(e, 2);
          for (const p of pats) { bld.test(patBit(p)); bld.je(L); }
          let prev = allocScratch(`__seq${nTmp++}`, e.line);
          bld.mpos(bld.patId(pats[0])); bld.movFromCur(prev);
          for (let i = 1; i < pats.length; i++) {
            const curReg = allocScratch(`__seq${nTmp++}`, e.line);
            bld.mpos(bld.patId(pats[i])); bld.movFromCur(curReg);
            bld.movToCur(prev); bld.cmpReg(curReg); bld.jae(L); // not strictly increasing → fail
            prev = curReg;
          }
          return;
        }
        if (e.name === "starts") { if (e.args.length !== 2) die('starts(ptr, pattern|"lit")', e.line); loadPtr(e.args[0]); bld.cmpstr(bld.patId(patArg(e.args[1]))); return bld.jne(L); }
        die(`\`${e.name}(...)\` is not a condition`, e.line);
        return;
      default: die("not a condition", e.line);
    }
  };

  const jumpIfTrue = (e, L) => {
    switch (e.kind) {
      case "not": return jumpIfFalse(e.e, L);
      case "or": jumpIfTrue(e.a, L); jumpIfTrue(e.b, L); return;
      case "and": { const cont = fresh(); jumpIfFalse(e.a, cont); jumpIfTrue(e.b, L); bld.label(cont); return; }
      case "cmp": cmpToFlags(e); return bld[DIR[e.op]](L);
      case "incidr": { value(e.a); const { net, prefix } = cidrParts(e.cidr, e.line); bld.cidr(net, prefix); return bld.je(L); }
      case "inset": { value(e.a); bld.lpm(); return bld.je(L); }
      case "inhash": { value(e.a); bld.hash(); return bld.je(L); }
      case "inbloom": { value(e.a); bld.bloom(); return bld.je(L); }
      case "inset6": { bld.lpm6(); return bld.je(L); }
      case "band": bandTest(e); return bld.jne(L);
      case "call":
        if (e.name === "any") { const pats = matchGroup(e, 1); bld.test(pats.reduce((m, p) => m | patBit(p), 0n)); return bld.jne(L); }
        if (e.name === "all" || e.name === "seq") { const cont = fresh(); jumpIfFalse(e, cont); bld.jmp(L); bld.label(cont); return; }
        if (e.name === "starts") { loadPtr(e.args[0]); bld.cmpstr(bld.patId(patArg(e.args[1]))); return bld.je(L); }
        die(`\`${e.name}(...)\` is not a condition`, e.line);
        return;
      default: die("not a condition", e.line);
    }
  };

  const verdict = (s) => {
    const r = (i) => { const a = s.args[i]; if (!a) die(`${s.verdict} needs a rule name`, s.line); if (a.kind === "string") return a.text; if (a.kind === "ref") return a.name; die('rule is a name or "string"', s.line); };
    switch (s.verdict) {
      case "pass": return bld.pass();
      case "drop": return bld.drop(bld.ruleId(r(0)));
      case "count": return bld.count(bld.ruleId(r(0)));
      case "ban": return bld.ban(bld.ruleId(r(0)), immVal(s.args[1]));
      case "rst": return bld.rst(bld.ruleId(r(0)), immVal(s.args[1]));
    }
  };

  const stmt = (s) => {
    switch (s.kind) {
      case "block": return s.stmts.forEach(stmt);
      case "if": {
        if (s.els) { const lElse = fresh(), lEnd = fresh(); jumpIfFalse(s.cond, lElse); stmt(s.then); bld.jmp(lEnd); bld.label(lElse); stmt(s.els); bld.label(lEnd); }
        else { const lEnd = fresh(); jumpIfFalse(s.cond, lEnd); stmt(s.then); bld.label(lEnd); }
        return;
      }
      case "return": return verdict(s);
      case "macrocall": {
        const m = macroMap.get(s.name);
        if (!m) die(`\`${s.name}\` is not a macro or a statement`, s.line);
        if (expanding.has(s.name)) die(`macro \`${s.name}\` is recursive`, s.line);
        expanding.add(s.name); m.stmts.forEach(stmt); expanding.delete(s.name);
        return;
      }
      case "setstate": return bld.sstore(immVal(s.value), s.ttl ? immVal(s.ttl) : 0n);
      case "ringpush": materialize(s.value); return bld.rpush();
      case "let": {
        if (REGISTERS.has(s.name) || declared.has(s.name) || masks.has(s.name)) die(`\`${s.name}\` is already a register, pattern, or mask`, s.line);
        const reg = scratch.get(s.name) ?? allocScratch(s.name, s.line);
        materialize(s.init); return bld.movFromCur(reg);
      }
      case "assign": {
        if (!scratch.has(s.name)) die(`\`${s.name}\` is not a local (declare it with \`let\`)`, s.line);
        materialize(s.init); return bld.movFromCur(scratch.get(s.name));
      }
      case "repeat": {
        const n = Number(s.count);
        if (!Number.isInteger(n) || n < 0 || n > 1024) die("repeat count is 0..1024", s.line);
        for (let k = 0; k < n; k++) stmt(s.body);
        return;
      }
      case "frame": return frameLower(s);
      case "decl": {
        if (s.type === "mask") { if (!(s.init.kind === "call" && s.init.name === "scan")) die("a mask is assigned from scan(...)", s.line); doScan(s.init); masks.add(s.name); }
        else { const reg = allocScratch(s.name, s.line); loadPtr(s.init); bld.movFromCur(reg); }
        return;
      }
      case "exprstmt": {
        const c = s.call;
        if (c.name === "log") return bld.log(immVal(c.args[0]));
        if (c.name === "count") return bld.count(bld.ruleId(c.args[0].kind === "string" ? c.args[0].text : c.args[0].name));
        if (c.name === "skip") {
          const p = c.args[0];
          if (!(p.kind === "ref" && scratch.has(p.name))) die("skip(ptrVariable, 'c')", s.line);
          bld.movToCur(scratch.get(p.name)); bld.skipb(Number(immVal(c.args[1])), 0n); return bld.movFromCur(scratch.get(p.name));
        }
        if (c.name === "redact") {
          if (c.args.length < 1) die('redact(pattern [, \'fill\'])', s.line);
          const mid = bld.patId(patArg(c.args[0]));
          const fill = c.args[1] ? Number(immVal(c.args[1])) & 0xff : 0x2a; /* default '*' */
          return bld.redact(mid, BigInt(fill));
        }
        if (c.name === "replace") {
          if (c.args.length !== 2) die('replace(pattern, "repl" | pattern)', s.line);
          const mid = bld.patId(patArg(c.args[0]));
          const rid = bld.patId(patArg(c.args[1])); /* a "literal" is interned as a pattern */
          const mlen = bld.patterns[mid].bytes.length, rlen = bld.patterns[rid].bytes.length;
          if (mlen !== rlen) die(`replace needs a same-length replacement (pattern is ${mlen} bytes, replacement is ${rlen})`, s.line);
          return bld.replace(mid, rid);
        }
        if (c.name === "dnat") {
          if (c.args.length !== 2 || c.args[0].kind !== "string") die('dnat("A.B.C.D", port)', s.line);
          const m = c.args[0].text.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
          if (!m) die(`bad IPv4 \`${c.args[0].text}\``, s.line);
          const oct = m.slice(1, 5).map(Number);
          if (oct.some((x) => x > 255)) die(`bad IPv4 \`${c.args[0].text}\``, s.line);
          const ip = ((oct[0] << 24) | (oct[1] << 16) | (oct[2] << 8) | oct[3]) >>> 0;
          const port = Number(immVal(c.args[1]));
          if (port < 0 || port > 65535) die("dnat port 0–65535", s.line);
          return bld.dnat(ip, port);
        }
        if (c.name === "redirect") {
          if (c.args.length !== 1) die("redirect(ifindex)", s.line);
          const ifx = Number(immVal(c.args[0]));
          if (!Number.isInteger(ifx) || ifx < 1 || ifx > 0xffffffff) die("redirect ifindex must be a positive integer", s.line);
          return bld.redirect(ifx);
        }
        die(`\`${c.name}(...)\` is not a statement`, s.line);
        return;
      }
      default: die("bad statement", s.line);
    }
  };

  // Program flags (order-independent of the ops).
  if (ast.nocase) bld.setNocase();
  if (ast.decode === "h2" || ast.decode === "huffman") bld.setDecode(DECODE[ast.decode], ast.reasmDport || 0);
  else if (ast.decode) bld.setTransform(TRANSFORM_TABLES[ast.decode].id, ast.reasmDport || 0);
  else if (ast.reasm) bld.setReasm(ast.reasmDport || 0);

  ast.body.forEach(stmt);
  bld.pass(); // the fall-through verdict
  return bld;
}

/* ---- the pipeline -------------------------------------------------------- */

/** Lower an AST (from parse(), or the dsl.js program builder) to a program. */
export function compileAst(ast) {
  let bld;
  try {
    bld = codegen(ast);
  } catch (e) {
    if (e instanceof CError) return { ok: false, errors: [{ line: e.line, text: e.message }], asm: "" };
    throw e;
  }
  const r = bld.finalize();
  const asm = r.listing.map((l) => "        " + l.text).join("\n");
  if (!r.ok) return { ok: false, errors: r.errors.map((e) => ({ line: 0, text: `internal: ${e.text}` })), asm };
  /* Compile the regex patterns into one DFA (null if there are none). */
  let regex = null;
  const regexPats = r.patterns.filter((p) => p.kind === "regex");
  if (regexPats.length) {
    try { regex = compileRegexes(regexPats.map((p) => ({ src: p.src, bit: p.id }))); }
    catch (e) { return { ok: false, errors: [{ line: 0, text: `regex: ${e.message}` }], asm }; }
  }
  return { ok: true, errors: [], asm, program: r.program, patterns: r.patterns, rules: r.rules, listing: r.listing, nocase: r.nocase, regex };
}

/** Compile pfw-C all the way to a program. Returns the disassembly too (`asm`). */
export function compile(source) {
  let ast;
  try {
    ast = parse(lex(source));
  } catch (e) {
    if (e instanceof CError) return { ok: false, errors: [{ line: e.line, text: e.message }], asm: "" };
    throw e;
  }
  return compileAst(ast);
}

/** Compile pfw-C to a disassembly listing (for display). { ok, errors, asm } */
export function compileToAsm(source) {
  const c = compile(source);
  return c.ok ? { ok: true, errors: [], asm: c.asm } : { ok: false, errors: c.errors, asm: c.asm };
}
