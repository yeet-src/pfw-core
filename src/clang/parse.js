/* pfw-C parser: tokens -> AST. */
import { CError } from "#/clang/errors.js";
import { LIMITS } from "#/isa.js";
import { TRANSFORM_TABLES } from "#/transform.js";
import { READS, VERDICTS } from "#/clang/lang.js";

const ARITH = ["+", "-", "&", "|", "<<", ">>"];
const TERM = ["*", "%"];

export function parse(toks) {
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
  const functions = [];
  const structKnobs = [];            // knob struct NAME { fields } declarations
  const structKnobNames = new Map(); // NAME -> Set(field) for member resolution in parsePrimary
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
      /* Parentheses hold a condition or, failing that, arithmetic: `(a == b)`
       * and `(a + b)` are both written this way, and only what follows the
       * first operand tells them apart. */
      const mark = pos;
      const e = parseExpr();
      if (isP(")")) { next(); return e; }
      if (peek().type === "punct" && (ARITH.includes(peek().value) || TERM.includes(peek().value))) {
        pos = mark;
        const a = parseArith();
        eat("punct", ")");
        return a;
      }
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
        if (member === "hash") return { kind: "flowhash", line: t.line };
        if (member !== "state" && member !== "count")
          err(`flow has no member \`${member}\` (only \`state\`, \`count\` and \`hash\`)`);
        return { kind: member === "count" ? "flowcount" : "flowstate", line: t.line };
      }
      /* src.state / src.count / src.rate(r, b): the per-flow members, scoped to
       * the SOURCE ADDRESS instead of the connection. Bare `src` is the address. */
      if (name === "src" && isP(".")) {
        next();
        const member = eat("ident").value;
        if (member === "rate") { const call = parseCall("rate", t.line); return { ...call, scope: 1 }; }
        if (member !== "state" && member !== "count")
          err(`src has no member \`${member}\` (only \`state\`, \`count\` and \`rate(per_second, burst)\`)`);
        return { kind: member === "count" ? "flowcount" : "flowstate", scope: 1, line: t.line };
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
      if (name === "argv") {
        eat("punct", "[");
        const it = eat("number");
        const idx = Number(it.value.startsWith("0x") ? parseInt(it.value, 16) : it.value);
        if (idx < 0 || idx >= LIMITS.ARGC) err(`argv index 0–${LIMITS.ARGC - 1}`);
        eat("punct", "]");
        let def = null;
        if (isP("??")) { next(); const d = peek(); if (d.type !== "number" && d.type !== "char") err("`??` default must be a number or char literal"); next(); def = { kind: d.type === "char" ? "char" : "num", text: d.value, line: d.line }; }
        return { kind: "arg", index: idx, def, line: t.line };
      }
      if (name === "argc") return { kind: "argc", line: t.line };
      if (structKnobNames.has(name) && isP(".")) {
        next(); const field = eat("ident").value;
        if (!structKnobNames.get(name).has(field)) err(`struct knob \`${name}\` has no field \`${field}\``);
        return { kind: "knob", knob: `${name}.${field}`, def: null, line: t.line };
      }
      if (name === "knob") {
        eat("punct", "("); if (peek().type !== "string") err('knob("name")'); const kn = next().value; eat("punct", ")");
        let def = null;
        if (isP("??")) { next(); const d = peek(); if (d.type !== "number" && d.type !== "char") err("`??` default must be a number or char literal"); next(); def = { kind: d.type === "char" ? "char" : "num", text: d.value, line: d.line }; }
        return { kind: "knob", knob: kn, def, line: t.line };
      }
      /* u8(p), be16(p + 2), ...: read one field at a pointer. The argument is
       * value arithmetic, so the offset is written where it is used. */
      if (READS.has(name) && isP("(")) {
        next();
        const ptr = parseArith();
        eat("punct", ")");
        return { kind: "read", ftype: name, ptr, line: t.line };
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
  /* Arithmetic over values. `*` and `%` bind tighter than the rest, as anyone
   * reading `a + b * c` expects; the others — + - & | << >> — are one level,
   * left to right, as they always were. Only used where a plain integer is
   * wanted (let / assignment / a read's pointer), never a mask test. */
  const parseTerm = () => {
    let e = parsePrimary();
    while (peek().type === "punct" && TERM.includes(peek().value)) {
      const op = next().value;
      e = { kind: "arith", op, a: e, b: parsePrimary(), line: e.line };
    }
    return e;
  };
  const parseArith = () => {
    let e = parseTerm();
    while (peek().type === "punct" && ARITH.includes(peek().value)) {
      const op = next().value;
      e = { kind: "arith", op, a: e, b: parseTerm(), line: e.line };
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
    if (isKw("match")) {
      // no fall-through: exactly one arm runs. `case V[, V] { ... }` / `default { ... }`
      next(); eat("punct", "("); const scrut = parseArith(); eat("punct", ")"); eat("punct", "{");
      const arms = []; let def = null;
      while (!isP("}")) {
        if (isKw("default")) { next(); def = parseStmt(); }
        else if (isKw("case")) {
          next(); const values = [parsePrimary()];
          while (isP(",")) { next(); values.push(parsePrimary()); }
          arms.push({ values, body: parseStmt() });
        } else err("match arms are `case V { ... }` or `default { ... }`");
      }
      eat("punct", "}");
      return { kind: "match", scrut, arms, default: def, line: t.line };
    }
    if (isKw("switch")) {
      // C-style fall-through: `case V:` statement lists, `break;` to exit
      next(); eat("punct", "("); const scrut = parseArith(); eat("punct", ")"); eat("punct", "{");
      const entries = [];
      const body = () => { const stmts = []; while (!isP("}") && !isKw("case") && !isKw("default")) stmts.push(parseStmt()); return stmts; };
      while (!isP("}")) {
        if (isKw("case")) {
          next(); const values = [parsePrimary()];
          while (isP(",")) { next(); values.push(parsePrimary()); }
          eat("punct", ":"); entries.push({ values, stmts: body() });
        } else if (isKw("default")) {
          next(); eat("punct", ":"); entries.push({ default: true, stmts: body() });
        } else err("switch body is `case V:` or `default:`");
      }
      eat("punct", "}");
      return { kind: "switch", scrut, entries, line: t.line };
    }
    if (isKw("break")) { next(); eat("punct", ";"); return { kind: "break", line: t.line }; }
    if (isKw("decide")) {
      // terminal verdict: decide pass|drop|count|ban|rst [ (...) ] ;
      next();
      const name = eat("ident").value;
      if (!VERDICTS.has(name)) err(`\`${name}\` is not a verdict (pass, drop, count, ban, rst)`);
      let args = [];
      if (isP("(")) args = parseCall(name, t.line).args;
      eat("punct", ";");
      return { kind: "return", verdict: name, args, line: t.line };
    }
    if (isKw("return")) {
      // value return from a subroutine: return <expr>;  -> rv = expr, then ret
      next();
      if (peek().type === "ident" && VERDICTS.has(peek().value))
        err(`verdicts use \`decide\` now — write \`decide ${peek().value}${peek().value === "pass" ? "" : "(...)"};\` (\`return\` is for a subroutine's value)`);
      const value = parseArith();
      eat("punct", ";");
      return { kind: "freturn", value, line: t.line };
    }
    if (isKw("mask") || isKw("ptr")) {
      const type = next().value;
      const name = eat("ident").value;
      eat("punct", "=");
      /* A pointer is an offset, so it is computed like any other value:
       * `ptr q = payload + 5;`. A mask comes from a scan, which is a call. */
      const init = type === "ptr" ? parseArith() : parseExpr();
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
    /* flow.state = N; — set this connection's state (src.state = N; — the source's) */
    if (t.type === "ident" && (t.value === "flow" || t.value === "src")) {
      const scope = t.value === "src" ? 1 : 0;
      next();
      eat("punct", ".");
      const member = eat("ident").value;
      if (member !== "state") err(`${t.value} has no member \`${member}\` (assignable: state)`);
      eat("punct", "=");
      const value = parseExpr();
      let ttl = null;
      if (isKw("for")) {
        next();
        ttl = parseExpr();
      }
      eat("punct", ";");
      return { kind: "setstate", value, ttl, scope, line: t.line };
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
    } else if (isKw("knob")) {
      // knob struct NAME { f1 [?? d], f2, ... };  — a named group of consecutive knob slots
      next();
      if (!isKw("struct")) err("top-level `knob` is `knob struct NAME { f1, f2 };`");
      next();
      const sname = eat("ident").value;
      if (structKnobNames.has(sname)) err(`struct knob \`${sname}\` already declared`);
      eat("punct", "{");
      const fields = [];
      const fset = new Set();
      while (!isP("}")) {
        const fname = eat("ident").value;
        if (fset.has(fname)) err(`duplicate field \`${fname}\` in struct knob \`${sname}\``);
        fset.add(fname);
        let def = null;
        if (isP("??")) { next(); const d = peek(); if (d.type !== "number" && d.type !== "char") err("`??` default must be a number or char literal"); next(); def = { kind: d.type === "char" ? "char" : "num", text: d.value, line: d.line }; }
        fields.push({ name: fname, def });
        if (isP(",")) next(); else break;
      }
      eat("punct", "}"); eat("punct", ";");
      structKnobs.push({ name: sname, fields });
      structKnobNames.set(sname, fset);
    } else if (isKw("fn")) {
      next();
      const name = eat("ident").value;
      eat("punct", "(");
      const params = [];
      while (!isP(")")) { params.push(eat("ident").value); if (isP(",")) next(); else break; }
      eat("punct", ")");
      if (params.length > 7) err("a subroutine takes at most 7 params (a0..a6)");
      eat("punct", "{");
      const stmts = [];
      while (!isP("}")) stmts.push(parseStmt());
      eat("punct", "}");
      functions.push({ name, params, stmts });
    } else if (isKw("filter")) {
      next();
      eat("punct", "{");
      const stmts = [];
      while (!isP("}")) stmts.push(parseStmt());
      eat("punct", "}");
      body = stmts;
    } else {
      err(`expected \`pattern\`, \`nocase\`, \`reassemble\`, \`fn\` or \`filter\`, found \`${peek().value ?? peek().type}\``);
    }
  }
  if (!body) throw new CError("a program needs a `filter { … }` block", 0);
  return { patterns, macros, functions, structKnobs, nocase, reasm, reasmDport, decode, body };
}
