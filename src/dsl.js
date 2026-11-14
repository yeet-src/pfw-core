/* A functional builder for pfw-C programs: author a rule as composed JS values
 * instead of source text. Expressions and statements are plain AST nodes made by
 * these functions; blocks are just lists of statements, so `iff`, `frame` and
 * `repeat` take them as arguments (blocks-as-values — curry `iff(cond)(then)` if
 * you like). It produces the same AST the parser does, so compileAst (clang.js)
 * does all the lowering — this is purely a nicer front door.
 *
 *   import * as C from "pfw-core/dsl";
 *   const prog = C.program(
 *     C.nocase(),
 *     C.pattern("bot", "GPTBot"),
 *     C.filter(
 *       C.iff(C.ne(C.dport, 80), C.pass()),
 *       C.iff(C.band(C.scan(C.payload, 1460), "bot"), C.rst("crawler", 60)),
 *       C.pass(),
 *     ),
 *   );
 *   // prog === compile(sourceText) for the equivalent program
 */
import { compileAst } from "#/clang.js";
import { Program } from "#/program.js";

/* ---- expressions --------------------------------------------------------- */

const isNode = (x) => x && typeof x === "object" && "kind" in x;
export const num = (n) => ({ kind: "num", text: String(n) });
export const ref = (name) => ({ kind: "ref", name });
/* Coerce: a node passes through; a number is a literal; a string is a name
 * (register / local / pattern). */
const E = (x) => (isNode(x) ? x : typeof x === "string" ? ref(x) : num(x));

// readable registers
export const payload = ref("payload"), sport = ref("sport"), dport = ref("dport");
export const proto = ref("proto"), len = ref("len"), end = ref("end");
export const l3 = ref("l3"), l4 = ref("l4"), ifindex = ref("ifindex"), frame = ref("frame"), src = ref("src");
// per-flow state and the ring / frame fields
export const flowState = { kind: "flowstate" }, flowCount = { kind: "flowcount" };
export const ringLen = { kind: "ringlen" };
export const ringGet = (i) => ({ kind: "ringget", idx: E(i) });
export const frameLen = { kind: "framefield", field: "len" };
export const frameType = { kind: "framefield", field: "type" };
export const frameData = { kind: "framefield", field: "data" };

const cmp = (op) => (a, b) => ({ kind: "cmp", op, a: E(a), b: E(b) });
export const eq = cmp("=="), ne = cmp("!="), lt = cmp("<"), gt = cmp(">"), le = cmp("<="), ge = cmp(">=");
export const and = (a, b) => ({ kind: "and", a: E(a), b: E(b) });
export const or = (a, b) => ({ kind: "or", a: E(a), b: E(b) });
export const not = (e) => ({ kind: "not", e: E(e) });
/* scan(...)/mask & a pattern (or several, as `p1 | p2 | ...`). */
export const band = (a, ...pats) => {
  if (!pats.length) throw new Error("band(scan|mask, ...patterns) needs a pattern");
  const por = (xs) => (xs.length === 1 ? E(xs[0]) : { kind: "por", a: E(xs[0]), b: por(xs.slice(1)) });
  return { kind: "band", a: E(a), b: por(pats) };
};
export const inCidr = (a, cidr) => ({ kind: "incidr", a: E(a), cidr }); // `a in "10.0.0.0/8"`

const arith = (op) => (a, b) => ({ kind: "arith", op, a: E(a), b: E(b) });
export const add = arith("+"), sub = arith("-"), bor = arith("|"), bitand = arith("&"), shl = arith("<<"), shr = arith(">>");

export const scan = (ptr, length) => ({ kind: "call", name: "scan", args: [E(ptr), num(length)] });
export const after = (pat) => ({ kind: "call", name: "after", args: [E(pat)] });
export const find = (ptr, ch, length) => ({ kind: "call", name: "find", args: [E(ptr), chr(ch), num(length)] });
export const starts = (ptr, pat) => ({ kind: "call", name: "starts", args: [E(ptr), E(pat)] });
export const any = (first, ...pats) => ({ kind: "call", name: "any", args: [E(first), ...pats.map(E)] });
export const all = (first, ...pats) => ({ kind: "call", name: "all", args: [E(first), ...pats.map(E)] });
export const seq = (first, ...pats) => ({ kind: "call", name: "seq", args: [E(first), ...pats.map(E)] });

const chr = (c) => (typeof c === "string" && c.length === 1 ? { kind: "char", text: c } : num(c));
const ruleArg = (r) => { if (typeof r !== "string") throw new Error("rule must be a name (string)"); return { kind: "string", text: r }; };

/* ---- statements (each returns an AST statement node) --------------------- */

const asBlock = (s) => (Array.isArray(s) ? { kind: "block", stmts: s.flat() } : s?.kind === "block" ? s : { kind: "block", stmts: [s] });

export const pass = () => ({ kind: "return", verdict: "pass", args: [] });
export const drop = (rule) => ({ kind: "return", verdict: "drop", args: [ruleArg(rule)] });
export const count = (rule) => ({ kind: "return", verdict: "count", args: [ruleArg(rule)] });
export const ban = (rule, ttl) => ({ kind: "return", verdict: "ban", args: [ruleArg(rule), num(ttl)] });
export const rst = (rule, ttl = 0) => ({ kind: "return", verdict: "rst", args: [ruleArg(rule), num(ttl)] });

export const block = (...stmts) => ({ kind: "block", stmts: stmts.flat() });
export const iff = (cond, then, els) => ({ kind: "if", cond: E(cond), then: asBlock(then), els: els === undefined ? null : asBlock(els) });
export const repeat = (n, ...body) => ({ kind: "repeat", count: String(n), body: block(...body) });

export const let_ = (name, e) => ({ kind: "let", name, init: E(e) });
export const assign = (name, e) => ({ kind: "assign", name, init: E(e) });
export const ptr = (name, e) => ({ kind: "decl", type: "ptr", name, init: E(e) });
export const mask = (name, scanExpr) => ({ kind: "decl", type: "mask", name, init: E(scanExpr) });
export const ringPush = (e) => ({ kind: "ringpush", value: E(e) });
export const setState = (v, ttl) => ({ kind: "setstate", value: num(v), ttl: ttl == null ? null : num(ttl) });
export const log = (n) => ({ kind: "exprstmt", call: { kind: "call", name: "log", args: [num(n)] } });
export const skip = (ptrName, ch) => ({ kind: "exprstmt", call: { kind: "call", name: "skip", args: [ref(ptrName), chr(ch)] } });
/** redact(patName[, fill]): overwrite every match of the pattern with a fill byte (default '*'). */
export const redact = (patName, fill = "*") => ({ kind: "exprstmt", call: { kind: "call", name: "redact", args: fill == null ? [ref(patName)] : [ref(patName), chr(fill)] } });
/** replace(patName, "repl"): overwrite every match with a same-length replacement string. */
export const replace = (patName, repl) => ({ kind: "exprstmt", call: { kind: "call", name: "replace", args: [ref(patName), { kind: "string", text: repl }] } });
/** dnat("A.B.C.D", port): rewrite the packet's destination IPv4 + port and forward. */
export const dnat = (ip, port) => ({ kind: "exprstmt", call: { kind: "call", name: "dnat", args: [{ kind: "string", text: ip }, num(port)] } });

/* frameWalk({ at?, len:{type,off}, type?:{type,off}, head, up }, ...body) */
export const frameWalk = (spec, ...body) => ({
  kind: "frame",
  start: spec.at ? E(spec.at) : null,
  fields: {
    len: { ftype: spec.len.type, off: spec.len.off, line: 0 },
    ...(spec.type ? { type: { ftype: spec.type.type, off: spec.type.off, line: 0 } } : {}),
    head: spec.head,
  },
  max: spec.up,
  body: block(...body),
  line: 0,
});

/* ---- program parts and assembly ------------------------------------------ */

export const nocase = () => ({ _part: "nocase" });
export const reassemble = (port = 0) => ({ _part: "reasm", port });
export const decode = (kind, port = 0) => ({ _part: "decode", kind, port });
export const pattern = (name, def) => ({
  _part: "pattern", name,
  def: typeof def === "string" ? { kind: "string", text: def } : { kind: "bytes", bytes: def.map((b) => num(b)) },
});
export const filter = (...stmts) => ({ _part: "filter", stmts: stmts.flat() });

/** Assemble program parts into an AST and compile it (same result as compile()). */
export function program(...parts) {
  const ast = { patterns: [], macros: [], nocase: false, reasm: false, reasmDport: 0, decode: null, body: null };
  for (const p of parts.flat()) {
    switch (p._part) {
      case "nocase": ast.nocase = true; break;
      case "reasm": ast.reasm = true; if (p.port) ast.reasmDport = p.port; break;
      case "decode": ast.decode = p.kind; ast.reasm = true; if (p.port) ast.reasmDport = p.port; break;
      case "pattern": ast.patterns.push({ name: p.name, def: p.def }); break;
      case "filter": ast.body = p.stmts; break;
      default: throw new Error("not a program part: " + JSON.stringify(p));
    }
  }
  if (!ast.body) throw new Error("a program needs a filter(...)");
  const compiled = compileAst(ast);
  if (!compiled.ok) throw new Error("compile: " + JSON.stringify(compiled.errors));
  return new Program(compiled);
}
