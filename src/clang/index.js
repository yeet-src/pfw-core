/* pfw-C pipeline: lex -> parse -> codegen, and the public compile entry points. */
import { compileRegexes } from "#/regex.js";
import { CError } from "#/clang/errors.js";
import { lex } from "#/clang/lex.js";
import { parse } from "#/clang/parse.js";
import { codegen } from "#/clang/codegen.js";

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
  return { ok: true, errors: [], asm, program: r.program, patterns: r.patterns, rules: r.rules, listing: r.listing, nocase: r.nocase, regex, consoleFormats: bld._consoleFormats, printkFormats: bld._printkFormats, knobs: bld._knobs, knobDefaults: bld._knobDefaults, knobStrs: bld._knobStrs, structKnobs: bld._structKnobs };
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
