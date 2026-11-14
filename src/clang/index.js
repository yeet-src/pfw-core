/* pfw-C: a small C-style language that compiles to pfw assembly — the entry
 * point. `#/clang` (or the package subpath `pfw-core/clang`) resolves here.
 *
 *   nocase;
 *   pattern gptbot = "GPTBot", claudebot = "ClaudeBot";
 *   filter {
 *     if (dport != 8080) decide pass;
 *     if (scan(payload, 1460) & (gptbot | claudebot)) { log(96); decide rst("crawler", 60); }
 *     decide pass;
 *   }
 *
 * The compiler is split by concern under this directory:
 *   errors.js    the CError type
 *   lang.js      shared constants (register names, verdict keywords)
 *   lex.js       source text -> tokens
 *   parse.js     tokens -> AST
 *   codegen.js   AST -> program ops, via the shared Builder
 *   index.js     the pipeline below: compile / compileAst / compileToAsm
 */
import { compileRegexes } from "#/regex.js";
import { CError } from "#/clang/errors.js";
import { lex } from "#/clang/lex.js";
import { parse } from "#/clang/parse.js";
import { codegen } from "#/clang/codegen.js";
import { BuildError } from "#/builder";

/** Lower an AST (from parse(), or the dsl.js program builder) to a program. */
export function compileAst(ast) {
  let bld;
  try {
    bld = codegen(ast);
  } catch (e) {
    if (e instanceof CError) return { ok: false, errors: [{ line: e.line, text: e.message }], asm: "" };
    /* The Builder refusing an op (most often: the program outgrew MAX_OPS) is a
     * compile error like any other, not a crash for the caller to catch. */
    if (e instanceof BuildError) return { ok: false, errors: [{ line: 0, text: e.message }], asm: "" };
    throw e;
  }
  const r = bld.finalize();
  const asm = r.listing.map((l) => "        " + l.text).join("\n");
  if (!r.ok) return { ok: false, errors: r.errors.map((e) => ({ line: 0, text: `internal: ${e.text}` })), asm };
  /* Compile the regex patterns into one DFA (null if there are none). */
  let regex = null;
  const regexPats = r.patterns.filter((p) => p.kind === "regex");
  if (regexPats.length) {
    try { regex = compileRegexes(regexPats.map((p) => ({ src: p.src, bit: p.id })), r.nocase); /* nocase: the input is folded, so the DFA must be too */ }
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
