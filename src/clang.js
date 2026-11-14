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
 *     if (dport != 8080) decide pass;
 *     if (scan(payload, 1460) & (gptbot | claudebot)) {
 *       log(96);
 *       decide rst("crawler", 60);
 *     }
 *     decide pass;
 *   }
 *
 * Reads (ints): payload sport dport proto len l3 l4 end ifindex
 * Verdicts (decide): pass | drop(rule) | count(rule) | ban(rule, ttl) | rst(rule, ttl)
 * Statements: if/else, match/switch, log(n), skip(ptr, 'c'), and the declarations
 *   mask m = scan(ptr, len);   ptr p = after(pat) | find(ptr, 'c', len) | payload;
 * Calls: scan(ptr,len)->mask, starts(ptr, pat|"lit")->bool, after(pat)->ptr,
 *   find(ptr,'c',len)->ptr
 *
 * The compiler is split by concern under ./clang/:
 *   errors.js    the CError type
 *   lang.js      shared constants (register names, verdict keywords)
 *   lex.js       source text -> tokens
 *   parse.js     tokens -> AST
 *   codegen.js   AST -> program ops, via the shared Builder
 *   index.js     the pipeline: compile / compileAst / compileToAsm
 * This file is the stable barrel so `#/clang.js` keeps resolving.
 */
export { compile, compileAst, compileToAsm } from "#/clang/index.js";
