/* A compile error that carries the source line, thrown by the lexer/parser and
 * caught at the pipeline boundary (turned into { ok:false, errors:[...] }). */
export class CError extends Error {
  constructor(msg, line) {
    super(msg);
    this.line = line;
  }
}
