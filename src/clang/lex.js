/* pfw-C lexer: source text -> tokens. */
import { CError } from "#/clang/errors.js";

const PUNCT = ["??", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "<", ">", "!", "&", "|", "+", "-", "*", "%", "(", ")", "{", "}", "[", "]", ";", ",", "=", ".", "@", ":"];

export function lex(src) {
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
      if (src[j] === "\\" && src[j + 1] === "x") {
        /* '\xNN': a byte by its hex value, as a string literal spells it. */
        const hex = src.slice(j + 2, j + 4);
        if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new CError("a '\\x' character literal takes two hex digits, like '\\x1f'", line);
        raw = "\\x" + hex;
        j += 4;
      } else if (src[j] === "\\") {
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
