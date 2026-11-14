/* pfw assembler lexer: split one line into label(s), mnemonic and operands. */
import { fail } from "#/asm/errors.js";

/* ---- lexing one line ----------------------------------------------------- */

/* Split a line into label(s), mnemonic and operands, honouring quotes
 * and parentheses, and dropping a `;` or `#` comment. */
export function lexLine(raw) {
  const out = { labels: [], mnem: null, operands: [] };
  let i = 0;
  const s = raw;
  const n = s.length;
  const isWs = (c) => c === " " || c === "\t";
  const skipWs = () => {
    while (i < n && isWs(s[i])) i++;
  };
  const isIdent = (c) => /[A-Za-z0-9_.]/.test(c);

  for (;;) {
    skipWs();
    if (i >= n || s[i] === ";" || s[i] === "#") return out;
    let j = i;
    while (j < n && isIdent(s[j])) j++;
    const word = s.slice(i, j);
    let k = j;
    while (k < n && isWs(s[k])) k++;
    if (word && s[k] === ":") {
      out.labels.push(word);
      i = k + 1;
      continue;
    }
    if (!word) fail(`unexpected \`${s[i]}\``);
    out.mnem = word;
    i = j;
    break;
  }
  /* operands: comma separated at depth 0, strings kept whole */
  let depth = 0;
  let cur = "";
  let inStr = false;
  for (; i < n; i++) {
    const c = s[i];
    if (inStr) {
      cur += c;
      if (c === "\\" && i + 1 < n) {
        cur += s[++i];
        continue;
      }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      cur += c;
      continue;
    }
    if (c === "'" && i + 2 < n) {
      let j = i + 1;
      let lit = "'";
      if (s[j] === "\\") {
        lit += s[j] + s[j + 1];
        j += 2;
      } else {
        lit += s[j];
        j += 1;
      }
      if (s[j] !== "'") fail("unterminated char literal");
      cur += lit + "'";
      i = j;
      continue;
    }
    if ((c === ";" || c === "#") && depth === 0) break;
    if (c === "(") depth++;
    if (c === ")") depth--;
    if (c === "," && depth === 0) {
      out.operands.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (inStr) fail("unterminated string");
  if (cur.trim()) out.operands.push(cur.trim());
  return out;
}
