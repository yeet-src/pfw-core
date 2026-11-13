/* The pfw assembler: AT&T syntax (src, dst), `$imm`, `D(%reg)`, labels,
 * `.pat` / `.nocase` directives. docs/isa.md is the reference. It parses text and
 * drives the shared Builder (builder.js) — the same op-constructor the pfw-C
 * compiler uses — so there is one definition of how an op is built.
 *
 * assemble(source) → { ok, errors, program, patterns, rules, listing }
 *   program   the `programs` map value: { nops, npats, nocase, gen, ops, pats }
 *   patterns  [{ id, name, bytes, text }]       bit `id` of %m
 *   rules     [{ id, name }]                     counters[id]
 *   listing   [{ pc, text, line }]               one entry per emitted op
 *
 * Immediates are BigInt in `ops[].imm`; the probe converts for the map.
 */
import { DECODE, LIMITS, LOAD_BE, OP, REG } from "#/isa.js";
import { Builder, BuildError, opText } from "#/builder.js";

export { opText };

/* Opcodes whose `reg` field names a register (so the Builder may allocate it). */
const REG_OPS = new Set([OP.MOV_RC, OP.MOV_CR, OP.ADD_R, OP.SUB_R, OP.CMP_R]);

const SIZE_SUFFIX = { b: 1, w: 2, l: 4, q: 8 };
const JUMPS = { jmp: OP.JMP, je: OP.JE, jz: OP.JE, jne: OP.JNE, jnz: OP.JNE, jb: OP.JB, jae: OP.JAE, ja: OP.JA, jbe: OP.JBE, jf: OP.JF };

class AsmError extends Error {}
const fail = (msg) => {
  throw new AsmError(msg);
};

/* ---- lexing one line ----------------------------------------------------- */

/* Split a line into label(s), mnemonic and operands, honouring quotes
 * and parentheses, and dropping a `;` or `#` comment. */
function lexLine(raw) {
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

/* ---- literals ------------------------------------------------------------ */

const ESC = { n: 10, r: 13, t: 9, 0: 0, "\\": 92, '"': 34, "'": 39 };

function unescape(body) {
  const out = [];
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c !== "\\") {
      out.push(c.charCodeAt(0) & 0xff);
      continue;
    }
    const e = body[++i];
    if (e === "x") {
      const hex = body.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) fail(`bad \\x escape`);
      out.push(parseInt(hex, 16));
      i += 2;
    } else if (e in ESC) out.push(ESC[e]);
    else fail(`unknown escape \\${e}`);
  }
  return out;
}

function parseNumber(tok) {
  if (/^-?0x[0-9a-fA-F]+$/.test(tok)) return BigInt(tok.replace("-", "")) * (tok.startsWith("-") ? -1n : 1n);
  if (/^-?\d+$/.test(tok)) return BigInt(tok);
  if (/^'(\\.|[^'\\])'$/.test(tok)) return BigInt(unescape(tok.slice(1, -1))[0]);
  return null;
}

/* "A.B.C.D/PREFIX" → the OP_CIDR immediate: net in the low 32 bits (host
 * order, as %saddr is), prefix length in bits 32..39. */
function parseCidr(text) {
  const m = text.replace(/^\$/, "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) fail(`bad CIDR \`${text}\` (want A.B.C.D/PREFIX)`);
  const oct = m.slice(1, 5).map(Number);
  const prefix = Number(m[5]);
  if (oct.some((x) => x > 255)) fail("CIDR octet 0–255");
  if (prefix > 32) fail("CIDR prefix 0–32");
  const net = ((oct[0] << 24) | (oct[1] << 16) | (oct[2] << 8) | oct[3]) >>> 0;
  return (BigInt(prefix) << 32n) | BigInt(net);
}

/* ---- operands ------------------------------------------------------------ */

/* {kind:"imm", text} | {kind:"reg", name, idx} | {kind:"mem", disp, base} | {kind:"label", name} */
function parseOperand(tok) {
  if (tok.startsWith("$")) return { kind: "imm", text: tok.slice(1) };
  if (tok.startsWith("%")) {
    const name = tok.slice(1).toLowerCase();
    if (!(name in REG)) fail(`no register \`%${name}\``);
    return { kind: "reg", name, idx: REG[name] };
  }
  const m = tok.match(/^(-?(?:0x[0-9a-fA-F]+|\d+))?\((%\w+)\)$/);
  if (m) {
    const base = parseOperand(m[2]);
    const disp = m[1] ? parseNumber(m[1]) : 0n;
    return { kind: "mem", disp, base };
  }
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tok)) return { kind: "label", name: tok };
  fail(`bad operand \`${tok}\``);
}

const isCur = (o) => o?.kind === "reg" && o.name === "cur";
/* %end is writable so `frame` can shrink the readable window to one record;
 * it only ever narrows reads (window/load clamp to it), so it stays safe. */
const isWritable = (o) => o?.kind === "reg" && /^(s[0-7]|m|end)$/.test(o.name);

/* ---- the assembler ------------------------------------------------------- */

export function assemble(source) {
  const errors = [];
  const bld = new Builder();

  /* A rule reference: a numeric id, or a name the Builder interns. */
  const ruleId = (text) => {
    const n = parseNumber(text);
    if (n !== null) { if (n < 0n || n >= BigInt(LIMITS.NRULES)) fail(`rule id 0–${LIMITS.NRULES - 1}`); return Number(n); }
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(text)) fail(`bad rule \`${text}\``);
    return bld.ruleId(text);
  };

  const patId = (text) => {
    const n = parseNumber(text);
    if (n !== null) { if (n < 0n || n >= BigInt(LIMITS.MAX_PATS)) fail(`pattern id 0–${LIMITS.MAX_PATS - 1}`); return Number(n); }
    return bld.patId(text);
  };

  /* `$a|$b|0x4` → a mask; names are pattern bits */
  const maskOf = (text) => {
    let mask = 0n;
    for (const part of text.split("|").map((p) => p.trim().replace(/^\$/, ""))) {
      if (!part) fail("empty term in mask");
      const n = parseNumber(part);
      if (n !== null) mask |= n;
      else mask |= 1n << BigInt(patId(part));
    }
    return mask;
  };

  const numberOf = (text, what = "immediate") => {
    const n = parseNumber(text);
    if (n === null) fail(`\`${text}\` is not a number (${what})`);
    return n;
  };

  /* Every op goes through the Builder; its reg is allocatable for register ops. */
  const emit = (code, reg = 0, imm = 0n, extra = {}) =>
    bld.op(code, reg, imm, { label: extra.label ?? null, regSlot: REG_OPS.has(code) });

  const lines = source.split(/\r?\n/);
  for (let ln = 0; ln < lines.length; ln++) {
    const lineNo = ln + 1;
    bld.at(lineNo); // stamp emitted ops with the source line
    try {
      const { labels: ls, mnem, operands } = lexLine(lines[ln]);
      for (const l of ls) bld.label(l);
      if (!mnem) continue;
      const m = mnem.toLowerCase();

      if (m === ".nocase") { bld.setNocase(); continue; }
      if (m === ".reasm") {
        let port = 0;
        if (operands.length) {
          const n = parseNumber(operands[0]);
          if (n === null || n < 0n || n > 65535n) fail(".reasm port 0–65535");
          port = Number(n);
        }
        bld.setReasm(port);
        continue;
      }
      if (m === ".decode") {
        const kind = operands[0];
        if (kind !== "h2" && kind !== "huffman") fail(".decode h2|huffman [PORT]");
        let port = 0;
        if (operands[1] !== undefined) {
          const n = parseNumber(operands[1]);
          if (n === null || n < 0n || n > 65535n) fail(".decode port 0–65535");
          port = Number(n);
        }
        bld.setDecode(DECODE[kind], port);
        continue;
      }
      if (m === ".transform") {
        /* .transform TABLE_ID [PORT] — decode through the loaded tt_cells table. */
        const id = parseNumber(operands[0]);
        if (id === null || id < 0n || id >= 8n) fail(".transform table 0–7");
        let port = 0;
        if (operands[1] !== undefined) {
          const n = parseNumber(operands[1]);
          if (n === null || n < 0n || n > 65535n) fail(".transform port 0–65535");
          port = Number(n);
        }
        bld.setTransform(Number(id), port);
        continue;
      }
      if (m === ".pat") {
        if (operands.length < 2) fail('.pat NAME, "literal" | bytes');
        const name = operands[0];
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) fail(`bad pattern name \`${name}\``);
        const body = operands.slice(1).join(",").trim();
        let bytes;
        if (body.startsWith('"')) {
          if (!body.endsWith('"')) fail("unterminated string");
          bytes = unescape(body.slice(1, -1));
        } else {
          bytes = body.split(/\s+/).map((byte) => {
            const n = parseNumber(byte);
            if (n === null || n < 0n || n > 255n) fail(`bad byte \`${byte}\``);
            return Number(n);
          });
        }
        bld.pat(name, bytes, body); // interns + checks empty / length / duplicate
        continue;
      }
      if (m.startsWith(".")) fail(`unknown directive \`${m}\``);

      /* cidr takes a CIDR literal, not a standard operand, so it is parsed
       * before parseOperand (which would choke on the dots and slash). It
       * tests %cur: `mov %saddr, %cur; cidr 10.0.0.0/8; je ...`. */
      if (m === "cidr") {
        if (operands.length !== 1) fail("cidr is `cidr A.B.C.D/PREFIX`");
        emit(OP.CIDR, 0, parseCidr(operands[0]));
        continue;
      }

      const o = operands.map(parseOperand);
      const [a, b] = o;
      const want = (n) => {
        if (o.length !== n) fail(`\`${m}\` takes ${n} operand${n === 1 ? "" : "s"}`);
      };

      if (m in JUMPS) {
        want(1);
        if (a.kind !== "label") fail("jump wants a label");
        emit(JUMPS[m], 0, 0n, { label: a.name });
      } else if (m === "mov") {
        want(2);
        if (a.kind === "reg" && isCur(b)) emit(OP.MOV_RC, a.idx);
        else if (isCur(a) && isWritable(b)) emit(OP.MOV_CR, b.idx);
        else fail("mov is `mov %REG, %cur` or `mov %cur, %sN|%m`");
      } else if (m === "lea") {
        want(2);
        if (a.kind !== "mem" || !isCur(b)) fail("lea is `lea D(%REG), %cur`");
        if (!isCur(a.base)) emit(OP.MOV_RC, a.base.idx);
        if (a.disp > 0n) emit(OP.ADD_I, 0, a.disp);
        else if (a.disp < 0n) emit(OP.SUB_I, 0, -a.disp);
      } else if (m === "add" || m === "sub") {
        want(2);
        if (!isCur(b)) fail(`${m} writes %cur`);
        if (a.kind === "imm") {
          const n = numberOf(a.text);
          const neg = n < 0n;
          emit((m === "add") !== neg ? OP.ADD_I : OP.SUB_I, 0, neg ? -n : n);
        } else if (a.kind === "reg") emit(m === "add" ? OP.ADD_R : OP.SUB_R, a.idx);
        else fail(`${m} wants $N or %reg`);
      } else if (m === "and") {
        want(2);
        if (a.kind !== "imm" || !isCur(b)) fail("and is `and $MASK, %cur`");
        emit(OP.AND_I, 0, numberOf(a.text));
      } else if (m === "or" || m === "shl" || m === "shr") {
        want(2);
        if (a.kind !== "imm" || !isCur(b)) fail(`${m} is \`${m} $N, %cur\``);
        emit(m === "or" ? OP.OR_I : m === "shl" ? OP.SHL_I : OP.SHR_I, 0, numberOf(a.text));
      } else if (/^mov(be)?[bwlq]$/.test(m)) {
        want(2);
        const be = m.includes("be");
        const size = SIZE_SUFFIX[m[m.length - 1]];
        if (be && size === 1) fail("movbeb makes no sense");
        if (a.kind !== "mem" || !isCur(b)) fail(`${m} is \`${m} D(%REG), %cur\``);
        if (!isCur(a.base)) emit(OP.MOV_RC, a.base.idx);
        let disp = a.disp;
        if (disp < 0n) {
          emit(OP.SUB_I, 0, -disp);
          disp = 0n;
        }
        emit(OP.LOAD, size | (be ? LOAD_BE : 0), disp);
      } else if (m === "cmp") {
        want(2);
        if (!isCur(b)) fail("cmp compares against %cur");
        if (a.kind === "imm") emit(OP.CMP_I, 0, numberOf(a.text));
        else if (a.kind === "reg") emit(OP.CMP_R, a.idx);
        else fail("cmp wants $N or %reg");
      } else if (m === "test") {
        want(2);
        if (a.kind !== "imm" || !(b.kind === "reg" && b.name === "m")) fail("test is `test $MASK, %m`");
        emit(OP.TEST, 0, maskOf(a.text));
      } else if (m === "scan") {
        if (o.length < 1 || o.length > 2) fail("scan is `scan $LEN[, (%cur)]`");
        if (a.kind !== "imm") fail("scan wants $LEN");
        if (b && !(b.kind === "mem" && isCur(b.base) && b.disp === 0n)) fail("scan reads at (%cur)");
        const n = numberOf(a.text);
        if (n < 1n || n > BigInt(LIMITS.SCAN_CAP)) fail(`scan length 1–${LIMITS.SCAN_CAP}`);
        emit(OP.SCAN, 0, n);
      } else if (m === "mpos") {
        want(2);
        if (a.kind !== "imm" || !isCur(b)) fail("mpos is `mpos $PAT, %cur`");
        emit(OP.MPOS, patId(a.text));
      } else if (m === "cmpstr") {
        want(2);
        if (a.kind !== "imm" || !(b.kind === "mem" && isCur(b.base))) fail("cmpstr is `cmpstr $PAT, (%cur)`");
        if (b.disp !== 0n) fail("cmpstr reads at (%cur); move the cursor first");
        emit(OP.CMPSTR, patId(a.text));
      } else if (m === "findb") {
        want(2);
        if (a.kind !== "imm" || b.kind !== "imm") fail("findb is `findb $BYTE, $LEN`");
        const byte = numberOf(a.text, "byte");
        const len = numberOf(b.text, "length");
        if (byte < 0n || byte > 255n) fail("byte 0–255");
        if (len < 1n || len > BigInt(LIMITS.SCAN_CAP)) fail(`length 1–${LIMITS.SCAN_CAP}`);
        emit(OP.FINDB, Number(byte), len);
      } else if (m === "skipb") {
        if (o.length < 1 || o.length > 2) fail("skipb is `skipb $BYTE[, $MAX]`");
        if (a.kind !== "imm") fail("skipb wants $BYTE");
        const byte = numberOf(a.text, "byte");
        if (byte < 0n || byte > 255n) fail("byte 0–255");
        emit(OP.SKIPB, Number(byte), b ? numberOf(b.text) : 0n);
      } else if (m === "pass") {
        want(0);
        emit(OP.PASS);
      } else if (m === "drop" || m === "count") {
        want(1);
        if (a.kind !== "imm") fail(`${m} wants $RULE`);
        emit(m === "drop" ? OP.DROP : OP.COUNT, ruleId(a.text));
      } else if (m === "log") {
        want(1);
        if (a.kind !== "imm") fail("log wants $LEN");
        const n = numberOf(a.text);
        if (n < 1n || n > BigInt(LIMITS.LOG_CAP)) fail(`log length 1–${LIMITS.LOG_CAP}`);
        emit(OP.LOG, 0, n);
      } else if (m === "ban" || m === "rst") {
        if (o.length < 1 || o.length > 2) fail(`${m} is \`${m} $RULE[, $TTL_SECONDS]\``);
        if (a.kind !== "imm") fail(`${m} wants $RULE`);
        emit(m === "ban" ? OP.BAN : OP.RST, ruleId(a.text), b ? numberOf(b.text, "ttl") : 0n);
      } else if (m === "flow") {
        want(1);
        if (!isCur(a)) fail("flow is `flow %cur`");
        emit(OP.FLOW);
      } else if (m === "mark") {
        if (o.length < 1 || o.length > 2) fail("mark is `mark $V[, $TTL_SECONDS]`");
        if (a.kind !== "imm") fail("mark wants $V");
        const v = numberOf(a.text);
        if (v < 16n) fail("user marks start at 16");
        emit(OP.MARK, Number(v & 0xffffffffn), b ? numberOf(b.text, "ttl") : 0n);
      } else if (m === "sload") {
        want(1);
        if (!isCur(a)) fail("sload is `sload %cur`");
        emit(OP.SLOAD);
      } else if (m === "sstore") {
        if (o.length < 1 || o.length > 2) fail("sstore is `sstore $STATE[, $TTL_SECONDS]`");
        if (a.kind !== "imm") fail("sstore wants $STATE");
        const ttl = b ? Number(numberOf(b.text, "ttl") & 0xffffffffn) : 0;
        emit(OP.SSTORE, ttl, numberOf(a.text, "state"));
      } else if (m === "bump") {
        want(1);
        if (!isCur(a)) fail("bump is `bump %cur`");
        emit(OP.BUMP);
      } else if (m === "rpush" || m === "rget" || m === "rlen") {
        want(1);
        if (!isCur(a)) fail(`${m} is \`${m} %cur\``);
        emit(m === "rpush" ? OP.RPUSH : m === "rget" ? OP.RGET : OP.RLEN);
      } else fail(`unknown instruction \`${m}\``);

    } catch (e) {
      if (!(e instanceof AsmError || e instanceof BuildError)) throw e;
      errors.push({ line: lineNo, text: e.message });
    }
  }

  /* The Builder resolves labels, allocates registers, and emits the program. */
  const r = bld.finalize();
  return {
    ok: errors.length === 0 && r.ok,
    errors: [...errors, ...r.errors],
    program: r.program,
    patterns: r.patterns,
    rules: r.rules,
    listing: r.listing,
    nocase: r.nocase,
    reasm: r.reasm,
  };
}
