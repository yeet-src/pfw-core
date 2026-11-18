/* The HPACK Huffman code (RFC 7541, Appendix B), built on the host into a
 * nibble (4-bit) decode state machine — the "transform table" the kernel's
 * `transform` op runs. This is the P2 thesis in one file: a decoding is *data*
 * the host derives from a spec, not states hand-coded in the kernel. The same
 * build shape takes any prefix code; Huffman is the first table.
 *
 * A cell is state × nibble -> (next state, emit?, symbol, accept?, fail?),
 * packed into one u32 the interpreter reads with shifts:
 *   bits  0..8  next state (<= 511)
 *   bit   9     EMIT  — this transition completes a symbol
 *   bit   10    ACCEPT — the next state is a valid end-of-input boundary
 *   bit   11    FAIL  — the input walked off the code tree (or hit EOS)
 *   bits  16..23 symbol (the byte emitted when EMIT)
 * Min code length is 5 > 4 bits, so at most one symbol completes per nibble.
 */

export const TT_CELL = { NEXT: 0x1ff, EMIT: 1 << 9, ACCEPT: 1 << 10, FAIL: 1 << 11, SYM_SHIFT: 16 };

import { TABLE } from "#/huffman/table.js";

const EOS = 256;

/* The code table as [{ sym, code, bits }]. */
export function codes() {
  return TABLE.trim().split("\n").map((l) => {
    const [sym, code, bits] = l.trim().split(/\s+/);
    return { sym: Number(sym), code: parseInt(code, 16), bits: Number(bits) };
  });
}

/* Build the binary code tree. Each node: { sym|null, kids[2], ones, depth }.
 * `ones` is true while the path from the root is all 1-bits — those internal
 * nodes at depth 1..7 are the valid Huffman padding, hence accept states. */
function buildTree() {
  const root = { sym: null, kids: [null, null], ones: true, depth: 0 };
  for (const { sym, code, bits } of codes()) {
    let n = root;
    for (let j = 0; j < bits; j++) {
      const bit = (code >> (bits - 1 - j)) & 1;
      if (!n.kids[bit]) n.kids[bit] = { sym: null, kids: [null, null], ones: n.ones && bit === 1, depth: n.depth + 1 };
      n = n.kids[bit];
    }
    n.sym = sym;
  }
  return root;
}

const isAccept = (n) => n.depth === 0 || (n.ones && n.depth <= 7);

/* Flatten the tree into the nibble state machine. Returns { nstates, cells }
 * where cells[state * 16 + nibble] is the packed u32. */
export function buildHuffman() {
  const root = buildTree();
  const ids = new Map([[root, 0]]);
  const order = [root];
  const cellsOf = []; // per state: array of 16 u32

  for (let s = 0; s < order.length; s++) {
    const state = order[s];
    const row = new Array(16).fill(0);
    for (let nib = 0; nib < 16; nib++) {
      let n = state, emit = false, sym = 0, fail = false;
      for (let b = 3; b >= 0 && !fail; b--) {
        const bit = (nib >> b) & 1;
        n = n.kids[bit];
        if (!n) { fail = true; break; }
        if (n.sym !== null) {
          if (n.sym === EOS) { fail = true; break; } // EOS in the input is an error
          emit = true; sym = n.sym; n = root;         // symbol complete; restart
        }
      }
      let cell = 0;
      if (fail) {
        cell = TT_CELL.FAIL;
      } else {
        if (!ids.has(n)) { ids.set(n, order.length); order.push(n); }
        cell = ids.get(n) & TT_CELL.NEXT;
        if (emit) cell |= TT_CELL.EMIT | ((sym & 0xff) << TT_CELL.SYM_SHIFT);
        if (isAccept(n)) cell |= TT_CELL.ACCEPT;
      }
      row[nib] = cell >>> 0;
    }
    cellsOf.push(row);
  }

  const nstates = order.length;
  const cells = new Uint32Array(nstates * 16);
  for (let s = 0; s < nstates; s++) for (let n = 0; n < 16; n++) cells[s * 16 + n] = cellsOf[s][n];
  return { nstates, cells };
}

/* Reference model of the kernel `transform` op: decode `bytes` (a Huffman
 * string) through the cells, exactly as pfw_step will. Returns { out, ok }
 * where ok is false on a FAIL cell or a non-accept final state. */
export function huffDecode(bytes, table = buildHuffman()) {
  const { cells } = table;
  const out = [];
  let state = 0;
  const step = (nib) => {
    const cell = cells[(state * 16 + nib) >>> 0];
    if (cell & TT_CELL.FAIL) return false;
    if (cell & TT_CELL.EMIT) out.push((cell >>> TT_CELL.SYM_SHIFT) & 0xff);
    state = cell & TT_CELL.NEXT;
    return true;
  };
  for (const byte of bytes) {
    if (!step((byte >> 4) & 0xf)) return { out: Uint8Array.from(out), ok: false };
    if (!step(byte & 0xf)) return { out: Uint8Array.from(out), ok: false };
  }
  // A clean end sits at an accept state (root, or on the all-ones padding path).
  return { out: Uint8Array.from(out), ok: acceptState(table, state) };
}

/* Whether `state` is a valid end state: root, or an all-ones padding node.
 * Derived from the cells: an accept state is one some transition marks ACCEPT
 * as its next, plus the root (state 0). */
let ACCEPT_SET = null;
function acceptState(table, state) {
  if (state === 0) return true;
  if (!ACCEPT_SET || ACCEPT_SET.table !== table) {
    const set = new Set([0]);
    for (const c of table.cells) if (c & TT_CELL.ACCEPT) set.add(c & TT_CELL.NEXT);
    ACCEPT_SET = { table, set };
  }
  return ACCEPT_SET.set.has(state);
}

/* The kernel reads the cells as a const array (bpf/include/huff_table.h) rather
 * than a map: a per-cell map lookup inside the decode loop blows the verifier's
 * jump budget. The header is generated, not hand-written — this is still a
 * decoding built from a spec, baked like the h2 static table. Regenerate with
 * `npm run gen:huff` (scripts/gen-huff.mjs) after editing the code table. The
 * writing is done there, not here: this module is bundled for isolates and
 * browsers, where there is no `node:fs` to import. */
export function headerText() {
  const { nstates, cells } = buildHuffman();
  const rows = [];
  for (let i = 0; i < cells.length; i += 8)
    rows.push("    " + [...cells.slice(i, i + 8)].map((c) => "0x" + c.toString(16).padStart(8, "0")).join(", ") + ",");
  return `/* Generated from src/huffman/table.js (RFC 7541 Appendix B). Do not edit
 * by hand; run \`npm run gen:huff\`. ${nstates} states, ${cells.length} cells.
 * Cell layout: next(0..8) EMIT(9) ACCEPT(10) FAIL(11) sym(16..23). */
#ifndef PFW_HUFF_TABLE_H
#define PFW_HUFF_TABLE_H

static const __u32 huff_cells[${cells.length}] = {
${rows.join("\n")}
};

#endif
`;
}
