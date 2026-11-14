/* Loadable transform tables (the general P2 transform). A table is the same
 * nibble state machine the Huffman decoder uses (see huffman.js for the cell
 * layout), but built here from a spec and LOADED into the kernel's tt_cells map
 * rather than baked — so a new decoding is data, no kernel change. The kernel's
 * pfw_transform stage runs tt_cells[transform_table], picked per program.
 *
 * Two kinds of table build here:
 *   buildByteMap(fn)   — a per-byte rewrite (an obfuscation to see through, a
 *                        normalization). Each input byte b emits fn(b).
 *   buildPrefix(codes) — a prefix code (Huffman-shaped); re-exported from
 *                        huffman.js's builder for completeness.
 *
 * huffDecode() in huffman.js runs ANY of these cell tables, so it doubles as the
 * reference model for every loaded table. */
import { TT_CELL, buildHuffman } from "#/huffman";

const TT_STATES = 256;
export const TT_CELLS = TT_STATES * 16;

/* A byte→byte rewrite as a nibble machine: root -(high nibble h)-> state 1+h
 * (mid-byte), then -(low nibble l)-> emit fn((h<<4)|l) and return to root. 17
 * states; no fail (every byte maps). */
export function buildByteMap(fn) {
  const cells = new Uint32Array(TT_CELLS);
  for (let h = 0; h < 16; h++) cells[0 * 16 + h] = (1 + h) & TT_CELL.NEXT; // mid-byte, not accept
  for (let h = 0; h < 16; h++) {
    const s = 1 + h;
    for (let l = 0; l < 16; l++) {
      const out = fn((h << 4) | l) & 0xff;
      cells[s * 16 + l] = (0 & TT_CELL.NEXT) | TT_CELL.EMIT | TT_CELL.ACCEPT | (out << TT_CELL.SYM_SHIFT);
    }
  }
  return { nstates: 17, cells };
}

const rot13 = (b) => {
  if (b >= 65 && b <= 90) return 65 + ((b - 65 + 13) % 26);
  if (b >= 97 && b <= 122) return 97 + ((b - 97 + 13) % 26);
  return b;
};

/* The loadable tables, by name → id. The host loads their cells into tt_cells
 * (see transformCells); a program selects one with `decode <name>` (pfw-C) which
 * sets pfw_prog.transform_table. `huffman` here is the loadable twin of the
 * baked table — proof the loadable path handles the real thing. */
export const TRANSFORM_TABLES = {
  unshift1: { id: 0, build: () => buildByteMap((b) => (b - 1) & 0xff) }, // undo a +1 byte shift
  rot13: { id: 1, build: () => buildByteMap(rot13) },
  huffman: { id: 2, build: () => buildHuffman() },
};

/* Flat [key, value] pairs for the tt_cells array map: key = id*TT_CELLS + cell.
 * The consumer (the firewall's loader) writes these into the map once. */
export function transformCells() {
  const out = [];
  for (const { id, build } of Object.values(TRANSFORM_TABLES)) {
    const { cells } = build();
    for (let i = 0; i < cells.length && i < TT_CELLS; i++) if (cells[i]) out.push([id * TT_CELLS + i, cells[i] >>> 0]);
  }
  return out;
}
