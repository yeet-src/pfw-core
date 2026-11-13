/* General (loadable) transform (P2): the tables built by transform.js decode
 * correctly through huffDecode (the same model the kernel's pfw_transform
 * mirrors), the name→id registry is consistent with what the host would load
 * into tt_cells, and a pfw-C `decode <table>` program compiles to the right
 * program fields. The kernel's acceptance of the loaded table is proven
 * separately by scripts/verify-load.mjs (the verifier can't run in this sandbox). */
import { huffDecode } from "#/huffman.js";
import { buildByteMap, TRANSFORM_TABLES, transformCells, TT_CELLS } from "#/transform.js";
import { compile } from "#/clang.js";
import { DECODE } from "#/isa.js";

const enc = new TextEncoder();
const toStr = (u8) => String.fromCharCode(...u8);

yeet.test("byte-map table: a +1 shift is decoded away", () => {
  const T = buildByteMap((b) => (b - 1) & 0xff);
  const plain = "GPTBot";
  const shifted = Uint8Array.from(enc.encode(plain), (b) => (b + 1) & 0xff); // what's on the wire
  const r = huffDecode(shifted, T);
  if (!r.ok || toStr(r.out) !== plain) throw new Error(`decoded ${JSON.stringify(toStr(r.out))}`);
});

yeet.test("byte-map table: rot13 round-trips", () => {
  const rot13 = (b) => (b >= 65 && b <= 90) ? 65 + ((b - 65 + 13) % 26)
    : (b >= 97 && b <= 122) ? 97 + ((b - 97 + 13) % 26) : b;
  const T = buildByteMap(rot13);
  const r = huffDecode(Uint8Array.from(enc.encode("uryyb")), T); // rot13("hello")
  if (!r.ok || toStr(r.out) !== "hello") throw new Error(`decoded ${JSON.stringify(toStr(r.out))}`);
});

yeet.test("loadable huffman twin matches the real codes", () => {
  // The registry's `huffman` entry is buildHuffman(); decode an RFC vector.
  const T = TRANSFORM_TABLES.huffman.build();
  const bytes = Uint8Array.from("f1e3c2e5f23a6ba0ab90f4ff".match(/../g).map((h) => parseInt(h, 16)));
  const r = huffDecode(bytes, T);
  if (!r.ok || toStr(r.out) !== "www.example.com") throw new Error(`decoded ${JSON.stringify(toStr(r.out))}`);
});

yeet.test("transformCells keys fall in each table's id window", () => {
  const pairs = transformCells();
  if (pairs.length === 0) throw new Error("no cells");
  const ids = Object.values(TRANSFORM_TABLES).map((t) => t.id);
  for (const [k] of pairs) {
    const id = Math.floor(k / TT_CELLS);
    if (!ids.includes(id)) throw new Error(`cell key ${k} -> id ${id} not in registry`);
  }
});

yeet.test("pfw-C `decode <table>` compiles to DECODE_TRANSFORM + the table id", () => {
  const c = compile(`
    decode rot13 8080;
    pattern bot = "GPTBot";
    filter {
      if (scan(payload, 2048) & bot) return rst("bot", 0);
      return pass;
    }`);
  if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors));
  if (c.program.decode !== DECODE.transform) throw new Error("decode=" + c.program.decode);
  if (c.program.transform_table !== TRANSFORM_TABLES.rot13.id) throw new Error("table=" + c.program.transform_table);
  if (c.program.reasm !== 1) throw new Error("decode must imply reasm");
});
