/* HPACK Huffman table (P2) built by src/huffman.js, validated against RFC 7541's
 * worked examples and by a full encode->decode round-trip of all 256 bytes. This
 * is what makes the baked bpf/include/huff_table.h trustworthy. */
import { buildHuffman, huffDecode, codes } from "#/huffman";

const T = buildHuffman();
const fromHex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const toStr = (u8) => String.fromCharCode(...u8);
const dec = (h) => { const r = huffDecode(fromHex(h), T); return { s: toStr(r.out), ok: r.ok }; };

yeet.test("256-state table built", () => {
  if (T.nstates !== 256) throw new Error("states=" + T.nstates);
});

yeet.test("RFC 7541 worked examples decode", () => {
  const vectors = [
    ["f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"], ["a8eb10649cbf", "no-cache"],
    ["25a849e95ba97d7f", "custom-key"], ["25a849e95bb8e8b4bf", "custom-value"],
    ["6402", "302"], ["aec3771a4b", "private"],
    ["d07abe941054d444a8200595040b8166e082a62d1bff", "Mon, 21 Oct 2013 20:13:21 GMT"],
    ["9d29ad171863c78f0b97c8e9ae82ae43d3", "https://www.example.com"],
    ["640eff", "307"], ["9bd9ab", "gzip"],
  ];
  for (const [h, w] of vectors) {
    const { s, ok } = dec(h);
    if (!ok || s !== w) throw new Error(`${h} -> ${JSON.stringify(s)} (want ${JSON.stringify(w)})`);
  }
});

yeet.test("every byte round-trips through encode->decode", () => {
  const byId = new Map(codes().map((c) => [c.sym, c]));
  const encode = (bytes) => {
    let acc = 0n, nbits = 0n;
    const out = [];
    for (const b of bytes) {
      const { code, bits } = byId.get(b);
      acc = (acc << BigInt(bits)) | BigInt(code); nbits += BigInt(bits);
      while (nbits >= 8n) { nbits -= 8n; out.push(Number((acc >> nbits) & 0xffn)); }
    }
    if (nbits > 0n) { const pad = 8n - nbits; out.push(Number(((acc << pad) | ((1n << pad) - 1n)) & 0xffn)); }
    return Uint8Array.from(out);
  };
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  const rt = huffDecode(encode(all), T);
  if (!rt.ok || rt.out.length !== 256 || !all.every((b, i) => rt.out[i] === b)) throw new Error("all-256 round-trip");
  for (let b = 0; b < 256; b++) {
    const d = huffDecode(encode(Uint8Array.of(b)), T);
    if (!d.ok || d.out.length !== 1 || d.out[0] !== b) throw new Error("single byte " + b);
  }
});
