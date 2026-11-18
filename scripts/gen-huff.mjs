/* Regenerate bpf/include/huff_table.h from the RFC 7541 code table in
 * src/huffman/table.js. Run after editing that table:
 *
 *   npm run gen:huff      (or: make gen-huff)
 *
 * This lives outside src/huffman on purpose. The library is bundled for
 * runtimes with no filesystem, and a bundler resolves every import
 * specifier it can see, a guarded `await import("node:fs")` included.
 */
import { writeFileSync } from "node:fs";
import { headerText } from "#/huffman";

const path = new URL("../bpf/include/huff_table.h", import.meta.url).pathname;
writeFileSync(path, headerText());
console.log(`wrote ${path}`);
