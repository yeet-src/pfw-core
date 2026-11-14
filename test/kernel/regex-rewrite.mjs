/* Kernel regex rewrite: redact / replace a REGEX match on the wire (not just a
 * literal). Only fixed-length regexes are rewritable, so the match end fixes the
 * span — the kernel walks the regex DFA in the rewrite stage and overwrites
 * [end+1-len, end] in place, fixing the L4 checksum. Proves structured-PII
 * scrubbing (SSN, dashed card number) at XDP. Needs yeetd + loopback;
 * `npm run test:regex-rewrite` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59671;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 120 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(400); }
}

function roundtrip(payload) {
  return new Promise((resolve, reject) => {
    let got = Buffer.alloc(0);
    const server = net.createServer((s) => { s.on("data", (d) => { got = Buffer.concat([got, d]); }); s.on("error", () => {}); });
    server.on("error", reject);
    server.listen(PORT, "127.0.0.1", () => {
      const sock = net.connect(PORT, "127.0.0.1");
      sock.on("connect", () => sock.write(Buffer.from(payload)));
      sock.on("error", () => {});
      setTimeout(() => { try { sock.destroy(); } catch {} server.close(); resolve(got.toString("latin1")); }, 700);
    });
  });
}

const guard = `if (dport != ${PORT}) decide pass;`;
const CASES = [
  { name: "redact SSN (regex, 11 bytes)",
    source: String.raw`regex ssn = "\d{3}-\d{2}-\d{4}";` + `\nfilter { ${guard} redact(ssn); decide pass; }`,
    send: "ssn 123-45-6789 and 987-65-4321 x", want: "ssn *********** and *********** x" },
  { name: "replace card (regex, 19 bytes) with same-length mask",
    source: String.raw`regex card = "\d{4}-\d{4}-\d{4}-\d{4}";` + `\nfilter { ${guard} replace(card, "XXXX-XXXX-XXXX-XXXX"); decide pass; }`,
    send: "pan 4111-1111-1111-1111 ok", want: "pan XXXX-XXXX-XXXX-XXXX ok" },
  { name: "regex redact leaves non-matches",
    source: String.raw`regex ssn = "\d{3}-\d{2}-\d{4}";` + `\nfilter { ${guard} redact(ssn); decide pass; }`,
    send: "no pii here 12-34-5", want: "no pii here 12-34-5" },
];

let fail = 0, n = 0;
console.log(`kernel regex rewrite — redact/replace a regex match on the wire, :${PORT}\n`);
for (const c of CASES) {
  await withProgram(c.source, async () => {
    await sleep(300);
    const got = await roundtrip(c.send);
    n++;
    const ok = got === c.want;
    if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} ${c.name}: got ${JSON.stringify(got)}${ok ? "" : ` want ${JSON.stringify(c.want)}`}`);
  });
}
console.log(`\n${n - fail}/${n} rewrote correctly`);
process.exit(fail ? 1 : 0);
