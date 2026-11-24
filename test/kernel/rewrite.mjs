/* Kernel rewrite test: load a redact/replace program, send a payload over
 * loopback through the XDP hook, and assert the SERVER RECEIVES the rewritten
 * bytes. This proves the whole wire path: the rewrite happened in the kernel AND
 * the L4 checksum was fixed (a wrong checksum makes the TCP stack drop the packet,
 * so the server would receive nothing). Needs yeetd + loopback; `npm run
 * test:rewrite` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59597;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

/* Hold `source` applied on lo, run fn(), tear down. */
async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"], { cwd: ROOT });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(400); }
}

/* Send `payload` to a local server; resolve with the bytes the server received. */
function roundtrip(payload) {
  return new Promise((resolve, reject) => {
    let got = Buffer.alloc(0);
    const server = net.createServer((s) => {
      s.on("data", (d) => { got = Buffer.concat([got, d]); });
      s.on("error", () => {});
    });
    server.on("error", reject);
    server.listen(PORT, "127.0.0.1", () => {
      const sock = net.connect(PORT, "127.0.0.1");
      sock.on("connect", () => sock.write(Buffer.from(payload)));
      sock.on("error", () => {});
      setTimeout(() => { try { sock.destroy(); } catch {} server.close(); resolve(got.toString("latin1")); }, 700);
    });
  });
}

const CASES = [
  { name: "redact fills every match", kind: "redact",
    source: `pattern tok = "secret";\nfilter { if (dport != ${PORT}) decide pass; redact(tok); decide pass; }`,
    send: "a secret b secret c", want: "a ****** b ****** c" },
  { name: "redact leaves non-matches", kind: "redact",
    source: `pattern tok = "secret";\nfilter { if (dport != ${PORT}) decide pass; redact(tok); decide pass; }`,
    send: "nothing to see here", want: "nothing to see here" },
  { name: "replace swaps same-length", kind: "replace",
    source: `pattern bot = "GPTBot";\nfilter { if (dport != ${PORT}) decide pass; replace(bot, "NOTBOT"); decide pass; }`,
    send: "UA: GPTBot and GPTBot!", want: "UA: NOTBOT and NOTBOT!" },
  { name: "nocase redact matches any case", kind: "redact",
    source: `nocase;\npattern tok = "secret";\nfilter { if (dport != ${PORT}) decide pass; redact(tok); decide pass; }`,
    send: "X SeCrEt Y", want: "X ****** Y" },
  // Ten redactions on one packet: past the four a packet could once carry,
  // where the fifth and later were silently left on the wire.
  { name: "ten redactions on one packet", kind: "redact",
    source: `${Array.from({ length: 10 }, (_, i) => `pattern t${i} = "key${i}=";`).join(" ")}\nfilter { if (dport != ${PORT}) decide pass; ${Array.from({ length: 10 }, (_, i) => `redact(t${i});`).join(" ")} decide pass; }`,
    send: Array.from({ length: 10 }, (_, i) => `key${i}=v`).join(" "), want: Array.from({ length: 10 }, () => "*****v").join(" ") },
];

let fail = 0, n = 0;
console.log(`kernel rewrite — redact/replace on the wire, :${PORT}\n`);
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
