/* Kernel redirect test: prove OP_REDIRECT (bpf_redirect -> XDP_REDIRECT) actually
 * re-injects the packet by the given ifindex, on real loopback traffic.
 *
 * A single host with no root can't build a veth pair, so we can't show true
 * cross-interface steering. We CAN isolate the redirect machinery on `lo`:
 *
 *   filter { if (proto != 17) return pass;
 *            if (dport != A) return pass;
 *            dnat("127.0.0.1", B);   // re-injected copy has dport B, so it
 *            redirect(IFX);          // passes on the second lap (no loop)
 *            return drop("redir"); } // DROP is the fallback the packet only
 *                                    // survives via a working redirect
 *
 * The verdict is DROP, so the ONLY way a datagram reaches the server on
 * 127.0.0.1:B is if bpf_redirect(IFX) overrode the drop and re-injected it.
 *   - IFX = 1 (lo): redirected onto lo, re-enters with dport B -> pass ->
 *     delivered. Server receives.  (redirect works, and overrides drop)
 *   - IFX = 9999 (invalid): bpf_redirect to a nonexistent ifindex fails in
 *     xdp_do_redirect and the packet is dropped. Server receives nothing.
 *     (the ifindex is honored; delivery in case 1 was not the pass path)
 *
 * UDP (one-way datagram) so there's no TCP return path needing reverse NAT.
 * Needs yeetd + loopback; `npm run test:redirect` (node). */
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("../..", import.meta.url).pathname;
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

/* Bind a UDP server at 127.0.0.1:dstPort, send `msg` to 127.0.0.1:sendPort,
 * resolve with what the server received (or "" after a timeout). */
function udpDeliver(sendPort, dstPort, msg) {
  return new Promise((resolve) => {
    const srv = dgram.createSocket("udp4");
    let got = "";
    srv.on("message", (m) => { got = m.toString("latin1"); });
    srv.on("error", () => {});
    srv.bind(dstPort, "127.0.0.1", () => {
      const cli = dgram.createSocket("udp4");
      cli.send(Buffer.from(msg), sendPort, "127.0.0.1", () => {});
      setTimeout(() => { try { cli.close(); } catch {} try { srv.close(); } catch {} resolve(got); }, 700);
    });
  });
}

const A = 59621, B = 59622;
const prog = (ifx) =>
  `filter { if (proto != 17) return pass; if (dport != ${A}) return pass; dnat("127.0.0.1", ${B}); redirect(${ifx}); return drop("redir"); }`;

const CASES = [
  { name: "redirect(lo) overrides drop -> delivered to B", ifx: 1, want: true },
  { name: "redirect(9999 invalid) -> dropped, nothing at B", ifx: 9999, want: false },
];

let fail = 0, n = 0;
console.log("kernel redirect — bpf_redirect(ifindex) re-injection on loopback\n");
for (const c of CASES) {
  await withProgram(prog(c.ifx), async () => {
    await sleep(300);
    const got = await udpDeliver(A, B, "redir-" + c.ifx);
    const delivered = got === "redir-" + c.ifx;
    n++;
    const ok = delivered === c.want;
    if (!ok) fail++;
    console.log(`  ${ok ? "ok  " : "FAIL"} ${c.name}: delivered=${delivered}${ok ? "" : ` want ${c.want}`}`);
  });
}
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
