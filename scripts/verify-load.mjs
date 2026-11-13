/* Load bin/app.bpf.o through yeetd and attach every program, so this kernel's
 * verifier judges the whole object (the local counterpart to `make veristat`,
 * which needs root). Prints OK and detaches, or the verifier error. Build first
 * with `make bpf`.
 *
 *   yeet run scripts/verify-load.mjs [--iface N]
 */
import { BpfObject } from "yeet:bpf";

const argv = yeet.args ?? {};
const iface = Number(argv.iface ?? 1);
const root = `${import.meta.dirname}/..`;

try {
  const control = await new BpfObject({ exe: `${root}/bin/app.bpf.o`, base: root })
    .bind("events", { kind: "ringbuf", btf_struct: "pfw_event" })
    .bind("programs", { kind: "array" })
    .bind("ac_goto", { kind: "array" })
    .bind("ac_fail", { kind: "array" })
    .bind("ac_accept", { kind: "array" })
    .bind("counters", { kind: "percpu_array" })
    .bind("decide_hist", { kind: "percpu_array" })
    .bind("flows", { kind: "lru_hash" })
    .bind("app.bss", { kind: "data" })
    .bind("decode_jmp", { kind: "prog_array" })
    .attach("pfw_decode", { kind: "prog_array", map: "decode_jmp", index: 0 })
    .attach("pfw_match", { kind: "prog_array", map: "decode_jmp", index: 1 })
    .attach("pfw_resolve", { kind: "prog_array", map: "decode_jmp", index: 2 })
    .attach("pfw_huff", { kind: "prog_array", map: "decode_jmp", index: 3 })
    .attach("pfw_xdp", { kind: "xdp", ifindex: [iface] })
    .start();
  console.log(`VERIFIER OK: every program loaded and attached (ifindex ${iface})`);
  await control.stop();
  console.log("detached");
} catch (e) {
  console.log("VERIFIER REJECTED or load failed:\n" + (e?.message ?? e));
  yeet.exit(1);
}
