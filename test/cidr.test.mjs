/* CIDR op (P5): assemble a `cidr` rule and run it through the reference
 * interpreter over a spread of source addresses, including the mask boundaries. */
import { assemble } from "#/asm.js";
import { build } from "#/ac.js";
import { machine, V } from "#/interp.js";

const ip = (s) => s.split(".").reduce((a, o) => ((a << 8) | Number(o)) >>> 0, 0) >>> 0;

const inCidr = (cidr, addr) => {
  const asm = assemble(`        mov     %saddr, %cur
        cidr    ${cidr}
        je      hit
        pass
hit:    rst     $1, $0`);
  if (!asm.ok) throw new Error(cidr + ": " + JSON.stringify(asm.errors));
  const run = machine({ asm, tables: build(asm.patterns, asm.nocase) });
  return run(new Uint8Array(40), 0, { ac: 0, mask: 0n }, { saddr: ip(addr), proto: 6, dport: 8080 }).verdict === V.RST;
};

const groups = {
  "/8": [["10.0.0.0/8", "10.0.0.1", 1], ["10.0.0.0/8", "10.255.255.255", 1], ["10.0.0.0/8", "11.0.0.0", 0], ["10.0.0.0/8", "9.255.255.255", 0], ["10.0.0.0/8", "127.0.0.1", 0]],
  loopback: [["127.0.0.0/8", "127.0.0.1", 1], ["127.0.0.0/8", "128.0.0.1", 0]],
  "/24": [["192.168.1.0/24", "192.168.1.0", 1], ["192.168.1.0/24", "192.168.1.255", 1], ["192.168.1.0/24", "192.168.2.0", 0], ["192.168.1.0/24", "192.168.0.255", 0]],
  "/32 exact": [["8.8.8.8/32", "8.8.8.8", 1], ["8.8.8.8/32", "8.8.8.9", 0]],
  "/0 any": [["0.0.0.0/0", "0.0.0.0", 1], ["0.0.0.0/0", "255.255.255.255", 1], ["0.0.0.0/0", "123.45.67.89", 1]],
  "/31 edge": [["10.0.0.0/31", "10.0.0.1", 1], ["10.0.0.0/31", "10.0.0.2", 0]],
};

for (const [name, cases] of Object.entries(groups)) {
  yeet.test(`cidr ${name}`, () => {
    for (const [cidr, addr, want] of cases)
      if (inCidr(cidr, addr) !== !!want) throw new Error(`${addr} in ${cidr}: want ${!!want}`);
  });
}
