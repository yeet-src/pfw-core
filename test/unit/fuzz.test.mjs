/* Property fuzzer: assemble thousands of random (but valid) programs and run
 * each over random frames / flow state, asserting the interpreter's invariants —
 * it never throws, always returns a real verdict, and is deterministic. With one
 * reference implementation there is no differential oracle on the host, so these
 * are properties, not golden outputs; they catch crashes, non-determinism and
 * out-of-range results across the whole op space, which the fixed tests can't. */
import { assemble } from "#/asm.js";
import { build } from "#/ac.js";
import { machine, V } from "#/interp.js";

/* A small LCG so a failure is reproducible from its seed. */
function rng(seed) {
  let s = seed >>> 0;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 0x100000000; };
}
const pick = (r, xs) => xs[Math.floor(r() * xs.length)];
const int = (r, n) => Math.floor(r() * n);

/* Instructions that are always valid on their own (no labels, no pattern refs):
 * the data/arith/load/flow-state/cidr ops. Jumps and patterns are added as a
 * bounded, always-forward block below. */
function randInsn(r) {
  const reg = () => `%s${int(r, 8)}`;
  switch (int(r, 14)) {
    case 0: return `        and     $${int(r, 256)}, %cur`;
    case 1: return `        add     $${int(r, 1000)}, %cur`;
    case 2: return `        sub     $${int(r, 1000)}, %cur`;
    case 3: return `        or      $${int(r, 256)}, %cur`;
    case 4: return `        shl     $${int(r, 16)}, %cur`;
    case 5: return `        shr     $${int(r, 16)}, %cur`;
    case 6: return `        mov     ${reg()}, %cur`;
    case 7: return `        mov     %cur, ${reg()}`;
    case 8: return `        cmp     $${int(r, 1000)}, %cur`;
    case 9: return `        movb    ${int(r, 40)}(%cur), %cur`;
    case 10: return `        movbew  ${int(r, 40)}(%cur), %cur`;
    case 11: return `        sload   %cur`;
    case 12: return `        bump    %cur`;
    default: return `        cidr    ${int(r, 256)}.${int(r, 256)}.${int(r, 256)}.0/${int(r, 33)}`;
  }
}

/* A whole program: some straight-line insns, an optional forward branch skipping
 * a drop, a scan+test on a planted pattern, then a random verdict. Always valid:
 * the only label is forward, the only pattern is declared. */
function randProgram(r) {
  const body = [];
  for (let k = int(r, 12); k > 0; k--) body.push(randInsn(r));
  if (r() < 0.5) {
    body.push(`        cmp     $${int(r, 500)}, %cur`);
    body.push(`        ${pick(r, ["je", "jne", "jb", "jae", "ja", "jbe"])}      skip`);
    body.push(`        drop    $1`);
    body.push(` skip:   mov     %payload, %cur`);
  }
  if (r() < 0.6) {
    body.push(`        mov     %payload, %cur`);
    body.push(`        scan    $${1 + int(r, 64)}, (%cur)`);
    body.push(`        test    $bot, %m`);
    body.push(`        je      out`);
    body.push(`        rst     $2, $0`);
  }
  const verdict = pick(r, ["pass", "drop    $3", "ban     $1, $5", "rst     $1, $0"]);
  return `.pat    bot, "GPTBot"\n${body.join("\n")}\n out:   ${verdict}`;
}

function randFrame(r) {
  const n = 1 + int(r, 80);
  const f = new Uint8Array(n);
  for (let i = 0; i < n; i++) f[i] = int(r, 256);
  if (r() < 0.3) { const s = "GPTBot"; for (let i = 0; i < 6 && i < n; i++) f[i] = s.charCodeAt(i); } // plant a match sometimes
  return f;
}
const randFlow = (r) => ({ ac: 0, mask: 0n, userState: int(r, 100), hits: int(r, 10), mark: int(r, 32) });
const randOpts = (r) => ({ proto: pick(r, [6, 17, 1]), dport: int(r, 65536), saddr: int(r, 0xffffffff) >>> 0 });

const N = Number(yeet.args?.n ?? 4000);

yeet.test(`${N} random programs: no throw, real verdict, deterministic`, () => {
  const r = rng(0xC0FFEE);
  for (let i = 0; i < N; i++) {
    const seed = (0xC0FFEE + i) >>> 0;
    const src = randProgram(r);
    const asm = assemble(src);
    if (!asm.ok) throw new Error(`seed ${seed}: generated invalid asm: ${JSON.stringify(asm.errors)}\n${src}`);
    const run = machine({ asm, tables: build(asm.patterns, asm.nocase) });
    const frame = randFrame(r), flow = randFlow(r), opts = randOpts(r);
    let a, b;
    try {
      a = run(frame, 0, { ...flow }, { ...opts });
      b = run(frame, 0, { ...flow }, { ...opts });
    } catch (e) {
      throw new Error(`seed ${seed}: interpreter threw: ${e.message}\n${src}`);
    }
    if (![V.PASS, V.DROP, V.BAN, V.RST].includes(a.verdict))
      throw new Error(`seed ${seed}: bad verdict ${a.verdict}\n${src}`);
    if (a.verdict !== b.verdict || a.rule !== b.rule)
      throw new Error(`seed ${seed}: non-deterministic (${a.verdict}/${a.rule} vs ${b.verdict}/${b.rule})\n${src}`);
    // feeding the returned flow back in must also be safe (multi-packet)
    try { run(randFrame(r), 0, a.flow, { ...opts }); } catch (e) {
      throw new Error(`seed ${seed}: threw on carried flow: ${e.message}`);
    }
  }
});
