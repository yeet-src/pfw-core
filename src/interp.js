/* A reference interpreter for the pfw ISA: pfw_step, window, ac_step, findb_step
 * and cmpstr_step from bpf/vm/match/scan.h, modelled line for line over the ops and
 * automaton the real assembler (src/asm.js) produces. The conformance tests in
 * this directory run programs through it and assert on the verdict, so a change
 * to the kernel interpreter that is not mirrored here (or vice versa) shows up as
 * a failing test. Pure host code — no kernel, no root.
 *
 *   machine({ asm, tables }) -> run(frame, payload, flow, opts) -> { verdict, rule, flow }
 *
 * `flow` carries what the kernel keeps per TCP flow — { ac, mask } plus the P3
 * ring { ring, ringHead, ringCount } — so a multi-packet test threads the
 * returned flow back in. Only the ops the tests exercise are modelled; an
 * unmodelled op throws rather than silently passing. */
import { LIMITS, NREGS, OP, REG } from "#/isa.js";

const SCAN_CAP = 2048, MAX_OPS = 8192, AC_MAX_FAIL = 16, RING_CAP = 16, U64 = (1n << 64n) - 1n;
const RL_SCALE = 1_000_000; /* OP_RATE fixed-point, mirrors RL_SCALE in pfw.h */
export const V = { NONE: 0, PASS: 1, DROP: 2, BAN: 3, RST: 4 };

/* OP_FHASH, as the kernel computes it (flow_hash in match/interp.h): the two
 * addresses folded to 32 bits, the ports and the protocol, through the murmur3
 * finaliser. Exported so a host can build a table the kernel will index the
 * same way. Addresses are u32 (IPv4, host order) or a 128-bit BigInt (IPv6). */
const fhMix = (h) => {
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h >>> 0;
};
export const addrFold = (a) => {
  if (typeof a !== "bigint") return Number(a) >>> 0;
  let h = 0n;
  for (let i = 0n; i < 4n; i++) h ^= (a >> (32n * i)) & 0xffffffffn;
  return Number(h);
};
export function flowHash({ saddr = 0, daddr = 0, sport = 0, dport = 0, proto = 6 } = {}) {
  let h = fhMix(addrFold(saddr));
  h = fhMix((h ^ addrFold(daddr)) >>> 0);
  h = fhMix((h ^ ((((sport & 0xffff) << 16) | (dport & 0xffff)) >>> 0)) >>> 0);
  return fhMix((h ^ (proto >>> 0)) >>> 0);
}

export function machine({ asm, tables, regex = null }) {
  const ops = asm.program.ops, pats = asm.program.pats;
  const goto_ = new Map(tables.edges), fail = new Map(tables.fails), accept = new Map(tables.accepts);
  /* nocase folds ASCII upper→lower; the automaton is built folded (ac.js), so
   * the input bytes must be folded too, exactly as the kernel's ac_step/cmpstr do. */
  const nocase = !!asm.program.nocase;
  const fold = (b) => (nocase && b >= 65 && b <= 90 ? b + 32 : b);

  return function run(frame, payload, flow, { proto = 6, dport = 80, sport = 0, saddr = 0, daddr = 0, set = [], hashset: hashArr = [], bloom: bloomArr = [], src6 = 0n, set6 = [], bucket = null, source = null, now = 0n, argv = [], shadow = false, knobs = [], knobStrs = [], cells = null, kv = null } = {}) {
    /* The key -> value map (`lookup`): a Map, or a plain object of entries. */
    const kvMap = new Map([...(kv instanceof Map ? kv : Object.entries(kv ?? {}))].map(([k, v]) => [BigInt(k) & U64, BigInt(v) & U64]));
    const hashset = new Set(hashArr.map((v) => BigInt(v) & 0xffffffffn));
    const bloom = new Set(bloomArr.map((v) => BigInt(v) & 0xffffffffn));
    const end = frame.length;
    const r = new Array(NREGS).fill(0n);
    r[REG.payload] = BigInt(payload); r[REG.end] = BigInt(end); r[REG.proto] = BigInt(proto);
    r[REG.dport] = BigInt(dport); r[REG.sport] = BigInt(sport); r[REG.cur] = BigInt(payload); r[REG.len] = BigInt(end > payload ? end - payload : 0);
    r[REG.saddr] = BigInt(saddr) & 0xffffffffn; /* IPv4 source, host order */
    r[REG.shadow] = shadow ? 1n : 0n; /* readable as %shadow */
    r[REG.m] = flow.mask;
    const emitted = []; /* OP_EMIT events: { id, nums } */
    const sampled = []; /* OP_SAMPLE copies of the frame: { tag, data, wireLen } */
    let dnat = null;    /* OP_DNAT: where the packet was steered, { ip, port } */
    const fargs = [], fstrs = [], consoleMsgs = []; /* OP_FARG numeric + OP_FARGS string buffers + collected console() messages */
    const hstack = new Array(64).fill(0n); /* the data stack (push/pop), %sp indexes it */
    const ring = flow.ring ? [...flow.ring] : new Array(RING_CAP).fill(0);
    let ringHead = flow.ringHead ?? 0, ringCount = flow.ringCount ?? 0;
    /* Per-flow scalars the program reads (mark, user_state, hits). Writes are
     * deferred like the kernel: sstore/mark take effect for the next packet, so
     * sload/flow read the entry values within this run. */
    const mark = flow.mark ?? 0;
    const userState = flow.userState ?? 0;
    let hits = flow.hits ?? 0, newState = userState, setMark = mark;
    /* The flow's registers (read-your-writes within a run, unlike the state) and
     * its byte and packet counts, which include the packet being judged. */
    const ureg = [0, 1, 2, 3].map((i) => BigInt(flow.ureg?.[i] ?? 0) & U64);
    const fbytes = BigInt(flow.bytes ?? 0) + BigInt(end > payload ? end - payload : 0), fpackets = BigInt(flow.packets ?? 0) + 1n;
    /* Per-SOURCE state (the `sources` map): src.state / src.count / src.rate and
     * the source ban. The caller threads the returned `source` back in to model
     * later packets from the same address, on any connection. */
    const srcState = source?.userState ?? 0;
    let srcHits = source?.hits ?? 0, srcNewState = srcState;
    const srcBucket = source ? (source.bucket ?? (source.bucket = {})) : null;
    let ac = flow.ac, pc = 0, zf = false, cf = false, ff = false, verdict = V.NONE, rule = 0;
    const mpos = new Array(64).fill(0);
    /* Reads clamp to R_END (the program may narrow it, e.g. `frame`), and never
     * past the actual buffer — as the kernel's window() bounds by st->r[R_END]. */
    const wend = () => Math.min(Number(r[REG.end]), end);
    const window = (off, want) => {
      const e = wend();
      if (off >= BigInt(e) || off > 0xffffn) return null;
      const o = Number(off);
      return frame.subarray(o, o + Math.min(want, e - o, SCAN_CAP));
    };
    const acStep = (raw) => {
      const b = fold(raw);
      let s = ac, k = 0;
      for (; k < AC_MAX_FAIL; k++) {
        const next = goto_.get(s * 256 + b);
        if (next) { s = next; break; }
        if (s === 0) break;
        s = fail.get(s) ?? 0;
      }
      if (k === AC_MAX_FAIL) s = 0;
      ac = s;
      return accept.get(s) ?? 0n;
    };
    for (let i = 0; i < MAX_OPS && !verdict && pc < ops.length; i++) {
      const { code, reg: rawReg, imm } = ops[pc];
      const reg = rawReg & (NREGS - 1); /* a register index, masked & (NREGS - 1) as the kernel does; ops that pack something else into reg read rawReg */
      let cur = r[REG.cur], next = pc + 1;
      const jump = (take) => {
        if (!take) return;
        if (imm <= BigInt(pc) || imm > BigInt(MAX_OPS)) verdict = V.PASS;
        else next = Number(imm);
      };
      switch (code) {
        case OP.MOV_RC: cur = r[reg]; break;
        case OP.MOV_CR: if (reg !== REG.cur) r[reg] = cur; break;
        case OP.ADD_I: cur = (cur + imm) & U64; break;
        case OP.SUB_I: cur = (cur - imm) & U64; break;
        case OP.ADD_R: cur = (cur + r[reg]) & U64; break;
        case OP.SUB_R: cur = (cur - r[reg]) & U64; break;
        case OP.AND_I: cur &= imm; break;
        case OP.OR_I: cur |= imm; break;
        case OP.SHL_I: cur = (cur << (imm & 63n)) & U64; break;
        case OP.SHR_I: cur = cur >> (imm & 63n); break;
        case OP.MUL_I: cur = (cur * imm) & U64; break;
        case OP.MUL_R: cur = (cur * r[reg]) & U64; break;
        case OP.MOD_I: if (imm) cur %= imm; else { cur = 0n; ff = true; } break; /* a zero divisor: 0 and a fault */
        case OP.MOD_R: if (r[reg]) cur %= r[reg]; else { cur = 0n; ff = true; } break;
        case OP.FHASH: cur = BigInt(flowHash({ saddr: src6 ? src6 : saddr, daddr, sport, dport, proto })); break;
        case OP.CMP_I: zf = cur === imm; cf = cur < imm; break;
        case OP.CIDR: {
          const net = imm & 0xffffffffn, prefix = Number((imm >> 32n) & 0xffn);
          const mask = prefix === 0 ? 0n : (prefix >= 32 ? 0xffffffffn : (0xffffffffn << BigInt(32 - prefix)) & 0xffffffffn);
          zf = ((cur & mask) === (net & mask)); cf = false;
          break;
        }
        case OP.CMP_R: zf = cur === r[reg]; cf = cur < r[reg]; break;
        case OP.TEST: zf = (r[REG.m] & imm) === 0n; cf = false; break;
        case OP.JMP: jump(true); break;
        case OP.JE: jump(zf); break;
        case OP.JNE: jump(!zf); break;
        case OP.JA: jump(!cf && !zf); break;
        case OP.JB: jump(cf); break;
        case OP.JAE: jump(!cf); break;
        case OP.JBE: jump(cf || zf); break;
        case OP.JF: if (ff) { ff = false; jump(true); } break;
        case OP.SCAN: {
          if (rawReg & 1) { ac = 0; r[REG.m] = 0n; }      // fresh scan (within): only this window counts
          const w = window(cur, Number(imm > 2048n ? 2048n : imm));
          let rs = 0;
          if (w) for (let k = 0; k < w.length; k++) {
            const acc = acStep(w[k]);                 // Aho-Corasick over literal patterns
            const fresh = acc & ~r[REG.m];
            r[REG.m] |= acc;
            for (let b = 0; b < 64; b++) if ((fresh >> BigInt(b)) & 1n) mpos[b] = Number(cur) + k + 1;
            if (regex) {                              // regex DFA over regex patterns, same window
              rs = regex.trans[rs][fold(w[k])];
              r[REG.m] |= regex.accept[rs];
            }
          }
          break;
        }
        case OP.MPOS: if (mpos[rawReg & 63]) cur = BigInt(mpos[rawReg & 63]); else ff = true; break;
        case OP.CMPSTR: {
          const p = pats[rawReg & 63];
          cf = false;
          if (!p || p.len === 0 || p.len > 64) { zf = false; break; } /* an empty slot just clears the flags */
          const w = window(cur, p.len);
          zf = !!w && w.length === p.len && p.bytes.every((b, k) => fold(w[k]) === fold(b)); // nocase folds both, as the kernel does
          break;
        }
        case OP.FINDB: {
          const w = window(cur, Number(imm > 2048n ? 2048n : imm));
          ff = true;
          const k = w ? w.indexOf(rawReg & 0xff) : -1;
          if (k >= 0) { cur = cur + BigInt(k); ff = false; }
          break;
        }
        case OP.LOAD: {
          const size = rawReg & 15, be = (rawReg & 16) !== 0;
          const off = (cur + imm) & U64; /* wraps, as the kernel's __u64 sum does */
          if (size !== 1 && size !== 2 && size !== 4 && size !== 8) { ff = true; break; }
          if (off > 0xffffn || off + BigInt(size) > BigInt(wend())) { ff = true; break; }
          const o = Number(off);
          let v = 0n;
          for (let k = 0; k < size; k++) v |= BigInt(frame[o + k]) << BigInt(8 * k); // little-endian
          if (be && size > 1) { let s = 0n; for (let k = 0; k < size; k++) s = (s << 8n) | ((v >> BigInt(8 * k)) & 0xffn); v = s; }
          cur = v;
          break;
        }
        case OP.SKIPB: {
          const cap = (imm === 0n || imm > 64n) ? 64 : Number(imm);
          const w = window(cur, cap);
          let count = 0;
          if (w) for (let k = 0; k < w.length; k++) { if (w[k] !== (rawReg & 0xff)) break; count = k + 1; }
          cur = cur + BigInt(count);
          break;
        }
        case OP.RPUSH: {
          ring[ringHead & (RING_CAP - 1)] = Number(cur & 0xffffffffn);
          ringHead = (ringHead + 1) & (RING_CAP - 1);
          if (ringCount < RING_CAP) ringCount++;
          break;
        }
        case OP.RGET: {
          const idx = Number(cur & 0xffffffffn);
          if (idx < ringCount) cur = BigInt(ring[(ringHead - 1 - idx) & (RING_CAP - 1)]);
          else { cur = 0n; ff = true; }
          break;
        }
        case OP.RLEN: cur = BigInt(ringCount); break;
        case OP.REDACT:
        case OP.REPLACE: {
          // Overwrite every match in [payload, end) in place, same length:
          // redact fills with imm's low byte, replace copies pattern imm.
          const repl = code === OP.REPLACE ? pats[Number(imm & 63n)] : null;
          const fillB = Number(imm & 0xffn);
          const end = Math.min(Number(r[REG.end]), frame.length);
          const start = Number(r[REG.payload]); /* whole payload, not cursor */
          if (rawReg & 0x8000) { // regex (fixed-length): DFA walk, overwrite [i+1-len, i] on accept of this bit
            const bit = BigInt(rawReg & 0x3fff), len = Number((imm >> 8n) & 0x7fn);
            if (regex && len > 0) {
              let s = 0;
              for (let i = start; i < end && i < start + SCAN_CAP; i++) {
                s = regex.trans[s][fold(frame[i])];
                if ((regex.accept[s] >> bit) & 1n) { const base = i + 1 - len; if (base >= start) for (let j = 0; j < len; j++) frame[base + j] = repl ? repl.bytes[j] : fillB; }
              }
            }
            break;
          }
          const p = pats[rawReg & 63];
          if (p && p.len > 0 && (!repl || repl.len === p.len)) {
            for (let o = start; o >= 0 && o + p.len <= end && o < start + 2048; o++) {
              let hit = true;
              for (let j = 0; j < p.len; j++) if (fold(frame[o + j]) !== fold(p.bytes[j])) { hit = false; break; }
              if (hit) { for (let j = 0; j < p.len; j++) frame[o + j] = repl ? repl.bytes[j] : fillB; o += p.len - 1; }
            }
          }
          break;
        }
        /* reg (sload/bump) or imm bit 32 (sstore) selects the scope: this flow, or
         * the source address. Source writes are deferred exactly like flow writes. */
        case OP.SLOAD: cur = BigInt(rawReg === 1 ? srcState : userState); break;
        case OP.SSTORE: if ((imm >> 32n) & 1n) srcNewState = Number(imm & 0xffffffffn); else newState = Number(imm & 0xffffffffn); break;
        case OP.BUMP:
          if (rawReg === 1) { srcHits = (srcHits + 1) >>> 0; cur = BigInt(srcHits); }
          else { hits = (hits + 1) >>> 0; cur = BigInt(hits); }
          break;
        case OP.FLOAD: { const which = rawReg & 7; cur = which === 4 ? fbytes : which === 5 ? fpackets : ureg[which & 3]; break; }
        case OP.FSTORE: ureg[rawReg & 3] = cur; break;
        case OP.FLOW: cur = BigInt(mark); break;
        case OP.MARK: setMark = rawReg; break;
        case OP.COUNT: rule = rawReg; break; // counter side effect; execution continues
        case OP.LOG: break;
        case OP.PASS: verdict = V.PASS; break;
        case OP.END: verdict = V.PASS; break;
        case OP.DROP: verdict = V.DROP; rule = rawReg & 63; break;
        case OP.BAN: verdict = V.BAN; rule = rawReg & 63; break;
        case OP.RST: verdict = V.RST; rule = rawReg & 63; break;
        case OP.DNAT: { /* the headers are the kernel's to rewrite; the host model records where the packet was sent */
          const t = rawReg & 1 ? cur : imm;
          if (!(rawReg & 1) || (t & 0xffffffffn)) dnat = { ip: Number(t & 0xffffffffn), port: Number((t >> 32n) & 0xffffn) };
          break;
        }
        case OP.LPM: zf = set.some((c) => (cur & c.mask) === (c.net & c.mask)); cf = false; break; /* src in the CIDR set */
        case OP.HASH: zf = hashset.has(cur & 0xffffffffn); cf = false; break; /* x in the exact hash set */
        case OP.BLOOM: zf = bloom.has(cur & 0xffffffffn); cf = false; break; /* x (probably) in the bloom set (modelled exact) */
        case OP.LPM6: zf = set6.some((c) => (src6 & c.mask) === (c.net & c.mask)); cf = false; break; /* IPv6 src in the CIDR set */
        case OP.ARG: { const idx = Number((imm >> 32n) & 0xffffn); cur = idx < argv.length ? BigInt(argv[idx]) & U64 : (imm & 0xffffffffn); break; } /* runtime arg or inline default */
        case OP.ARGC: cur = BigInt(argv.length); break; /* number of args the host set */
        case OP.KNOB: { const slot = Number(imm) & 31; cur = BigInt(knobs[slot] ?? 0) & U64; break; } /* live host-set control value */
        case OP.KVGET: { /* the value under key cur, or the default and a fault */
          if (kvMap.has(cur)) cur = kvMap.get(cur);
          else { cur = imm & U64; ff = true; }
          break;
        }
        case OP.TLOAD: { /* a host-loaded table cell; `cells` is the program's cell space: an array, or (index) -> value */
          const base = imm & 0xffffffffn, size = imm >> 32n;
          const at = (i) => (typeof cells === "function" ? cells(i) : cells?.[i]) ?? 0;
          if (cur < size) cur = BigInt(at(Number(base + cur))) & U64;
          else { cur = 0n; ff = true; }
          break;
        }
        case OP.KNOBHAS: { /* ZF = the host-set string knob occurs in the payload window */
          const needle = knobStrs[Number(imm) & 15];
          zf = false; cf = false;
          if (needle && needle.length) {
            const off = Number(r[REG.payload]), end = Math.min(Number(r[REG.end]), frame.length, off + 256);
            const nb = typeof needle === "string" ? Array.from(needle, (ch) => ch.charCodeAt(0) & 0xff) : needle;
            for (let i = off; i + nb.length <= end && !zf; i++) { let eq = true; for (let j = 0; j < nb.length; j++) if (frame[i + j] !== nb[j]) { eq = false; break; } if (eq) zf = true; }
          }
          break;
        }
        case OP.FARG: if (fargs.length < LIMITS.FARGS) fargs.push(cur); break; /* push a numeric format arg */
        case OP.FARGS: { /* capture a %s string: cur is a frame offset, up to imm/32 bytes */
          if (fstrs.length < 2) {
            const off = Number(cur), e2 = Math.min(Number(r[REG.end]), frame.length);
            const len = Math.max(0, Math.min(Number(imm), 256, e2 - off));
            let str = ""; for (let j = 0; j < len; j++) str += String.fromCharCode(frame[off + j]);
            fstrs.push(str);
          }
          break;
        }
        case OP.CONSOLE: consoleMsgs.push({ fmtid: Number(imm), nums: fargs.splice(0), strs: fstrs.splice(0) }); break; /* emit a console message */
        case OP.SAMPLE: { /* the frame from its first byte, as it is now, cut at imm and at the cap */
          const n = Math.min(Number(imm > BigInt(LIMITS.SAMPLE_CAP) ? BigInt(LIMITS.SAMPLE_CAP) : imm), frame.length);
          sampled.push({ tag: rawReg & 0xff, data: frame.slice(0, n), wireLen: frame.length });
          break;
        }
        case OP.EMIT: emitted.push({ id: Number(imm & 0xffffffffn), nums: fargs.splice(0) }); break; /* a typed event: the id and the numbers */
        case OP.PRINTK: fargs.splice(0); break; /* kernel-only: bpf_trace_printk to the trace pipe; host no-op (clears args) */
        case OP.PUSH: { const sp = Number(r[REG.sp]); if (sp < 64) { hstack[sp] = cur; r[REG.sp] = BigInt(sp + 1); } break; } /* push cur, sp++ */
        case OP.POP: { let sp = Number(r[REG.sp]); if (sp > 0) { sp--; cur = hstack[sp]; r[REG.sp] = BigInt(sp); } break; } /* sp--, cur = top */
        case OP.CALL: { const sp = Number(r[REG.sp]); if (sp < 64) { hstack[sp] = BigInt(next); r[REG.sp] = BigInt(sp + 1); next = Number(imm); } break; } /* push return pc, jump */
        case OP.RET: { let sp = Number(r[REG.sp]); if (sp > 0) { sp--; next = Number(hstack[sp]); r[REG.sp] = BigInt(sp); } break; } /* pop pc */
        case OP.REDIRECT: break; /* kernel-only: forwards the packet out an ifindex (XDP_REDIRECT); no effect on the host frame model */
        case OP.RATE: { /* token bucket; ZF = over the limit. The caller passes a persistent `bucket` ({tokens,ts}) and `now` to model state across packets; absent one, treat as allowed. */
          const packed = rawReg & 2 ? cur : imm; /* reg bit 1: rate and burst were computed, and are in the cursor */
          const rate = Number(packed & 0xffffffffn), cap = Number((packed >> 32n) & 0xffffffffn) * RL_SCALE;
          const b = rawReg & 1 ? srcBucket : bucket, nowN = Number(now);
          if (!b) { zf = false; cf = false; break; }
          let tokens;
          if (b.ts === undefined) tokens = cap; /* unseeded: full bucket (kernel uses rl_ts==0, where ktime is never 0) */
          else { const refill = Math.floor((Math.max(0, nowN - b.ts) * rate) / 1000); tokens = Math.min(cap, (b.tokens ?? 0) + refill); }
          b.ts = nowN;
          if (tokens >= RL_SCALE) { b.tokens = tokens - RL_SCALE; zf = false; }
          else { b.tokens = tokens; zf = true; }
          cf = false;
          break;
        }
        default: throw new Error("op not modelled: " + code);
      }
      r[REG.cur] = cur;
      pc = next;
    }
    /* Shadow mode: an enforcement verdict is reported as PASS (the packet would
     * be let through) with the would-be verdict in `would`, mirroring the kernel. */
    const vfinal = verdict || V.PASS;
    const isEnforce = vfinal === V.DROP || vfinal === V.BAN || vfinal === V.RST;
    return {
      verdict: shadow && isEnforce ? V.PASS : vfinal, would: shadow && isEnforce ? vfinal : undefined, rule,
      flow: { ac, mask: r[REG.m], ring, ringHead, ringCount, mark: setMark, userState: newState, hits, ureg, bytes: fbytes, packets: fpackets },
      source: { userState: srcNewState, hits: srcHits, bucket: srcBucket ?? {}, banned: (source?.banned ?? false) || (vfinal === V.BAN && !shadow) },
      consoleMsgs, emitted, dnat, sampled,
    };
  };
}
