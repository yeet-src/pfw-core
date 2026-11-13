/* Example pfw-C programs, one per VM feature. Importable (so the test suite
 * compiles them without file I/O) and a tour of the language. */
export const examples = {
  crawlers: `// Reset AI crawlers on :80 by user-agent, case-insensitively.
nocase;
pattern gptbot = "GPTBot", claudebot = "ClaudeBot", bytespider = "Bytespider";
filter {
  if (dport != 80) return pass;
  if (scan(payload, 1460) & (gptbot | claudebot | bytespider)) return rst("crawler", 60);
  return pass;
}`,

  cidr: `// Source-address targeting (P5): allow an internal range, drop a blocklist.
filter {
  if (proto != 6) return pass;
  if (src in "10.0.0.0/8") return pass;
  if (src in "203.0.113.0/24") return drop("blocklist");
  return pass;
}`,

  huffman: `// HPACK-Huffman decode (P2): match a bot in the decoded header stream.
decode huffman 8080;
pattern bot = "GPTBot";
filter {
  if (scan(payload, 2048) & bot) return rst("huff_bot", 0);
  return pass;
}`,

  frames: `// Walk length-prefixed records (P4): only scan HTTP/2 HEADERS frames.
pattern bot = "GPTBot";
filter {
  if (proto != 6) return pass;
  frame (len = be24 @ 0, type = u8 @ 3, head = 9) up to 8 {
    if (frame.type == 1) {
      if (scan(frame.data, 1024) & bot) return rst("h2_bot", 0);
    }
  }
  return pass;
}`,

  ring: `// Per-flow ring (P3): reset a connection once it sends too many segments.
reassemble 8080;
filter {
  if (len == 0) return pass;
  ring.push(len);
  if (ring.len >= 8) return rst("too_many_segments", 0);
  return pass;
}`,
};
