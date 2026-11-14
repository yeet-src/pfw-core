# 1. Lexical structure

**Comments.** `// line` to end of line, and `/* block */` (non-nested).

**Identifiers.** `[A-Za-z_][A-Za-z0-9_]*`. Keywords (`if`, `filter`, `decide`, …)
are identifiers matched positionally — there is no separate reserved-word class,
but using a keyword as a name will not parse where the keyword is expected.

**Number literals.** Decimal (`80`, `1460`) or hex (`0x1f`, `0X80`). Integers
only; every value is a 64-bit unsigned quantity.

**Character literals.** `'c'` — one byte. Escapes: `\n` `\r` `\t` `\0` `\\` `\'`
`\"` and `\xHH` (two hex digits). A char literal is just its byte value.

**String literals.** `"..."`, used for patterns, CIDRs, rule names, and
format/IP arguments. In a *pattern* the bytes are unescaped with `\n \r \t \0 \\
\' \"` and `\xHH`; any other `\c` becomes the literal `c`.

**Byte-list patterns.** `{ 0xac, 0xed, 0x00, 0x05 }` — a comma-separated list of
number or char literals, for binary signatures.

```c
pattern java = { 0xac, 0xed, 0x00, 0x05 };   // Java serialization magic
```

**Punctuation / operators** (longest match first):

```
??  ==  !=  <=  >=  &&  ||  <<  >>
<   >   !   &   |   +   -   (   )   {   }   [   ]   ;   ,   =   .   @   :
```

---
