# 9. Grammar (summary)

```ebnf
program     = { item } ;
item        = "nocase" ";"
            | "reassemble" [ number ] ";"
            | "decode" ident [ number ] ";"
            | "pattern" patdecl { "," patdecl } ";"
            | "regex" ident "=" string ";"
            | "knob" "struct" ident "{" knobfield { "," knobfield } "}" ";"
            | "macro" ident "{" { stmt } "}"
            | "fn" ident "(" [ ident { "," ident } ] ")" "{" { stmt } "}"
            | "filter" "{" { stmt } "}" ;      (* required, once *)
patdecl     = ident "=" ( string | "{" bytelist "}" ) ;
knobfield   = ident [ "??" (number|char) ] ;

stmt        = block | if | match | switch | "break" ";"
            | "decide" verdict ";" | "return" arith ";"
            | ( "mask" | "ptr" ) ident "=" expr ";"
            | "let" ident "=" arith ";"
            | "repeat" "(" number ")" stmt
            | "frame" [ "at" primary ] "(" framefields ")" "up" "to" number stmt
            | "ring" "." "push" "(" expr ")" ";"
            | ("flow"|"src") "." "state" "=" expr [ "for" expr ] ";"
            | ident "=" arith ";"          (* assign local / writable register *)
            | ident ";"                     (* macro expansion *)
            | ident "(" [ args ] ")" ";" ;  (* call / builtin statement *)
if          = "if" "(" expr ")" stmt [ "else" stmt ] ;
match       = "match" "(" arith ")" "{" { "case" prims block | "default" block } "}" ;
switch      = "switch" "(" arith ")" "{" { ("case" prims | "default") ":" { stmt } } "}" ;
verdict     = "pass" | "drop" "(" args ")" | "count" "(" args ")"
            | "ban" "(" args ")" | "rst" "(" args ")" ;

expr        = and { "||" and } ;                (* condition grammar *)
and         = compare { "&&" compare } ;
compare     = maskop [ "in" cidr-or-set ]
                     [ "&" maskop ] [ cmpop maskop ] ;
maskop      = primary { "|" primary } ;
arith       = primary { ("+"|"-"|"&"|"|"|"<<"|">>") primary } ;  (* value grammar *)
primary     = number | char | string | ident | "(" expr ")" | "!" primary
            | ("flow"|"src") "." ("state"|"count") | "src" "." "rate" "(" expr "," expr ")" | "ring" "." ("len"|"get" "(" expr ")")
            | "frame" "." ("len"|"type"|"data")
            | "argv" "[" number "]" [ "??" (number|char) ] | "argc"
            | "knob" "(" string ")" [ "??" (number|char) ] | "kstr" "(" string ")"
            | ident "." ident                  (* knob struct field *)
            | ident "(" [ args ] ")" ;         (* call *)
```

---
