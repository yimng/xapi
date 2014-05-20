type token =
  | IDENT of (string)
  | STRING of (string)
  | INT of (int)
  | COMMA
  | LBRACKET
  | RBRACKET
  | EQ
  | SEMICOLON
  | NEWLINE
  | EOF

open Parsing;;
# 2 "xn_cfg_parser.mly"
open Xn_cfg_types
# 17 "xn_cfg_parser.ml"
let yytransl_const = [|
  260 (* COMMA *);
  261 (* LBRACKET *);
  262 (* RBRACKET *);
  263 (* EQ *);
  264 (* SEMICOLON *);
  265 (* NEWLINE *);
    0 (* EOF *);
    0|]

let yytransl_block = [|
  257 (* IDENT *);
  258 (* STRING *);
  259 (* INT *);
    0|]

let yylhs = "\255\255\
\001\000\001\000\001\000\002\000\004\000\004\000\003\000\003\000\
\005\000\005\000\007\000\007\000\007\000\008\000\008\000\006\000\
\006\000\000\000"

let yylen = "\002\000\
\001\000\002\000\002\000\004\000\001\000\001\000\001\000\004\000\
\001\000\001\000\000\000\001\000\003\000\002\000\005\000\000\000\
\002\000\002\000"

let yydefred = "\000\000\
\000\000\000\000\000\000\000\000\001\000\018\000\000\000\000\000\
\002\000\003\000\009\000\010\000\016\000\000\000\007\000\000\000\
\006\000\005\000\004\000\017\000\016\000\000\000\000\000\000\000\
\008\000\016\000\000\000\016\000\000\000"

let yydgoto = "\002\000\
\006\000\007\000\014\000\019\000\015\000\016\000\022\000\023\000"

let yysindex = "\003\000\
\001\000\000\000\016\255\001\000\000\000\000\000\001\000\003\255\
\000\000\000\000\000\000\000\000\000\000\013\255\000\000\000\255\
\000\000\000\000\000\000\000\000\000\000\014\255\015\255\017\255\
\000\000\000\000\000\255\000\000\017\255"

let yyrindex = "\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\018\255\
\000\000\000\000\000\000\000\000\000\000\000\000\019\255\011\255\
\000\000\000\000\021\255\000\000\012\255"

let yygindex = "\000\000\
\006\000\000\000\000\000\000\000\240\255\242\255\000\000\000\000"

let yytablesize = 266
let yytable = "\021\000\
\005\000\011\000\012\000\001\000\011\000\012\000\024\000\013\000\
\020\000\009\000\028\000\027\000\010\000\029\000\014\000\015\000\
\014\000\015\000\026\000\025\000\017\000\018\000\008\000\011\000\
\012\000\020\000\013\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\003\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\004\000"

let yycheck = "\016\000\
\000\000\002\001\003\001\001\000\002\001\003\001\021\000\005\001\
\009\001\004\000\027\000\026\000\007\000\028\000\004\001\004\001\
\006\001\006\001\004\001\006\001\008\001\009\001\007\001\006\001\
\006\001\009\001\006\001\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\001\001\255\255\255\255\255\255\255\255\255\255\255\255\
\255\255\009\001"

let yynames_const = "\
  COMMA\000\
  LBRACKET\000\
  RBRACKET\000\
  EQ\000\
  SEMICOLON\000\
  NEWLINE\000\
  EOF\000\
  "

let yynames_block = "\
  IDENT\000\
  STRING\000\
  INT\000\
  "

let yyact = [|
  (fun _ -> failwith "parser")
; (fun __caml_parser_env ->
    Obj.repr(
# 10 "xn_cfg_parser.mly"
                       ( [] )
# 163 "xn_cfg_parser.ml"
               : Xn_cfg_types.config))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 0 : Xn_cfg_types.config) in
    Obj.repr(
# 11 "xn_cfg_parser.mly"
                       ( _2 )
# 170 "xn_cfg_parser.ml"
               : Xn_cfg_types.config))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'setting) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : Xn_cfg_types.config) in
    Obj.repr(
# 12 "xn_cfg_parser.mly"
                       ( _1 :: _2 )
# 178 "xn_cfg_parser.ml"
               : Xn_cfg_types.config))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 3 : string) in
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'value) in
    let _4 = (Parsing.peek_val __caml_parser_env 0 : 'endstmt) in
    Obj.repr(
# 15 "xn_cfg_parser.mly"
                                ( _1, _3 )
# 187 "xn_cfg_parser.ml"
               : 'setting))
; (fun __caml_parser_env ->
    Obj.repr(
# 18 "xn_cfg_parser.mly"
                 ( () )
# 193 "xn_cfg_parser.ml"
               : 'endstmt))
; (fun __caml_parser_env ->
    Obj.repr(
# 19 "xn_cfg_parser.mly"
                   ( () )
# 199 "xn_cfg_parser.ml"
               : 'endstmt))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'atom) in
    Obj.repr(
# 22 "xn_cfg_parser.mly"
            ( _1 )
# 206 "xn_cfg_parser.ml"
               : 'value))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 2 : 'nlok) in
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'valuelist) in
    Obj.repr(
# 23 "xn_cfg_parser.mly"
                                        ( List _3 )
# 214 "xn_cfg_parser.ml"
               : 'value))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 26 "xn_cfg_parser.mly"
             ( String _1 )
# 221 "xn_cfg_parser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 27 "xn_cfg_parser.mly"
          ( Int _1 )
# 228 "xn_cfg_parser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    Obj.repr(
# 30 "xn_cfg_parser.mly"
                       ( [] )
# 234 "xn_cfg_parser.ml"
               : 'valuelist))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'values) in
    Obj.repr(
# 31 "xn_cfg_parser.mly"
                  ( _1 )
# 241 "xn_cfg_parser.ml"
               : 'valuelist))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'values) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : 'nlok) in
    Obj.repr(
# 32 "xn_cfg_parser.mly"
                             ( _1 )
# 249 "xn_cfg_parser.ml"
               : 'valuelist))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'atom) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'nlok) in
    Obj.repr(
# 35 "xn_cfg_parser.mly"
                  ( [ _1 ] )
# 257 "xn_cfg_parser.ml"
               : 'values))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 4 : 'values) in
    let _3 = (Parsing.peek_val __caml_parser_env 2 : 'nlok) in
    let _4 = (Parsing.peek_val __caml_parser_env 1 : 'atom) in
    let _5 = (Parsing.peek_val __caml_parser_env 0 : 'nlok) in
    Obj.repr(
# 36 "xn_cfg_parser.mly"
                                    ( _4 :: _1 )
# 267 "xn_cfg_parser.ml"
               : 'values))
; (fun __caml_parser_env ->
    Obj.repr(
# 39 "xn_cfg_parser.mly"
                  ( () )
# 273 "xn_cfg_parser.ml"
               : 'nlok))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'nlok) in
    Obj.repr(
# 40 "xn_cfg_parser.mly"
                ( () )
# 280 "xn_cfg_parser.ml"
               : 'nlok))
(* Entry file *)
; (fun __caml_parser_env -> raise (Parsing.YYexit (Parsing.peek_val __caml_parser_env 0)))
|]
let yytables =
  { Parsing.actions=yyact;
    Parsing.transl_const=yytransl_const;
    Parsing.transl_block=yytransl_block;
    Parsing.lhs=yylhs;
    Parsing.len=yylen;
    Parsing.defred=yydefred;
    Parsing.dgoto=yydgoto;
    Parsing.sindex=yysindex;
    Parsing.rindex=yyrindex;
    Parsing.gindex=yygindex;
    Parsing.tablesize=yytablesize;
    Parsing.table=yytable;
    Parsing.check=yycheck;
    Parsing.error_function=parse_error;
    Parsing.names_const=yynames_const;
    Parsing.names_block=yynames_block }
let file (lexfun : Lexing.lexbuf -> token) (lexbuf : Lexing.lexbuf) =
   (Parsing.yyparse yytables 1 lexfun lexbuf : Xn_cfg_types.config)
