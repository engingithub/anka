//! Canonical self-hosted compiler source used to bootstrap CC_B for the
//! interactive development shell.
//!
//! The generator intentionally lives as a child of `guest_compiler` so it
//! shares the exact workspace/token/ISA constants used by the bootstrap AST.
//! This is the same canonical source exercised by the bootstrap fixed-point
//! regression corpus.

use super::*;

fn canonical_readbyte() -> String {
    format!(
        "int readbyte(int pos) {{ \
         int aligned = pos & (0 - 8); \
         int word = *(*{} + aligned); \
         int shift = (pos & 7) * 8; \
         return (word >> shift) & 255; }} ",
        WS_TEXT_BASE)
}

fn canonical_writebyte() -> String {
    format!(
        "int writebyte(int addr, int byte) {{ \
         int aligned = addr & (0 - 8); \
         int shift = (addr & 7) * 8; \
         int word = *(aligned); \
         int mask = 255 << shift; \
         word = (word & ((0 - 1) - mask)) | ((byte & 255) << shift); \
         *(aligned) = word; \
         return 0; }} ")
}

fn canonical_storeliteral() -> String {
    // Two-ended image allocator (7.2): literals grow downward from
    // OUTPUT_SIZE within the output buffer.  Returns the absolute
    // offset of the literal header within the output buffer.
    // Underflow-safe: checks lp < size before lp - size.
    format!(
        "int storeliteral() {{ \
         int len = *{nl}; \
         int start = *{ns}; \
         int lp = *{litp}; \
         int aligned = (len + 7) & (0 - 8); \
         int sz = aligned + 8; \
         if (lp < sz) {{ *{e} = 1; return 0; }} \
         lp = lp - sz; \
         *({out} + lp) = len; \
         int db = {out} + lp + 8; \
         int i = 0; \
         while (i < len) {{ \
         writebyte(db + i, readbyte(start + i)); \
         i = i + 1; }} \
         *{litp} = lp; \
         return lp; }} ",
        ns = WS_TOK_NAME_START, nl = WS_TOK_NAME_LEN,
        litp = WS_LIT_POS, e = WS_ERROR, out = LAYOUT_OUT)
}

fn canonical_peekchar() -> String {
    format!(
        "int peekchar() {{ \
         int p = *{}; \
         if (*{} <= p) {{ return 0; }} \
         return readbyte(p); }} ",
        WS_POS, WS_SRC_LEN)
}

fn canonical_advance() -> String {
    format!(
        "int advance() {{ \
         *{} = *{} + 1; \
         return 0; }} ",
        WS_POS, WS_POS)
}

fn canonical_skipws() -> String {
    "int skipws() { \
     int ch = peekchar(); \
     while ((0 < ch) & (ch <= 32)) { \
     advance(); \
     ch = peekchar(); } \
     return 0; } ".to_string()
}

fn canonical_nameseq() -> String {
    "int nameseq(int sa, int la, int sb, int lb) { \
     if (la != lb) { return 0; } \
     int i = 0; \
     int a = 0; \
     int b = 0; \
     while (i < la) { \
     a = readbyte(sa + i); \
     b = readbyte(sb + i); \
     if (a != b) { return 0; } \
     i = i + 1; } \
     return 1; } ".to_string()
}

fn canonical_classifykw() -> String {
    // Keyword bytes: if=105,102  int=105,110,116
    //   else=101,108,115,101  while=119,104,105,108,101
    //   return=114,101,116,117,114,110
    //   sysret=115,121,115,114,101,116
    //   syscall=115,121,115,99,97,108,108
    format!(
        "int classifykw(int s, int l) {{ \
         if (l == 2) {{ \
         if (readbyte(s) == 105) {{ \
         if (readbyte(s + 1) == 102) {{ return {kw_if}; }} }} }} \
         if (l == 3) {{ \
         if (readbyte(s) == 105) {{ \
         if (readbyte(s + 1) == 110) {{ \
         if (readbyte(s + 2) == 116) {{ return {kw_int}; }} }} }} }} \
         if (l == 4) {{ \
         if (readbyte(s) == 101) {{ \
         if (readbyte(s + 1) == 108) {{ \
         if (readbyte(s + 2) == 115) {{ \
         if (readbyte(s + 3) == 101) {{ return {kw_else}; }} }} }} }} }} \
         if (l == 5) {{ \
         if (readbyte(s) == 119) {{ \
         if (readbyte(s + 1) == 104) {{ \
         if (readbyte(s + 2) == 105) {{ \
         if (readbyte(s + 3) == 108) {{ \
         if (readbyte(s + 4) == 101) {{ return {kw_while}; }} }} }} }} }} }} \
         if (l == 6) {{ \
         if (readbyte(s) == 114) {{ \
         if (readbyte(s + 1) == 101) {{ \
         if (readbyte(s + 2) == 116) {{ \
         if (readbyte(s + 3) == 117) {{ \
         if (readbyte(s + 4) == 114) {{ \
         if (readbyte(s + 5) == 110) {{ return {kw_return}; }} }} }} }} }} }} \
         if (readbyte(s) == 115) {{ \
         if (readbyte(s + 1) == 121) {{ \
         if (readbyte(s + 2) == 115) {{ \
         if (readbyte(s + 3) == 114) {{ \
         if (readbyte(s + 4) == 101) {{ \
         if (readbyte(s + 5) == 116) {{ return {kw_sysret}; }} }} }} }} }} }} }} \
         if (l == 7) {{ \
         if (readbyte(s) == 115) {{ \
         if (readbyte(s + 1) == 121) {{ \
         if (readbyte(s + 2) == 115) {{ \
         if (readbyte(s + 3) == 99) {{ \
         if (readbyte(s + 4) == 97) {{ \
         if (readbyte(s + 5) == 108) {{ \
         if (readbyte(s + 6) == 108) {{ return {kw_syscall}; }} }} }} }} }} }} }} }} \
         return {ident}; }} ",
        kw_if = TOK_IF, kw_int = TOK_INT_KW, kw_else = TOK_ELSE,
        kw_while = TOK_WHILE, kw_return = TOK_RETURN,
        kw_sysret = TOK_SYSRET, kw_syscall = TOK_SYSCALL,
        ident = TOK_IDENT)
}

fn canonical_setchartok() -> String {
    format!(
        "int setchartok(int t, int v) {{ \
         *{} = t; *{} = v; \
         advance(); return 0; }} ",
        WS_TOK_TYPE, WS_TOK_VALUE)
}

fn canonical_scannumber() -> String {
    format!(
        "int scannumber() {{ \
         int v = 0; \
         int ch = peekchar(); \
         while ((48 <= ch) & (ch <= 57)) {{ \
         v = v * 10 + (ch - 48); \
         if (131071 < v) {{ *{e} = 1; ch = 0; }} \
         else {{ advance(); ch = peekchar(); }} }} \
         *{t} = {num}; *{tv} = v; return 0; }} ",
        e = WS_ERROR,
        t = WS_TOK_TYPE,
        num = TOK_NUMBER,
        tv = WS_TOK_VALUE)
}

fn canonical_scanident() -> String {
    format!(
        "int scanident() {{ \
         int ch = peekchar(); \
         int start = *{pos}; \
         int len = 0; \
         while ((97 <= ch) & (ch <= 122)) {{ \
         len = len + 1; advance(); ch = peekchar(); }} \
         while ((48 <= ch) & (ch <= 57)) {{ \
         len = len + 1; advance(); ch = peekchar(); }} \
         *{ns} = start; *{nl} = len; \
         *{tt} = classifykw(start, len); return 0; }} ",
        pos = WS_POS,
        ns = WS_TOK_NAME_START,
        nl = WS_TOK_NAME_LEN,
        tt = WS_TOK_TYPE)
}

fn canonical_validateutf8() -> String {
    "int validateutf8(int start, int len) { \
     int i = 0; int b = 0; int need = 0; \
     int lo = 0; int hi = 0; int j = 0; int c = 0; \
     while (i < len) { \
     b = readbyte(start + i); \
     if (b <= 127) { i = i + 1; } \
     else { \
     need = 0; lo = 128; hi = 191; \
     if ((194 <= b) & (b <= 223)) { need = 1; } \
     else { if (b == 224) { need = 2; lo = 160; } \
     else { if ((225 <= b) & (b <= 236)) { need = 2; } \
     else { if (b == 237) { need = 2; hi = 159; } \
     else { if ((238 <= b) & (b <= 239)) { need = 2; } \
     else { if (b == 240) { need = 3; lo = 144; } \
     else { if ((241 <= b) & (b <= 243)) { need = 3; } \
     else { if (b == 244) { need = 3; hi = 143; } \
     else { return 1; \
     } } } } } } } } \
     if (len < i + need + 1) { return 1; } \
     c = readbyte(start + i + 1); \
     if (c < lo) { return 1; } \
     if (hi < c) { return 1; } \
     j = 2; \
     while (j <= need) { \
     c = readbyte(start + i + j); \
     if (c < 128) { return 1; } \
     if (191 < c) { return 1; } \
     j = j + 1; } \
     i = i + need + 1; \
     } } \
     return 0; } ".into()
}

fn canonical_scanstring() -> String {
    format!(
        "int scanstring() {{ \
         advance(); \
         int start = *{pos}; \
         int len = 0; \
         while (*{pos} < *{sl}) {{ \
         if (peekchar() == 34) {{ \
         advance(); \
         if (validateutf8(start, len) != 0) {{ \
         *{e} = 1; *{tt} = {eof}; return 0; }} \
         *{ns} = start; *{nl} = len; \
         *{tt} = {str}; return 0; }} \
         len = len + 1; advance(); }} \
         *{e} = 1; *{tt} = {eof}; return 0; }} ",
        pos = WS_POS, sl = WS_SRC_LEN,
        ns = WS_TOK_NAME_START, nl = WS_TOK_NAME_LEN,
        tt = WS_TOK_TYPE, e = WS_ERROR,
        str = TOK_STRING, eof = TOK_EOF)
}

fn canonical_nexttoken() -> String {
    format!(
        "int nexttoken() {{ \
         skipws(); \
         if (*{sl} <= *{pos}) {{ *{tt} = {eof}; return 0; }} \
         int ch = peekchar(); \
         if (ch == 43) {{ return setchartok({plus}, 43); }} \
         if (ch == 45) {{ return setchartok({minus}, 45); }} \
         if (ch == 42) {{ return setchartok({star}, 42); }} \
         if (ch == 59) {{ return setchartok({semi}, 59); }} \
         if (ch == 44) {{ return setchartok({comma}, 44); }} \
         if (ch == 40) {{ return setchartok({lp}, 40); }} \
         if (ch == 41) {{ return setchartok({rp}, 41); }} \
         if (ch == 123) {{ return setchartok({lb}, 123); }} \
         if (ch == 125) {{ return setchartok({rb}, 125); }} \
         if (ch == 124) {{ return setchartok({pipe}, 124); }} \
         if (ch == 38) {{ return setchartok({amp}, 38); }} \
         if (ch == 61) {{ advance(); \
         if (peekchar() == 61) {{ advance(); *{tt} = {eqeq}; return 0; }} \
         *{tt} = {eq}; return 0; }} \
         if (ch == 60) {{ advance(); ch = peekchar(); \
         if (ch == 61) {{ advance(); *{tt} = {le}; return 0; }} \
         if (ch == 60) {{ advance(); *{tt} = {shl}; return 0; }} \
         *{tt} = {lt}; return 0; }} \
         if (ch == 62) {{ advance(); \
         if (peekchar() == 62) {{ advance(); *{tt} = {shr}; return 0; }} \
         *{e} = 1; *{tt} = {eof}; return 0; }} \
         if (ch == 33) {{ advance(); \
         if (peekchar() == 61) {{ advance(); *{tt} = {ne}; return 0; }} \
         *{e} = 1; *{tt} = {eof}; return 0; }} \
         if (ch == 34) {{ return scanstring(); }} \
         if ((97 <= ch) & (ch <= 122)) {{ return scanident(); }} \
         if ((48 <= ch) & (ch <= 57)) {{ return scannumber(); }} \
         *{e} = 1; *{tt} = {eof}; return 0; }} ",
        pos = WS_POS, sl = WS_SRC_LEN, tt = WS_TOK_TYPE,
        e = WS_ERROR,
        eof = TOK_EOF, plus = TOK_PLUS, minus = TOK_MINUS,
        star = TOK_STAR, semi = TOK_SEMI, comma = TOK_COMMA,
        lp = TOK_LPAREN, rp = TOK_RPAREN,
        lb = TOK_LBRACE, rb = TOK_RBRACE,
        pipe = TOK_PIPE, amp = TOK_AMP,
        eq = TOK_EQ, eqeq = TOK_EQEQ, ne = TOK_NE,
        le = TOK_LE, lt = TOK_LT,
        shl = TOK_SHL, shr = TOK_SHR)
}

fn canonical_compilecall() -> String {
    format!(
        "int compilecall(int ns, int nl) {{ \
         nexttoken(); \
         int argc = 0; \
         if (*{tt} != {rp}) {{ \
         compileexpr(); \
         emit(enci({subi}, {sp}, {sp}, 8)); \
         emit(enci({st}, {r4}, {sp}, 0)); \
         argc = 1; \
         while (*{tt} == {comma}) {{ \
         if (4 <= argc) {{ *{e} = 1; return 0; }} \
         nexttoken(); \
         compileexpr(); \
         emit(enci({subi}, {sp}, {sp}, 8)); \
         emit(enci({st}, {r4}, {sp}, 0)); \
         argc = argc + 1; }} }} \
         if (*{tt} != {rp}) {{ *{e} = 1; }} \
         nexttoken(); \
         if (0 < argc) {{ emit(enci({ld}, {r0}, {sp}, (argc - 1) * 8)); }} \
         if (1 < argc) {{ emit(enci({ld}, 1, {sp}, (argc - 2) * 8)); }} \
         if (2 < argc) {{ emit(enci({ld}, 2, {sp}, (argc - 3) * 8)); }} \
         if (3 < argc) {{ emit(enci({ld}, 3, {sp}, (argc - 4) * 8)); }} \
         if (0 < argc) {{ emit(enci({addi}, {sp}, {sp}, argc * 8)); }} \
         int pos = *{op}; \
         emit({call} << 26); \
         addfixup(pos, ns, nl, argc); \
         emit(encr({mov}, {r4}, {r0}, 0)); \
         return 0; }} ",
        tt = WS_TOK_TYPE, rp = TOK_RPAREN, comma = TOK_COMMA,
        e = WS_ERROR, op = WS_OUT_POS,
        subi = OP_SUBI, addi = OP_ADDI, st = OP_ST, ld = OP_LD,
        call = OP_CALL, mov = OP_MOV,
        sp = GEN_SP, r4 = GEN_R4, r0 = GEN_R0)
}

fn canonical_compileprimary() -> String {
    format!(
        "int compileprimary() {{ \
         int tok = *{tt}; \
         int ns = 0; \
         int nl = 0; \
         int argc = 0; \
         if (tok == {num}) {{ \
         ns = *{tv}; \
         nexttoken(); \
         emit(enci({movi}, {r4}, 0, ns)); \
         return 0; }} \
         if (tok == {ident}) {{ \
         ns = *{tns}; nl = *{tnl}; \
         nexttoken(); \
         if (*{tt} == {lp}) {{ \
         compilecall(ns, nl); \
         }} else {{ \
         ns = lookupsymbol(ns, nl); \
         emit(enci({ld}, {r4}, {fp}, ns)); }} \
         return 0; }} \
         if (tok == {lp}) {{ \
         nexttoken(); \
         compileexpr(); \
         if (*{tt} != {rp}) {{ *{e} = 1; }} \
         else {{ nexttoken(); }} \
         return 0; }} \
         if (tok == {syscall}) {{ \
         nexttoken(); \
         if (*{tt} != {lp}) {{ *{e} = 1; }} \
         nexttoken(); \
         compileexpr(); \
         emit(enci({subi}, {sp}, {sp}, 8)); \
         emit(enci({st}, {r4}, {sp}, 0)); \
         if (*{tt} != {comma}) {{ *{e} = 1; }} \
         nexttoken(); \
         compileexpr(); \
         emit(enci({subi}, {sp}, {sp}, 8)); \
         emit(enci({st}, {r4}, {sp}, 0)); \
         if (*{tt} != {comma}) {{ *{e} = 1; }} \
         nexttoken(); \
         compileexpr(); \
         emit(enci({subi}, {sp}, {sp}, 8)); \
         emit(enci({st}, {r4}, {sp}, 0)); \
         if (*{tt} != {comma}) {{ *{e} = 1; }} \
         nexttoken(); \
         compileexpr(); \
         emit(enci({subi}, {sp}, {sp}, 8)); \
         emit(enci({st}, {r4}, {sp}, 0)); \
         argc = 4; \
         if (*{tt} == {comma}) {{ \
         nexttoken(); \
         compileexpr(); \
         emit(enci({subi}, {sp}, {sp}, 8)); \
         emit(enci({st}, {r4}, {sp}, 0)); \
         argc = 5; \
         if (*{tt} == {comma}) {{ \
         nexttoken(); \
         compileexpr(); \
         emit(enci({subi}, {sp}, {sp}, 8)); \
         emit(enci({st}, {r4}, {sp}, 0)); \
         argc = 6; }} }} \
         if (*{tt} != {rp}) {{ *{e} = 1; }} \
         nexttoken(); \
         emit(enci({ld2}, {r0}, {sp}, (argc - 1) * 8)); \
         emit(enci({ld2}, 1, {sp}, (argc - 2) * 8)); \
         emit(enci({ld2}, 2, {sp}, (argc - 3) * 8)); \
         emit(enci({ld2}, 3, {sp}, (argc - 4) * 8)); \
         if (4 < argc) {{ emit(enci({ld2}, {r4}, {sp}, (argc - 5) * 8)); }} \
         if (5 < argc) {{ emit(enci({ld2}, {r5}, {sp}, (argc - 6) * 8)); }} \
         emit(enci({addi}, {sp}, {sp}, argc * 8)); \
         emit(encs({trap})); \
         emit(encr({mov}, {r4}, {r0}, 0)); \
         return 0; }} \
         if (tok == {sysret}) {{ \
         nexttoken(); \
         if (*{tt} != {lp}) {{ *{e} = 1; }} \
         nexttoken(); \
         if (*{tt} != {num}) {{ *{e} = 1; }} \
         if (*{tv} != 1) {{ *{e} = 1; }} \
         nexttoken(); \
         if (*{tt} != {rp}) {{ *{e} = 1; }} \
         nexttoken(); \
         emit(encr({mov}, {r4}, 1, 0)); \
         return 0; }} \
         if (tok == {str}) {{ \
         int litoff = storeliteral(); \
         nexttoken(); \
         emit(enci({movi}, {r4}, 0, litoff)); \
         return 0; }} \
         *{e} = 1; return 0; }} ",
        tt = WS_TOK_TYPE, tv = WS_TOK_VALUE,
        tns = WS_TOK_NAME_START, tnl = WS_TOK_NAME_LEN,
        e = WS_ERROR,
        num = TOK_NUMBER, ident = TOK_IDENT,
        str = TOK_STRING, sysret = TOK_SYSRET,
        lp = TOK_LPAREN, rp = TOK_RPAREN,
        comma = TOK_COMMA, syscall = TOK_SYSCALL,
        movi = OP_MOVI, ld = OP_LD, ld2 = OP_LD,
        subi = OP_SUBI, addi = OP_ADDI, st = OP_ST, trap = OP_TRAP,
        mov = OP_MOV,
        r4 = GEN_R4, r5 = GEN_R5, r0 = GEN_R0,
        fp = GEN_FP, sp = GEN_SP)
}

fn canonical_exprsave() -> String {
    format!(
        "int exprsave() {{ \
         int off = *{esp}; \
         emit(enci({st}, {r4}, {sp}, off)); \
         *{esp} = *{esp} - 8; \
         return 0; }} ",
        esp = WS_EXPR_SP,
        st = OP_ST, r4 = GEN_R4, sp = GEN_SP)
}

fn canonical_exprrestore() -> String {
    format!(
        "int exprrestore() {{ \
         *{esp} = *{esp} + 8; \
         int off = *{esp}; \
         emit(enci({ld}, {r5}, {sp}, off)); \
         return 0; }} ",
        esp = WS_EXPR_SP,
        ld = OP_LD, r5 = GEN_R5, sp = GEN_SP)
}

fn canonical_compilemult() -> String {
    format!(
        "int compilemult() {{ \
         compileunary(); \
         while (*{tt} == {star}) {{ \
         nexttoken(); \
         exprsave(); compileunary(); exprrestore(); \
         emit(encr({mul}, {r4}, {r5}, {r4})); }} \
         return 0; }} ",
        tt = WS_TOK_TYPE, star = TOK_STAR,
        mul = OP_MUL, r4 = GEN_R4, r5 = GEN_R5)
}

fn canonical_compileadd() -> String {
    format!(
        "int compileadd() {{ \
         compilemult(); \
         int op = 0; \
         while ((*{tt} == {plus}) | (*{tt} == {minus})) {{ \
         op = *{tt}; nexttoken(); \
         exprsave(); compilemult(); exprrestore(); \
         if (op == {plus}) {{ emit(encr({add}, {r4}, {r5}, {r4})); }} \
         else {{ emit(encr({sub}, {r4}, {r5}, {r4})); }} }} \
         return 0; }} ",
        tt = WS_TOK_TYPE,
        plus = TOK_PLUS, minus = TOK_MINUS,
        add = OP_ADD, sub = OP_SUB,
        r4 = GEN_R4, r5 = GEN_R5)
}

fn canonical_compileshift() -> String {
    format!(
        "int compileshift() {{ \
         compileadd(); \
         int op = 0; \
         while ((*{tt} == {shl}) | (*{tt} == {shr})) {{ \
         op = *{tt}; nexttoken(); \
         exprsave(); compileadd(); exprrestore(); \
         if (op == {shl}) {{ emit(encr({shlop}, {r4}, {r5}, {r4})); }} \
         else {{ emit(encr({shrop}, {r4}, {r5}, {r4})); }} }} \
         return 0; }} ",
        tt = WS_TOK_TYPE,
        shl = TOK_SHL, shr = TOK_SHR,
        shlop = OP_SHL, shrop = OP_SHR,
        r4 = GEN_R4, r5 = GEN_R5)
}

fn canonical_compilebitand() -> String {
    format!(
        "int compilebitand() {{ \
         compileshift(); \
         while (*{tt} == {amp}) {{ \
         nexttoken(); \
         exprsave(); compileshift(); exprrestore(); \
         emit(encr({and}, {r4}, {r5}, {r4})); }} \
         return 0; }} ",
        tt = WS_TOK_TYPE, amp = TOK_AMP,
        and = OP_AND, r4 = GEN_R4, r5 = GEN_R5)
}

fn canonical_compilebitor() -> String {
    format!(
        "int compilebitor() {{ \
         compilebitand(); \
         while (*{tt} == {pipe}) {{ \
         nexttoken(); \
         exprsave(); compilebitand(); exprrestore(); \
         emit(encr({or}, {r4}, {r5}, {r4})); }} \
         return 0; }} ",
        tt = WS_TOK_TYPE, pipe = TOK_PIPE,
        or = OP_OR, r4 = GEN_R4, r5 = GEN_R5)
}

// Comparison helper: CMP 0,R5,R4; MOVI R4,0; BCC skip,+4; MOVI R4,1
fn cmp_emit(skip_cond: i64) -> String {
    format!(
        "emit(encr({cmpi}, 0, {r5}, {r4})); \
         emit(enci({movi}, {r4}, 0, 0)); \
         emit(encb({skip}, 4)); \
         emit(enci({movi2}, {r4}, 0, 1)); ",
        cmpi = OP_CMP, r5 = GEN_R5, r4 = GEN_R4,
        movi = OP_MOVI, movi2 = OP_MOVI,
        skip = skip_cond)
}

fn canonical_compilerel() -> String {
    format!(
        "int compilerel() {{ \
         compilebitor(); \
         int op = 0; \
         while ((*{tt} == {lt}) | (*{tt} == {le})) {{ \
         op = *{tt}; nexttoken(); \
         exprsave(); compilebitor(); exprrestore(); \
         if (op == {lt}) {{ {cmp_lt} }} \
         else {{ {cmp_le} }} }} \
         return 0; }} ",
        tt = WS_TOK_TYPE,
        lt = TOK_LT, le = TOK_LE,
        cmp_lt = cmp_emit(COND_GE),   // < skips on GE
        cmp_le = cmp_emit(COND_GT))   // <= skips on GT
}

fn canonical_compileeq() -> String {
    format!(
        "int compileeq() {{ \
         compilerel(); \
         int op = 0; \
         while ((*{tt} == {eqeq}) | (*{tt} == {ne})) {{ \
         op = *{tt}; nexttoken(); \
         exprsave(); compilerel(); exprrestore(); \
         if (op == {eqeq}) {{ {cmp_eq} }} \
         else {{ {cmp_ne} }} }} \
         return 0; }} ",
        tt = WS_TOK_TYPE,
        eqeq = TOK_EQEQ, ne = TOK_NE,
        cmp_eq = cmp_emit(COND_NE),   // == skips on NE
        cmp_ne = cmp_emit(COND_EQ))   // != skips on EQ
}

fn canonical_compileexpr() -> String {
    "int compileexpr() { return compileeq(); } ".to_string()
}

fn canonical_compilestmt() -> String {
    format!(
        "int compilestmt() {{ \
         int tok = *{tt}; \
         int ns = 0; \
         int nl = 0; \
         int bp = 0; \
         int sp2 = 0; \
         if (tok == {kw_int}) {{ \
         nexttoken(); \
         if (*{tt} != {ident}) {{ *{e} = 1; }} \
         ns = *{tns}; nl = *{tnl}; \
         nexttoken(); \
         if (*{tt} != {eq}) {{ *{e} = 1; }} \
         nexttoken(); \
         compileexpr(); \
         if (*{tt} != {semi}) {{ *{e} = 1; }} \
         nexttoken(); \
         sp2 = addsymbol(ns, nl); \
         emit(enci({st}, {r4}, {fp}, sp2)); \
         return 0; }} \
         if (tok == {kw_return}) {{ \
         nexttoken(); \
         compileexpr(); \
         if (*{tt} != {semi}) {{ *{e} = 1; }} \
         nexttoken(); \
         emit(encr({mov}, {r0}, {r4}, 0)); \
         emit(encr({mov}, {sp}, {fp}, 0)); \
         emit(enci({ld}, {fp}, {sp}, 0)); \
         emit(enci({ld}, {lr}, {sp}, 8)); \
         emit(enci({addi}, {sp}, {sp}, 16)); \
         emit(encs({ret})); \
         return 1; }} \
         if (tok == {kw_if}) {{ \
         nexttoken(); \
         if (*{tt} != {lp}) {{ *{e} = 1; }} \
         nexttoken(); \
         compileexpr(); \
         if (*{tt} != {rp}) {{ *{e} = 1; }} \
         nexttoken(); \
         emit(enci({cmpi}, 0, {r4}, 0)); \
         bp = *{op}; \
         emit(encb({ceq}, 0)); \
         if (*{tt} != {lb}) {{ *{e} = 1; }} \
         nexttoken(); \
         ns = compileblock(); \
         if (*{tt} == {kw_else}) {{ \
         nexttoken(); \
         sp2 = *{op}; \
         emit(encb({cal}, 0)); \
         patchbranch(bp, {ceq}, *{op}); \
         if (*{tt} != {lb}) {{ *{e} = 1; }} \
         nexttoken(); \
         nl = compileblock(); \
         patchbranch(sp2, {cal}, *{op}); \
         return ns & nl; \
         }} else {{ \
         patchbranch(bp, {ceq}, *{op}); \
         return 0; }} \
         return 0; }} \
         if (tok == {kw_while}) {{ \
         nexttoken(); \
         if (*{tt} != {lp}) {{ *{e} = 1; }} \
         nexttoken(); \
         bp = *{op}; \
         compileexpr(); \
         if (*{tt} != {rp}) {{ *{e} = 1; }} \
         nexttoken(); \
         emit(enci({cmpi}, 0, {r4}, 0)); \
         sp2 = *{op}; \
         emit(encb({ceq}, 0)); \
         if (*{tt} != {lb}) {{ *{e} = 1; }} \
         nexttoken(); \
         compileblock(); \
         ns = 0 - ((*{op} - bp) >> 2); \
         emit(encb({cal}, ns)); \
         patchbranch(sp2, {ceq}, *{op}); \
         return 0; }} \
         if (tok == {star}) {{ \
         nexttoken(); \
         compileexpr(); \
         exprsave(); \
         if (*{tt} != {eq}) {{ *{e} = 1; }} \
         nexttoken(); \
         compileexpr(); \
         exprrestore(); \
         if (*{tt} != {semi}) {{ *{e} = 1; }} \
         nexttoken(); \
         emit(enci({st}, {r4}, {r5}, 0)); \
         return 0; }} \
         if (tok == {ident}) {{ \
         ns = *{tns}; nl = *{tnl}; \
         nexttoken(); \
         if (*{tt} == {lp}) {{ \
         compilecall(ns, nl); \
         if (*{tt} != {semi}) {{ *{e} = 1; }} \
         nexttoken(); \
         return 0; }} \
         if (*{tt} != {eq}) {{ *{e} = 1; }} \
         nexttoken(); \
         compileexpr(); \
         if (*{tt} != {semi}) {{ *{e} = 1; }} \
         nexttoken(); \
         sp2 = lookupsymbol(ns, nl); \
         emit(enci({st}, {r4}, {fp}, sp2)); \
         return 0; }} \
         *{e} = 1; return 0; }} ",
        tt = WS_TOK_TYPE, tns = WS_TOK_NAME_START, tnl = WS_TOK_NAME_LEN,
        e = WS_ERROR, op = WS_OUT_POS,
        kw_int = TOK_INT_KW, kw_return = TOK_RETURN,
        kw_if = TOK_IF, kw_else = TOK_ELSE, kw_while = TOK_WHILE,
        ident = TOK_IDENT, star = TOK_STAR,
        eq = TOK_EQ, semi = TOK_SEMI,
        lp = TOK_LPAREN, rp = TOK_RPAREN,
        lb = TOK_LBRACE,
        st = OP_ST, ld = OP_LD, addi = OP_ADDI,
        cmpi = OP_CMPI, ret = OP_RET, mov = OP_MOV,
        ceq = COND_EQ, cal = COND_AL,
        r4 = GEN_R4, r5 = GEN_R5, r0 = GEN_R0,
        fp = GEN_FP, lr = GEN_LR, sp = GEN_SP)
}

fn canonical_compilefuncdef() -> String {
    format!(
        "int compilefuncdef() {{ \
         if (*{tt} != {kw_int}) {{ *{e} = 1; }} \
         nexttoken(); \
         if (*{tt} != {ident}) {{ *{e} = 1; }} \
         int ns = *{tns}; \
         int fnl = *{tnl}; \
         nexttoken(); \
         if (*{tt} != {lp}) {{ *{e} = 1; }} \
         nexttoken(); \
         *{sc} = 0; \
         *{esp} = (0 - {espabs}); \
         int pc = 0; \
         int pns = 0; \
         int pnl = 0; \
         while (*{tt} == {kw_int}) {{ \
         if (4 <= pc) {{ *{e} = 1; return 0; }} \
         nexttoken(); \
         if (*{tt} != {ident}) {{ *{e} = 1; }} \
         pns = *{tns}; pnl = *{tnl}; \
         nexttoken(); \
         addsymbol(pns, pnl); \
         pc = pc + 1; \
         if (*{tt} == {comma}) {{ nexttoken(); }} }} \
         if (*{tt} != {rp}) {{ *{e} = 1; }} \
         nexttoken(); \
         if (*{tt} != {lb}) {{ *{e} = 1; }} \
         nexttoken(); \
         addfunc(ns, fnl, pc); \
         int pp = *{op}; \
         emit(encs({nop})); \
         emit(encs({nop})); \
         emit(encs({nop})); \
         emit(encs({nop})); \
         if (0 < pc) {{ emit(enci({st_op}, {r0}, {fp}, 0 - 8)); }} \
         if (1 < pc) {{ emit(enci({st_op}, 1, {fp}, 0 - 16)); }} \
         if (2 < pc) {{ emit(enci({st_op}, 2, {fp}, 0 - 24)); }} \
         if (3 < pc) {{ emit(enci({st_op}, 3, {fp}, 0 - 32)); }} \
         ns = compileblock(); \
         int fs = 16 + *{sc} * 8; \
         int npad = ({nop} << 26) << 32; \
         int base = {out} + pp; \
         *base = enci({subi}, {sp}, {sp}, fs) | npad; \
         *(base + 8) = enci({st_op}, {lr}, {sp}, fs - 8) | npad; \
         *(base + 16) = enci({st_op}, {fp}, {sp}, fs - 16) | npad; \
         *(base + 24) = enci({addi}, {fp}, {sp}, fs - 16) | npad; \
         if (ns == 0) {{ *{e} = 1; }} \
         return 0; }} ",
        tt = WS_TOK_TYPE, tns = WS_TOK_NAME_START, tnl = WS_TOK_NAME_LEN,
        e = WS_ERROR, op = WS_OUT_POS, sc = WS_SYM_COUNT,
        esp = WS_EXPR_SP, espabs = -EXPR_SP_INIT,
        out = LAYOUT_OUT,
        kw_int = TOK_INT_KW, ident = TOK_IDENT,
        lp = TOK_LPAREN, rp = TOK_RPAREN,
        comma = TOK_COMMA, lb = TOK_LBRACE,
        nop = OP_NOP, subi = OP_SUBI, addi = OP_ADDI,
        st_op = OP_ST,
        r0 = GEN_R0, fp = GEN_FP, lr = GEN_LR, sp = GEN_SP)
}

fn canonical_findmain() -> String {
    // "main" = 109, 97, 105, 110
    format!(
        "int findmain() {{ \
         int cnt = *{fc}; \
         int i = 0; \
         int base = 0; \
         int ns = 0; \
         int nl = 0; \
         while (i < cnt) {{ \
         base = {ft} + i * 32; \
         ns = *base; nl = *(base + 8); \
         if (nl == 4) {{ \
         if (readbyte(ns) == 109) {{ \
         if (readbyte(ns + 1) == 97) {{ \
         if (readbyte(ns + 2) == 105) {{ \
         if (readbyte(ns + 3) == 110) {{ \
         return *(base + 16); }} }} }} }} }} \
         i = i + 1; }} \
         *{e} = 1; return 0; }} ",
        fc = WS_FUNC_COUNT, ft = WS_FUNC_TABLE,
        e = WS_ERROR)
}

fn canonical_compileblock() -> String {
    format!(
        "int compileblock() {{ \
         int ret = 0; \
         while (((*{tt} != {rb}) & (*{tt} != {eof})) & (*{e} == 0)) {{ \
         ret = ret | compilestmt(); }} \
         if (*{e} != 0) {{ return ret; }} \
         if (*{tt} == {eof}) {{ *{e} = 1; return ret; }} \
         nexttoken(); \
         return ret; }} ",
        tt = WS_TOK_TYPE, e = WS_ERROR,
        rb = TOK_RBRACE, eof = TOK_EOF)
}

pub(crate) fn canonical_compiler_source() -> String {
    format!(
        "{}{}{}{}{}{}{}",
        canonical_stmt_prelude(),
        canonical_compilefuncdef(),
        canonical_findmain(),
        canonical_compilermain(),
        "", "", "")
}

/// CC_B source variant used only when bootstrapping a compiler whose own
/// generated image no longer fits the historical 80 KiB fixed-point arena.
///
/// The canonical source above is intentionally frozen by the Phase 9.3h
/// fixed-point regression. This variant changes only the compiler entry
/// point so a supervised harness can supply a larger output frontier through
/// WS_OUTPUT_LIMIT. A zero word retains the historical 80 KiB behavior.
pub(crate) fn extended_compiler_source() -> String {
    format!(
        "{}{}{}{}{}{}{}",
        canonical_stmt_prelude(),
        canonical_compilefuncdef(),
        canonical_findmain(),
        extended_compilermain(),
        "", "", "")
}

fn canonical_compilermain() -> String {
    // After compilation, normalize literal segment offset:
    // lp == OUTPUT_SIZE → no literals → pass 0 as R3.
    // Otherwise pass lp (the literal frontier) as R3.
    // Equality check, not comparison: corruption should propagate.
    //
    // WS_LIT_POS is initialized to OUTPUT_SIZE here so the compiler
    // is self-sufficient — the host does not need to write workspace
    // fields before boot (Phase 8.1c).
    format!(
        "int main() {{ \
         int mode = *{mode}; \
         int src = {layout_src}; \
         int slen = *src; \
         int sbase = src + 8; \
         if ({srclimit} < slen) {{ return 0 - 1; }} \
         *{pos} = 0; \
         *{sl} = slen; \
         *{tb} = sbase; \
         *{e} = 0; \
         *{sc} = 0; \
         *{op} = 0; \
         *{esp} = (0 - {espabs}); \
         *{fc} = 0; \
         *{fxc} = 0; \
         *{litp} = {outsize}; \
         nexttoken(); \
         int sp = *{op}; \
         emit({call} << 26); \
         emit(encs({halt})); \
         while ((*{tt} != {eof}) & (*{e} == 0)) {{ \
         compilefuncdef(); }} \
         resolvefixups(); \
         int ma = findmain(); \
         patchcall(sp, ma); \
         if (*{e} != 0) {{ return 0 - 1; }} \
         int seal = syscall(5, {layout_out}, 0, 0); \
         int sz = *{op}; \
         int lp = *{litp}; \
         if (lp == {outsize}) {{ lp = 0; }} \
         if (mode == {compile_only}) {{ return 0; }} \
         return syscall(6, {layout_out}, sz, lp); }} ",
        mode = WS_MODE, compile_only = CCB_MODE_COMPILE_ONLY,
        layout_src = LAYOUT_SRC,
        srclimit = SOURCE_SIZE - 8,
        layout_out = LAYOUT_OUT,
        pos = WS_POS, sl = WS_SRC_LEN, tb = WS_TEXT_BASE,
        e = WS_ERROR, sc = WS_SYM_COUNT, op = WS_OUT_POS,
        esp = WS_EXPR_SP, espabs = -EXPR_SP_INIT,
        fc = WS_FUNC_COUNT, fxc = WS_FIX_COUNT,
        tt = WS_TOK_TYPE, eof = TOK_EOF,
        litp = WS_LIT_POS, outsize = OUTPUT_SIZE,
        call = OP_CALL, halt = OP_HALT)
}

fn extended_compilermain() -> String {
    format!(
        "int main() {{ \
         int mode = *{mode}; \
         int outlimit = *{outlimit}; \
         if (outlimit == 0) {{ outlimit = {outsize}; }} \
         int src = {layout_src}; \
         int slen = *src; \
         int sbase = src + 8; \
         if ({srclimit} < slen) {{ return 0 - 1; }} \
         *{pos} = 0; \
         *{sl} = slen; \
         *{tb} = sbase; \
         *{e} = 0; \
         *{sc} = 0; \
         *{op} = 0; \
         *{esp} = (0 - {espabs}); \
         *{fc} = 0; \
         *{fxc} = 0; \
         *{litp} = outlimit; \
         nexttoken(); \
         int sp = *{op}; \
         emit({call} << 26); \
         emit(encs({halt})); \
         while ((*{tt} != {eof}) & (*{e} == 0)) {{ \
         compilefuncdef(); }} \
         resolvefixups(); \
         int ma = findmain(); \
         patchcall(sp, ma); \
         if (*{e} != 0) {{ return 0 - 1; }} \
         int seal = syscall(5, {layout_out}, 0, 0); \
         int sz = *{op}; \
         int lp = *{litp}; \
         if (lp == outlimit) {{ lp = 0; }} \
         if (mode == {compile_only}) {{ return 0; }} \
         return syscall(6, {layout_out}, sz, lp); }} ",
        mode = WS_MODE, outlimit = WS_OUTPUT_LIMIT,
        compile_only = CCB_MODE_COMPILE_ONLY,
        layout_src = LAYOUT_SRC,
        srclimit = SOURCE_SIZE - 8,
        layout_out = LAYOUT_OUT,
        pos = WS_POS, sl = WS_SRC_LEN, tb = WS_TEXT_BASE,
        e = WS_ERROR, sc = WS_SYM_COUNT, op = WS_OUT_POS,
        esp = WS_EXPR_SP, espabs = -EXPR_SP_INIT,
        fc = WS_FUNC_COUNT, fxc = WS_FIX_COUNT,
        tt = WS_TOK_TYPE, eof = TOK_EOF,
        litp = WS_LIT_POS, outsize = OUTPUT_SIZE,
        call = OP_CALL, halt = OP_HALT)
}

fn canonical_compileunary() -> String {
    format!(
        "int compileunary() {{ \
         if (*{tt} == {star}) {{ \
         nexttoken(); \
         compileunary(); \
         emit(enci({ld}, {r4}, {r4}, 0)); \
         return 0; }} \
         return compileprimary(); }} ",
        tt = WS_TOK_TYPE, star = TOK_STAR,
        ld = OP_LD, r4 = GEN_R4)
}

fn canonical_enci() -> String {
    "int enci(int op, int rd, int rs, int imm) { \
     return (op << 26) | (rd << 22) | (rs << 18) | ((imm << 46) >> 46); } ".to_string()
}

fn canonical_encr() -> String {
    "int encr(int op, int rd, int rs, int rs2) { \
     return (op << 26) | (rd << 22) | (rs << 18) | (rs2 << 14); } ".to_string()
}

fn canonical_encs() -> String {
    "int encs(int op) { return op << 26; } ".to_string()
}

fn canonical_encb() -> String {
    format!(
        "int encb(int cond, int disp) {{ \
         return ({bcc} << 26) | (cond << 22) | ((disp << 42) >> 42); }} ",
        bcc = OP_BCC)
}

fn canonical_emit() -> String {
    // Width-safe collision guard (7.2): the full 8-byte write
    // must fit below the literal frontier WS_LIT_POS.
    //   if (lp < 8) → underflow guard
    //   if (lp - 8 < pos) → collision
    // When no literals (lp == OUTPUT_SIZE), degenerates to original.
    format!(
        "int emit(int word) {{ \
         int pos = *{op}; \
         int lp = *{litp}; \
         if (lp < 8) {{ *{e} = 1; return 0; }} \
         if (lp - 8 < pos) {{ *{e} = 1; return 0; }} \
         int padded = word | (({nop} << 26) << 32); \
         *({out} + pos) = padded; \
         *{op} = pos + 8; \
         return 0; }} ",
        op = WS_OUT_POS,
        litp = WS_LIT_POS,
        e = WS_ERROR,
        nop = OP_NOP,
        out = LAYOUT_OUT)
}

fn canonical_patchbranch() -> String {
    format!(
        "int patchbranch(int pos, int cond, int target) {{ \
         int disp = (target - pos) >> 2; \
         int word = ({bcc} << 26) | (cond << 22) | ((disp << 42) >> 42); \
         int padded = word | (({nop} << 26) << 32); \
         *({out} + pos) = padded; \
         return 0; }} ",
        bcc = OP_BCC,
        nop = OP_NOP,
        out = LAYOUT_OUT)
}

fn canonical_patchcall() -> String {
    format!(
        "int patchcall(int pos, int addr) {{ \
         int disp = (addr >> 2) - (pos >> 2); \
         int word = ({call} << 26) | ((disp << 42) >> 42); \
         int padded = word | (({nop} << 26) << 32); \
         *({out} + pos) = padded; \
         return 0; }} ",
        call = OP_CALL,
        nop = OP_NOP,
        out = LAYOUT_OUT)
}

fn canonical_addsymbol() -> String {
    format!(
        "int addsymbol(int ns, int nl) {{ \
         int cnt = *{sc}; \
         if (32 <= cnt) {{ *{e} = 1; return 0; }} \
         int i = 0; \
         int base = 0; \
         int sns = 0; \
         int snl = 0; \
         while (i < cnt) {{ \
         base = {st} + i * 24; \
         sns = *base; snl = *(base + 8); \
         if (nameseq(ns, nl, sns, snl) == 1) {{ *{e} = 1; return 0; }} \
         i = i + 1; }} \
         int off = (0 - (cnt + 1)) * 8; \
         base = {st} + cnt * 24; \
         *base = ns; *(base + 8) = nl; *(base + 16) = off; \
         *{sc} = cnt + 1; \
         return off; }} ",
        sc = WS_SYM_COUNT,
        e = WS_ERROR,
        st = WS_SYM_TABLE)
}

fn canonical_lookupsymbol() -> String {
    format!(
        "int lookupsymbol(int ns, int nl) {{ \
         int cnt = *{sc}; \
         int i = 0; \
         int base = 0; \
         while (i < cnt) {{ \
         base = {st} + i * 24; \
         if (nameseq(ns, nl, *base, *(base + 8)) == 1) {{ \
         return *(base + 16); }} \
         i = i + 1; }} \
         *{e} = 1; return 0; }} ",
        sc = WS_SYM_COUNT,
        e = WS_ERROR,
        st = WS_SYM_TABLE)
}

fn canonical_addfunc() -> String {
    format!(
        "int addfunc(int ns, int nl, int arity) {{ \
         int cnt = *{fc}; \
         if (64 <= cnt) {{ *{e} = 1; return 0; }} \
         int base = {ft} + cnt * 32; \
         *base = ns; *(base + 8) = nl; \
         *(base + 16) = *{op}; *(base + 24) = arity; \
         *{fc} = cnt + 1; return 0; }} ",
        fc = WS_FUNC_COUNT,
        e = WS_ERROR,
        ft = WS_FUNC_TABLE,
        op = WS_OUT_POS)
}

fn canonical_lookupfunc() -> String {
    format!(
        "int lookupfunc(int ns, int nl) {{ \
         int cnt = *{fc}; \
         int i = 0; \
         int base = 0; \
         while (i < cnt) {{ \
         base = {ft} + i * 32; \
         if (nameseq(ns, nl, *base, *(base + 8)) == 1) {{ \
         return *(base + 16); }} \
         i = i + 1; }} \
         *{e} = 1; return 0; }} ",
        fc = WS_FUNC_COUNT,
        e = WS_ERROR,
        ft = WS_FUNC_TABLE)
}

fn canonical_lookuparity() -> String {
    format!(
        "int lookuparity(int ns, int nl) {{ \
         int cnt = *{fc}; \
         int i = 0; \
         int base = 0; \
         while (i < cnt) {{ \
         base = {ft} + i * 32; \
         if (nameseq(ns, nl, *base, *(base + 8)) == 1) {{ \
         return *(base + 24); }} \
         i = i + 1; }} \
         *{e} = 1; return 0; }} ",
        fc = WS_FUNC_COUNT,
        e = WS_ERROR,
        ft = WS_FUNC_TABLE)
}

fn canonical_addfixup() -> String {
    format!(
        "int addfixup(int cp, int ns, int nl, int argc) {{ \
         int cnt = *{xc}; \
         if (512 <= cnt) {{ *{e} = 1; return 0; }} \
         int base = {xt} + cnt * 32; \
         *base = cp; *(base + 8) = ns; \
         *(base + 16) = nl; *(base + 24) = argc; \
         *{xc} = cnt + 1; return 0; }} ",
        xc = WS_FIX_COUNT,
        e = WS_ERROR,
        xt = WS_FIX_TABLE)
}

fn canonical_resolvefixups() -> String {
    format!(
        "int resolvefixups() {{ \
         int cnt = *{xc}; \
         int i = 0; \
         int base = 0; \
         int cp = 0; \
         int ns = 0; \
         int nl = 0; \
         int argc = 0; \
         int addr = 0; \
         int arity = 0; \
         while (i < cnt) {{ \
         base = {xt} + i * 32; \
         cp = *base; ns = *(base + 8); \
         nl = *(base + 16); argc = *(base + 24); \
         addr = lookupfunc(ns, nl); \
         arity = lookuparity(ns, nl); \
         if (argc != arity) {{ *{e} = 1; }} \
         patchcall(cp, addr); \
         i = i + 1; }} \
         return 0; }} ",
        xc = WS_FIX_COUNT,
        e = WS_ERROR,
        xt = WS_FIX_TABLE)
}

fn canonical_expr_prelude() -> String {
    format!(
        "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
        canonical_readbyte(),
        canonical_writebyte(),
        canonical_storeliteral(),
        canonical_peekchar(),
        canonical_advance(),
        canonical_skipws(),
        canonical_nameseq(),
        canonical_classifykw(),
        canonical_setchartok(),
        canonical_scannumber(),
        canonical_scanident(),
        canonical_validateutf8(),
        canonical_scanstring(),
        canonical_nexttoken(),
        canonical_enci(),
        canonical_encr(),
        canonical_encs(),
        canonical_encb(),
        canonical_emit(),
        canonical_patchbranch(),
        canonical_patchcall(),
        canonical_addsymbol(),
        canonical_lookupsymbol(),
        canonical_addfunc(),
        canonical_lookupfunc(),
        canonical_lookuparity(),
        canonical_addfixup(),
        canonical_resolvefixups(),
        canonical_exprsave(),
        canonical_exprrestore(),
        canonical_compilecall(),
        canonical_compileprimary(),
        canonical_compileunary(),
        canonical_compilemult(),
        canonical_compileadd(),
        canonical_compileshift(),
        canonical_compilebitand(),
        canonical_compilebitor(),
    )
}

fn canonical_stmt_prelude() -> String {
    format!(
        "{}{}{}{}{}{}{}",
        canonical_expr_prelude(),
        canonical_compilerel(),
        canonical_compileeq(),
        canonical_compileexpr(),
        canonical_compilestmt(),
        canonical_compileblock(),
        "")
}
