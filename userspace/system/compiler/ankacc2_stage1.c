int readbyte(int pos) {
    int aligned = pos & (0 - 8);
    int word = *(*49168 + aligned);
    int shift = (pos & 7) * 8;
    return (word >> shift) & 255;
}

int peekchar() {
    int pos = *49152;
    if (*49160 <= pos) { return 0; }
    return readbyte(pos);
}

int advance() {
    *49152 = *49152 + 1;
    return 0;
}

int seterror(int code) {
    if (*49176 == 0) { *49176 = code; }
    return 0;
}

int skipspace() {
    int ch = peekchar();
    while ((0 < ch) & (ch <= 32)) {
        advance();
        ch = peekchar();
    }
    return 0;
}

int firstchar(int ch) {
    if ((65 <= ch) & (ch <= 90)) { return 1; }
    if ((97 <= ch) & (ch <= 122)) { return 1; }
    if (ch == 95) { return 1; }
    return 0;
}

int restchar(int ch) {
    if (firstchar(ch) == 1) { return 1; }
    if ((48 <= ch) & (ch <= 57)) { return 1; }
    return 0;
}

int keyword(int start, int len) {
    if (len == 3) {
        if (readbyte(start) == 105) {
            if (readbyte(start + 1) == 110) {
                if (readbyte(start + 2) == 116) { return 1; }
            }
        }
    }
    if (len == 6) {
        if (readbyte(start) == 114) {
            if (readbyte(start + 1) == 101) {
                if (readbyte(start + 2) == 116) {
                    if (readbyte(start + 3) == 117) {
                        if (readbyte(start + 4) == 114) {
                            if (readbyte(start + 5) == 110) { return 2; }
                        }
                    }
                }
            }
        }
    }
    return 3;
}

int scanident() {
    int start = *49152;
    int len = 0;
    int ch = peekchar();
    while (restchar(ch) == 1) {
        len = len + 1;
        if (63 < len) {
            seterror(2);
            return 0;
        }
        advance();
        ch = peekchar();
    }
    *49200 = start;
    *49208 = len;
    *49184 = keyword(start, len);
    return 0;
}

int hexvalue(int ch) {
    if ((48 <= ch) & (ch <= 57)) { return ch - 48; }
    if ((65 <= ch) & (ch <= 70)) { return ch - 55; }
    if ((97 <= ch) & (ch <= 102)) { return ch - 87; }
    return 0 - 1;
}

int maxdigit(int pos) {
    if (pos == 0) { return 1; }
    if (pos == 1) { return 8; }
    if (pos == 2) { return 4; }
    if (pos == 3) { return 4; }
    if (pos == 4) { return 6; }
    if (pos == 5) { return 7; }
    if (pos == 6) { return 4; }
    if (pos == 7) { return 4; }
    if (pos == 8) { return 0; }
    if (pos == 9) { return 7; }
    if (pos == 10) { return 3; }
    if (pos == 11) { return 7; }
    if (pos == 12) { return 0; }
    if (pos == 13) { return 9; }
    if (pos == 14) { return 5; }
    if (pos == 15) { return 5; }
    if (pos == 16) { return 1; }
    if (pos == 17) { return 6; }
    if (pos == 18) { return 1; }
    return 5;
}

int decimalfits(int start) {
    int pos = 0;
    int ch = 0;
    int lim = 0;
    while (pos < 20) {
        ch = readbyte(start + pos) - 48;
        lim = maxdigit(pos);
        if (ch < lim) { return 1; }
        if (lim < ch) { return 0; }
        pos = pos + 1;
    }
    return 1;
}

int scandecimal() {
    int value = 0;
    int significant = 0;
    int sigstart = 0;
    int seen = 0;
    int ch = peekchar();
    int digit = 0;
    while ((48 <= ch) & (ch <= 57)) {
        digit = ch - 48;
        if (seen == 0) {
            if (digit != 0) {
                seen = 1;
                sigstart = *49152;
                significant = 1;
            }
        } else {
            significant = significant + 1;
        }
        value = value * 10 + digit;
        advance();
        ch = peekchar();
    }
    if (20 < significant) {
        seterror(3);
        return 0;
    }
    if (significant == 20) {
        if (decimalfits(sigstart) == 0) {
            seterror(3);
            return 0;
        }
    }
    *49192 = value;
    *49184 = 4;
    return 0;
}

int scanhex() {
    int value = 0;
    int significant = 0;
    int seen = 0;
    int any = 0;
    int digit = 0;
    int ch = 0;
    advance();
    advance();
    ch = peekchar();
    digit = hexvalue(ch);
    while (0 <= digit) {
        any = 1;
        if (seen == 0) {
            if (digit != 0) {
                seen = 1;
                significant = 1;
            }
        } else {
            significant = significant + 1;
        }
        value = (value << 4) | digit;
        advance();
        ch = peekchar();
        digit = hexvalue(ch);
    }
    if (any == 0) {
        seterror(3);
        return 0;
    }
    if (16 < significant) {
        seterror(3);
        return 0;
    }
    *49192 = value;
    *49184 = 4;
    return 0;
}

int scannumber() {
    int pos = *49152;
    if (readbyte(pos) == 48) {
        if (pos + 1 < *49160) {
            int ch = readbyte(pos + 1);
            if ((ch == 120) | (ch == 88)) { return scanhex(); }
        }
    }
    return scandecimal();
}

int chartoken(int tok) {
    *49184 = tok;
    advance();
    return 0;
}

int nexttoken() {
    skipspace();
    if (*49176 != 0) { *49184 = 0; return 0; }
    if (*49160 <= *49152) { *49184 = 0; return 0; }
    int ch = peekchar();
    if (firstchar(ch) == 1) { return scanident(); }
    if ((48 <= ch) & (ch <= 57)) { return scannumber(); }
    if (ch == 40) { return chartoken(5); }
    if (ch == 41) { return chartoken(6); }
    if (ch == 123) { return chartoken(7); }
    if (ch == 125) { return chartoken(8); }
    if (ch == 59) { return chartoken(9); }
    seterror(1);
    *49184 = 0;
    return 0;
}

int nameequal(int first, int flen, int second, int slen) {
    if (flen != slen) { return 0; }
    int pos = 0;
    while (pos < flen) {
        if (readbyte(first + pos) != readbyte(second + pos)) { return 0; }
        pos = pos + 1;
    }
    return 1;
}

int enci(int op, int dest, int source, int imm) {
    return (op << 26) | (dest << 22) | (source << 18) | ((imm << 46) >> 46);
}

int encr(int op, int dest, int left, int right) {
    return (op << 26) | (dest << 22) | (left << 18) | (right << 14);
}

int encs(int op) {
    return op << 26;
}

int emit(int word) {
    int pos = *49224;
    if (*68472 < pos + 8) {
        seterror(8);
        return 0;
    }
    int padded = word | ((63 << 26) << 32);
    *(73728 + pos) = padded;
    *49224 = pos + 8;
    return 0;
}

int patchcall(int pos, int address) {
    int disp = (address >> 2) - (pos >> 2);
    int word = (50 << 26) | ((disp << 42) >> 42);
    int padded = word | ((63 << 26) << 32);
    *(73728 + pos) = padded;
    return 0;
}

int addfunc(int start, int len, int address) {
    int count = *49240;
    int pos = 0;
    int base = 0;
    while (pos < count) {
        base = 50024 + pos * 32;
        if (nameequal(start, len, *base, *(base + 8)) == 1) {
            seterror(5);
            return 0;
        }
        pos = pos + 1;
    }
    if (64 <= count) {
        seterror(8);
        return 0;
    }
    base = 50024 + count * 32;
    *base = start;
    *(base + 8) = len;
    *(base + 16) = address;
    *(base + 24) = 0;
    *49240 = count + 1;
    return 0;
}

int lookupfunc(int start, int len) {
    int count = *49240;
    int pos = 0;
    int base = 0;
    while (pos < count) {
        base = 50024 + pos * 32;
        if (nameequal(start, len, *base, *(base + 8)) == 1) {
            return *(base + 16);
        }
        pos = pos + 1;
    }
    return 0 - 1;
}

int addfix(int pos, int start, int len) {
    int count = *49248;
    if (128 <= count) {
        seterror(8);
        return 0;
    }
    int base = 52072 + count * 24;
    *base = pos;
    *(base + 8) = start;
    *(base + 16) = len;
    *49248 = count + 1;
    return 0;
}

int prologue() {
    emit(enci(17, 15, 15, 8));
    emit(enci(33, 14, 15, 0));
    return 0;
}

int epilogue() {
    emit(enci(32, 14, 15, 0));
    emit(enci(16, 15, 15, 8));
    emit(encs(56));
    return 0;
}

int emitconstant(int value) {
    int pos = 0;
    int shift = 0;
    int nibble = 0;
    emit(enci(22, 0, 0, 0));
    emit(enci(22, 1, 0, 4));
    while (pos < 16) {
        emit(encr(6, 0, 0, 1));
        shift = (15 - pos) * 4;
        nibble = (value >> shift) & 15;
        emit(enci(22, 2, 0, nibble));
        emit(encr(4, 0, 0, 2));
        pos = pos + 1;
    }
    return 0;
}

int parseexpr() {
    if (*49184 == 4) {
        int value = *49192;
        nexttoken();
        emitconstant(value);
        return 0;
    }
    if (*49184 == 3) {
        int start = *49200;
        int len = *49208;
        nexttoken();
        if (*49184 != 5) { seterror(4); return 0; }
        nexttoken();
        if (*49184 != 6) { seterror(4); return 0; }
        nexttoken();
        int pos = *49224;
        emit(50 << 26);
        addfix(pos, start, len);
        return 0;
    }
    seterror(4);
    return 0;
}

int parsefunc() {
    if (*49184 != 1) { seterror(4); return 0; }
    nexttoken();
    if (*49184 != 3) { seterror(4); return 0; }
    int start = *49200;
    int len = *49208;
    nexttoken();
    if (*49184 != 5) { seterror(4); return 0; }
    nexttoken();
    if (*49184 != 6) { seterror(4); return 0; }
    nexttoken();
    if (*49184 != 7) { seterror(4); return 0; }
    nexttoken();
    addfunc(start, len, *49224);
    prologue();
    if (*49184 != 2) { seterror(4); return 0; }
    nexttoken();
    parseexpr();
    if (*49184 != 9) { seterror(4); return 0; }
    nexttoken();
    epilogue();
    if (*49184 != 8) { seterror(4); return 0; }
    nexttoken();
    return 0;
}

int findmain() {
    int count = *49240;
    int pos = 0;
    int base = 0;
    int start = 0;
    int len = 0;
    while (pos < count) {
        base = 50024 + pos * 32;
        start = *base;
        len = *(base + 8);
        if (len == 4) {
            if (readbyte(start) == 109) {
                if (readbyte(start + 1) == 97) {
                    if (readbyte(start + 2) == 105) {
                        if (readbyte(start + 3) == 110) { return *(base + 16); }
                    }
                }
            }
        }
        pos = pos + 1;
    }
    seterror(6);
    return 0;
}

int resolve() {
    int count = *49248;
    int pos = 0;
    int base = 0;
    int address = 0;
    while (pos < count) {
        base = 52072 + pos * 24;
        address = lookupfunc(*(base + 8), *(base + 16));
        if (address < 0) {
            seterror(7);
            return 0;
        }
        patchcall(*base, address);
        pos = pos + 1;
    }
    return 0;
}

int main() {
    int mode = *68464;
    int source = 28672;
    int length = *source;
    if (20472 < length) { return 0 - 1; }
    *49152 = 0;
    *49160 = length;
    *49168 = source + 8;
    *49176 = 0;
    *49184 = 0;
    *49192 = 0;
    *49200 = 0;
    *49208 = 0;
    *49224 = 0;
    *49240 = 0;
    *49248 = 0;
    *68456 = *68472;
    int entry = *49224;
    emit(50 << 26);
    emit(encs(62));
    nexttoken();
    while ((*49184 != 0) & (*49176 == 0)) {
        parsefunc();
    }
    if (*49176 == 0) {
        resolve();
    }
    int address = 0;
    if (*49176 == 0) {
        address = findmain();
    }
    if (*49176 == 0) {
        patchcall(entry, address);
    }
    if (*49176 != 0) { return 0 - 1; }
    int seal = syscall(5, 73728, 0, 0);
    if (mode == 1) { return 0; }
    return syscall(6, 73728, *49224, 0);
}
