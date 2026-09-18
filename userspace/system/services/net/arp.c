int getbyte(int addr) {
    int base = addr & (0 - 8);
    int word = *base;
    int shift = (addr & 7) * 8;
    return (word >> shift) & 255;
}

int putbyte(int addr, int value) {
    int base = addr & (0 - 8);
    int shift = (addr & 7) * 8;
    int word = *base;
    int mask = (0 - 1) - (255 << shift);
    word = (word & mask) | ((value & 255) << shift);
    *base = word;
    return 0;
}

int pair(int addr) {
    int high = getbyte(addr);
    int low = getbyte(addr + 1);
    return (high << 8) | low;
}

int frameok(int addr, int len) {
    if (len < 42) {
        return 0;
    }
    if (1514 < len) {
        return 0;
    }
    if (pair(addr + 12) != 2054) {
        return 0;
    }
    return 1;
}

int headok(int addr) {
    if (pair(addr + 14) != 1) {
        return 0;
    }
    if (pair(addr + 16) != 2048) {
        return 0;
    }
    if (getbyte(addr + 18) != 6) {
        return 0;
    }
    if (getbyte(addr + 19) != 4) {
        return 0;
    }
    return 1;
}

int islocal(int addr) {
    if (getbyte(addr + 38) != 10) {
        return 0;
    }
    if (getbyte(addr + 39) != 0) {
        return 0;
    }
    if (getbyte(addr + 40) != 0) {
        return 0;
    }
    if (getbyte(addr + 41) != 2) {
        return 0;
    }
    return 1;
}

int makerepl(int addr) {
    int m0 = getbyte(addr + 22);
    int m1 = getbyte(addr + 23);
    int m2 = getbyte(addr + 24);
    int m3 = getbyte(addr + 25);
    int m4 = getbyte(addr + 26);
    int m5 = getbyte(addr + 27);
    int i0 = getbyte(addr + 28);
    int i1 = getbyte(addr + 29);
    int i2 = getbyte(addr + 30);
    int i3 = getbyte(addr + 31);

    putbyte(addr + 0, m0);
    putbyte(addr + 1, m1);
    putbyte(addr + 2, m2);
    putbyte(addr + 3, m3);
    putbyte(addr + 4, m4);
    putbyte(addr + 5, m5);

    putbyte(addr + 6, 2);
    putbyte(addr + 7, 0);
    putbyte(addr + 8, 0);
    putbyte(addr + 9, 0);
    putbyte(addr + 10, 0);
    putbyte(addr + 11, 2);

    putbyte(addr + 20, 0);
    putbyte(addr + 21, 2);

    putbyte(addr + 22, 2);
    putbyte(addr + 23, 0);
    putbyte(addr + 24, 0);
    putbyte(addr + 25, 0);
    putbyte(addr + 26, 0);
    putbyte(addr + 27, 2);

    putbyte(addr + 28, 10);
    putbyte(addr + 29, 0);
    putbyte(addr + 30, 0);
    putbyte(addr + 31, 2);

    putbyte(addr + 32, m0);
    putbyte(addr + 33, m1);
    putbyte(addr + 34, m2);
    putbyte(addr + 35, m3);
    putbyte(addr + 36, m4);
    putbyte(addr + 37, m5);

    putbyte(addr + 38, i0);
    putbyte(addr + 39, i1);
    putbyte(addr + 40, i2);
    putbyte(addr + 41, i3);
    return 0;
}

int main() {
    int status = syscall(18, 0, 0, 1, 0);
    int len = sysret(1);
    int opcode = 0;

    if (status != 0) {
        return 100 + status;
    }
    if (frameok(65536, len) == 0) {
        return 64;
    }
    if (headok(65536) == 0) {
        return 64;
    }

    opcode = pair(65536 + 20);
    if (opcode != 1) {
        return 3;
    }
    if (islocal(65536) == 0) {
        return 2;
    }

    makerepl(65536);
    status = syscall(19, 0, 0, 1, 0, len);
    if (status != 0) {
        return 120 + status;
    }
    return 1;
}
