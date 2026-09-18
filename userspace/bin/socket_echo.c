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

int main() {
    int msg = 0;
    int tag = 0;
    int len = 0;
    int status = 0;

    msg = syscall(14, 0, 0, 0);
    tag = sysret(1);
    if (tag != 1) {
        return 10;
    }
    if (msg != 1) {
        return 11;
    }

    msg = syscall(14, 0, 0, 0);
    tag = sysret(1);
    if (tag != 1) {
        return 12;
    }
    if (msg <= 4096) {
        return 13;
    }
    len = msg - 4096;
    if (len != 4) {
        return 14;
    }
    if (getbyte(98304) != 112) {
        return 15;
    }
    if (getbyte(98305) != 105) {
        return 16;
    }
    if (getbyte(98306) != 110) {
        return 17;
    }
    if (getbyte(98307) != 103) {
        return 18;
    }

    putbyte(98304, 112);
    putbyte(98305, 111);
    putbyte(98306, 110);
    putbyte(98307, 103);
    status = syscall(12, 0, 0, 8196);
    if (status != 0) {
        return 19;
    }

    msg = syscall(14, 0, 0, 0);
    tag = sysret(1);
    if (tag != 1) {
        return 20;
    }
    if (msg != 2) {
        return 21;
    }
    return 0;
}
