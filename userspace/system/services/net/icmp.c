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

int putpair(int addr, int value) {
    putbyte(addr, (value >> 8) & 255);
    putbyte(addr + 1, value & 255);
    return 0;
}

int cksum(int addr, int len) {
    int sum = 0;
    int pos = 0;
    int word = 0;

    while (pos + 1 < len) {
        word = pair(addr + pos);
        sum = sum + word;
        sum = (sum & 65535) + (sum >> 16);
        pos = pos + 2;
    }
    if (pos < len) {
        sum = sum + (getbyte(addr + pos) << 8);
        sum = (sum & 65535) + (sum >> 16);
    }
    while (65535 < sum) {
        sum = (sum & 65535) + (sum >> 16);
    }
    return 65535 - sum;
}

int ipok(int addr, int len) {
    int total = 0;
    int frag = 0;

    if (len < 34) {
        return 0;
    }
    if (1514 < len) {
        return 0;
    }
    if (pair(addr + 12) != 2048) {
        return 0;
    }
    if (getbyte(addr + 14) != 69) {
        return 0;
    }

    total = pair(addr + 16);
    if (total < 20) {
        return 0;
    }
    if (len - 14 < total) {
        return 0;
    }
    if (cksum(addr + 14, 20) != 0) {
        return 0;
    }

    frag = pair(addr + 20);
    if ((frag & 16383) != 0) {
        return 0;
    }
    return 1;
}

int islocal(int addr) {
    if (getbyte(addr + 30) != 10) {
        return 0;
    }
    if (getbyte(addr + 31) != 0) {
        return 0;
    }
    if (getbyte(addr + 32) != 0) {
        return 0;
    }
    if (getbyte(addr + 33) != 2) {
        return 0;
    }
    return 1;
}

int makerepl(int addr, int ilen) {
    int m0 = getbyte(addr + 6);
    int m1 = getbyte(addr + 7);
    int m2 = getbyte(addr + 8);
    int m3 = getbyte(addr + 9);
    int m4 = getbyte(addr + 10);
    int m5 = getbyte(addr + 11);
    int i0 = getbyte(addr + 26);
    int i1 = getbyte(addr + 27);
    int i2 = getbyte(addr + 28);
    int i3 = getbyte(addr + 29);
    int sum = 0;

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

    putbyte(addr + 22, 64);
    putbyte(addr + 24, 0);
    putbyte(addr + 25, 0);

    putbyte(addr + 26, 10);
    putbyte(addr + 27, 0);
    putbyte(addr + 28, 0);
    putbyte(addr + 29, 2);

    putbyte(addr + 30, i0);
    putbyte(addr + 31, i1);
    putbyte(addr + 32, i2);
    putbyte(addr + 33, i3);

    sum = cksum(addr + 14, 20);
    putpair(addr + 24, sum);

    putbyte(addr + 34, 0);
    putbyte(addr + 35, 0);
    putbyte(addr + 36, 0);
    putbyte(addr + 37, 0);
    sum = cksum(addr + 34, ilen);
    putpair(addr + 36, sum);
    return 0;
}

int main() {
    int status = syscall(18, 0, 0, 1, 0);
    int len = sysret(1);
    int total = 0;
    int ilen = 0;

    if (status != 0) {
        return 100 + status;
    }
    if (ipok(65536, len) == 0) {
        return 64;
    }
    if (islocal(65536) == 0) {
        return 2;
    }
    if (getbyte(65536 + 23) != 1) {
        return 3;
    }

    total = pair(65536 + 16);
    ilen = total - 20;
    if (ilen < 8) {
        return 64;
    }
    if (cksum(65536 + 34, ilen) != 0) {
        return 64;
    }
    if (getbyte(65536 + 34) != 8) {
        return 3;
    }
    if (getbyte(65536 + 35) != 0) {
        return 3;
    }

    makerepl(65536, ilen);
    status = syscall(19, 0, 0, 1, 0, len);
    if (status != 0) {
        return 120 + status;
    }
    return 1;
}
