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

int addsum(int sum, int word) {
    sum = sum + word;
    sum = (sum & 65535) + (sum >> 16);
    return sum;
}

int cksum(int addr, int len) {
    int sum = 0;
    int pos = 0;

    while (pos + 1 < len) {
        sum = addsum(sum, pair(addr + pos));
        pos = pos + 2;
    }
    if (pos < len) {
        sum = addsum(sum, getbyte(addr + pos) << 8);
    }
    while (65535 < sum) {
        sum = (sum & 65535) + (sum >> 16);
    }
    return 65535 - sum;
}

int udpcsum(int addr, int ulen) {
    int sum = 0;
    int pos = 0;

    sum = addsum(sum, pair(addr + 26));
    sum = addsum(sum, pair(addr + 28));
    sum = addsum(sum, pair(addr + 30));
    sum = addsum(sum, pair(addr + 32));
    sum = addsum(sum, 17);
    sum = addsum(sum, ulen);

    while (pos + 1 < ulen) {
        sum = addsum(sum, pair(addr + 34 + pos));
        pos = pos + 2;
    }
    if (pos < ulen) {
        sum = addsum(sum, getbyte(addr + 34 + pos) << 8);
    }
    while (65535 < sum) {
        sum = (sum & 65535) + (sum >> 16);
    }
    return 65535 - sum;
}

int ipok(int addr, int len) {
    int total = 0;
    int frag = 0;

    if (len < 42) {
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
    if (total < 28) {
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

int makerepl(int addr, int ulen) {
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
    int sport = pair(addr + 34);
    int dport = pair(addr + 36);
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

    putpair(addr + 34, dport);
    putpair(addr + 36, sport);
    putpair(addr + 40, 0);
    sum = udpcsum(addr, ulen);
    if (sum == 0) {
        sum = 65535;
    }
    putpair(addr + 40, sum);

    sum = cksum(addr + 14, 20);
    putpair(addr + 24, sum);
    return 0;
}

int main() {
    int status = syscall(18, 0, 0, 1, 0);
    int len = sysret(1);
    int total = 0;
    int ulen = 0;
    int usum = 0;

    if (status != 0) {
        return 100 + status;
    }
    if (ipok(65536, len) == 0) {
        return 64;
    }
    if (islocal(65536) == 0) {
        return 2;
    }
    if (getbyte(65536 + 23) != 17) {
        return 3;
    }

    total = pair(65536 + 16);
    ulen = pair(65536 + 38);
    if (ulen < 8) {
        return 64;
    }
    if (ulen != total - 20) {
        return 64;
    }
    if (pair(65536 + 36) != 49152) {
        return 3;
    }

    usum = pair(65536 + 40);
    if (usum != 0) {
        if (udpcsum(65536, ulen) != 0) {
            return 64;
        }
    }

    makerepl(65536, ulen);
    status = syscall(19, 0, 0, 1, 0, len);
    if (status != 0) {
        return 120 + status;
    }
    return 1;
}
