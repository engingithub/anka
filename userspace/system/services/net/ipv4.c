int getbyte(int addr) {
    int base = addr & (0 - 8);
    int word = *base;
    int shift = (addr & 7) * 8;
    return (word >> shift) & 255;
}

int pair(int addr) {
    int high = getbyte(addr);
    int low = getbyte(addr + 1);
    return (high << 8) | low;
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

int frameok(int addr, int len) {
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

int main() {
    int status = syscall(18, 0, 0, 1, 0);

    if (status != 0) {
        return 100 + status;
    }
    if (frameok(65536, sysret(1)) == 0) {
        return 64;
    }
    if (islocal(65536) == 0) {
        return 2;
    }
    if (getbyte(65536 + 23) != 1) {
        return 3;
    }
    return 1;
}
