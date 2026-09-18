int readbyte(int addr) {
    int aligned = addr & (0 - 8);
    int word = *aligned;
    int shift = (addr & 7) * 8;
    return (word >> shift) & 255;
}

int validlen(int len) {
    return (14 <= len) & (len <= 1514);
}

int etype(int addr) {
    int high = readbyte(addr + 12);
    int low = readbyte(addr + 13);
    return (high << 8) | low;
}

int dispatch(int addr, int len) {
    int kind = 0;
    if (validlen(len) == 0) {
        return 64;
    }
    kind = etype(addr);
    if (kind == 2054) {
        return 1;
    }
    if (kind == 2048) {
        return 2;
    }
    return 3;
}

int main() {
    int status = syscall(18, 0, 0, 1, 0);
    int len = sysret(1);
    if (status != 0) {
        return 100 + status;
    }
    return dispatch(65536, len);
}
