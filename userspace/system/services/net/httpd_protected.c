int getbyte(char *addr);
int putbyte(char *addr, int value);
int reqok(char *addr, int len);
int put200(char *addr);
int put404(char *addr);

int main() {
    char buffer[1024];
    char extra[1];
    int used=0;
    int count=0;
    int done=0;
    int out=0;
    while ((used<1024) & (done==0)) {
        count=read_bytes(buffer+used,1024-used);
        if (count==(0-1)) { return 10; }
        if (count==0) { done=1; } else { used=used+count; }
    }
    if (used==1024) {
        count=read_bytes(extra,1);
        if (count!=0) { return 14; }
    }
    if (used==0) { return 11; }
    if (reqok(buffer,used)!=0) { out=put200(buffer); } else { out=put404(buffer); }
    if (write_bytes(buffer,out)!=out) { return 15; }
    return 0;
}

int getbyte(char *addr) { return *addr; }
int putbyte(char *addr, int value) { *addr=value; return 0; }

int reqok(char *addr, int len) {
    if (len < 23) {
        return 0;
    }
    if (1024 < len) {
        return 0;
    }
    if (getbyte(addr + 0) != 71) {
        return 0;
    }
    if (getbyte(addr + 1) != 69) {
        return 0;
    }
    if (getbyte(addr + 2) != 84) {
        return 0;
    }
    if (getbyte(addr + 3) != 32) {
        return 0;
    }
    if (getbyte(addr + 4) != 47) {
        return 0;
    }
    if (getbyte(addr + 5) != 97) {
        return 0;
    }
    if (getbyte(addr + 6) != 108) {
        return 0;
    }
    if (getbyte(addr + 7) != 105) {
        return 0;
    }
    if (getbyte(addr + 8) != 118) {
        return 0;
    }
    if (getbyte(addr + 9) != 101) {
        return 0;
    }
    if (getbyte(addr + 10) != 32) {
        return 0;
    }
    if (getbyte(addr + 11) != 72) {
        return 0;
    }
    if (getbyte(addr + 12) != 84) {
        return 0;
    }
    if (getbyte(addr + 13) != 84) {
        return 0;
    }
    if (getbyte(addr + 14) != 80) {
        return 0;
    }
    if (getbyte(addr + 15) != 47) {
        return 0;
    }
    if (getbyte(addr + 16) != 49) {
        return 0;
    }
    if (getbyte(addr + 17) != 46) {
        return 0;
    }
    if (getbyte(addr + 18) != 49) {
        return 0;
    }
    if (getbyte(addr + 19) != 13) {
        return 0;
    }
    if (getbyte(addr + 20) != 10) {
        return 0;
    }
    if (getbyte(addr + len - 4) != 13) {
        return 0;
    }
    if (getbyte(addr + len - 3) != 10) {
        return 0;
    }
    if (getbyte(addr + len - 2) != 13) {
        return 0;
    }
    if (getbyte(addr + len - 1) != 10) {
        return 0;
    }
    return 1;
}

int put200(char *addr) {
    putbyte(addr + 0, 72);
    putbyte(addr + 1, 84);
    putbyte(addr + 2, 84);
    putbyte(addr + 3, 80);
    putbyte(addr + 4, 47);
    putbyte(addr + 5, 49);
    putbyte(addr + 6, 46);
    putbyte(addr + 7, 49);
    putbyte(addr + 8, 32);
    putbyte(addr + 9, 50);
    putbyte(addr + 10, 48);
    putbyte(addr + 11, 48);
    putbyte(addr + 12, 32);
    putbyte(addr + 13, 79);
    putbyte(addr + 14, 75);
    putbyte(addr + 15, 13);
    putbyte(addr + 16, 10);
    putbyte(addr + 17, 67);
    putbyte(addr + 18, 111);
    putbyte(addr + 19, 110);
    putbyte(addr + 20, 116);
    putbyte(addr + 21, 101);
    putbyte(addr + 22, 110);
    putbyte(addr + 23, 116);
    putbyte(addr + 24, 45);
    putbyte(addr + 25, 76);
    putbyte(addr + 26, 101);
    putbyte(addr + 27, 110);
    putbyte(addr + 28, 103);
    putbyte(addr + 29, 116);
    putbyte(addr + 30, 104);
    putbyte(addr + 31, 58);
    putbyte(addr + 32, 32);
    putbyte(addr + 33, 49);
    putbyte(addr + 34, 54);
    putbyte(addr + 35, 13);
    putbyte(addr + 36, 10);
    putbyte(addr + 37, 67);
    putbyte(addr + 38, 111);
    putbyte(addr + 39, 110);
    putbyte(addr + 40, 110);
    putbyte(addr + 41, 101);
    putbyte(addr + 42, 99);
    putbyte(addr + 43, 116);
    putbyte(addr + 44, 105);
    putbyte(addr + 45, 111);
    putbyte(addr + 46, 110);
    putbyte(addr + 47, 58);
    putbyte(addr + 48, 32);
    putbyte(addr + 49, 99);
    putbyte(addr + 50, 108);
    putbyte(addr + 51, 111);
    putbyte(addr + 52, 115);
    putbyte(addr + 53, 101);
    putbyte(addr + 54, 13);
    putbyte(addr + 55, 10);
    putbyte(addr + 56, 13);
    putbyte(addr + 57, 10);
    putbyte(addr + 58, 65);
    putbyte(addr + 59, 110);
    putbyte(addr + 60, 107);
    putbyte(addr + 61, 97);
    putbyte(addr + 62, 54);
    putbyte(addr + 63, 52);
    putbyte(addr + 64, 32);
    putbyte(addr + 65, 105);
    putbyte(addr + 66, 115);
    putbyte(addr + 67, 32);
    putbyte(addr + 68, 97);
    putbyte(addr + 69, 108);
    putbyte(addr + 70, 105);
    putbyte(addr + 71, 118);
    putbyte(addr + 72, 101);
    putbyte(addr + 73, 46);
    return 74;
}

int put404(char *addr) {
    putbyte(addr + 0, 72);
    putbyte(addr + 1, 84);
    putbyte(addr + 2, 84);
    putbyte(addr + 3, 80);
    putbyte(addr + 4, 47);
    putbyte(addr + 5, 49);
    putbyte(addr + 6, 46);
    putbyte(addr + 7, 49);
    putbyte(addr + 8, 32);
    putbyte(addr + 9, 52);
    putbyte(addr + 10, 48);
    putbyte(addr + 11, 52);
    putbyte(addr + 12, 32);
    putbyte(addr + 13, 78);
    putbyte(addr + 14, 111);
    putbyte(addr + 15, 116);
    putbyte(addr + 16, 32);
    putbyte(addr + 17, 70);
    putbyte(addr + 18, 111);
    putbyte(addr + 19, 117);
    putbyte(addr + 20, 110);
    putbyte(addr + 21, 100);
    putbyte(addr + 22, 13);
    putbyte(addr + 23, 10);
    putbyte(addr + 24, 67);
    putbyte(addr + 25, 111);
    putbyte(addr + 26, 110);
    putbyte(addr + 27, 116);
    putbyte(addr + 28, 101);
    putbyte(addr + 29, 110);
    putbyte(addr + 30, 116);
    putbyte(addr + 31, 45);
    putbyte(addr + 32, 76);
    putbyte(addr + 33, 101);
    putbyte(addr + 34, 110);
    putbyte(addr + 35, 103);
    putbyte(addr + 36, 116);
    putbyte(addr + 37, 104);
    putbyte(addr + 38, 58);
    putbyte(addr + 39, 32);
    putbyte(addr + 40, 48);
    putbyte(addr + 41, 13);
    putbyte(addr + 42, 10);
    putbyte(addr + 43, 67);
    putbyte(addr + 44, 111);
    putbyte(addr + 45, 110);
    putbyte(addr + 46, 110);
    putbyte(addr + 47, 101);
    putbyte(addr + 48, 99);
    putbyte(addr + 49, 116);
    putbyte(addr + 50, 105);
    putbyte(addr + 51, 111);
    putbyte(addr + 52, 110);
    putbyte(addr + 53, 58);
    putbyte(addr + 54, 32);
    putbyte(addr + 55, 99);
    putbyte(addr + 56, 108);
    putbyte(addr + 57, 111);
    putbyte(addr + 58, 115);
    putbyte(addr + 59, 101);
    putbyte(addr + 60, 13);
    putbyte(addr + 61, 10);
    putbyte(addr + 62, 13);
    putbyte(addr + 63, 10);
    return 64;
}

