int visit(char *caller, int expected);
int touch(char *caller);
int main() {
    char parent[4];
    if (*(parent+0) != 0) { return syscall(0, 1, 0, 0); }
    *(parent+0) = 41;
    int result = visit(parent, 41);
    if (result != 0) { return syscall(0, result, 0, 0); }
    if (*(parent+0) != 42) { return syscall(0, 2, 0, 0); }
    result = visit(parent, 42);
    if (result != 0) { return syscall(0, result, 0, 0); }
    if (*(parent+0) != 43) { return syscall(0, 3, 0, 0); }
    return syscall(0, 0, 0, 0);
}
int visit(char *caller, int expected) {
    char secret[48];
    int marker;
    char *empty;
    int i = 0;
    if (marker != 0) { return 10; }
    if (empty != 0) { return 11; }
    while (i < 48) {
        if (*(secret+i) != 0) { return 12; }
        *(secret+i) = i + 1;
        i = i + 1;
    }
    if (*(caller+0) != expected) { return 13; }
    int result = touch(caller);
    if (result != 0) { return result; }
    if (*(caller+0) != expected + 1) { return 14; }
    i = 0;
    while (i < 48) {
        if (*(secret+i) != i + 1) { return 15; }
        i = i + 1;
    }
    marker = 99;
    empty = caller;
    return 0;
}
int touch(char *caller) {
    char spare[8];
    int i = 0;
    while (i < 8) {
        if (*(spare+i) != 0) { return 16; }
        i = i + 1;
    }
    *(caller+0) = *(caller+0) + 1;
    return 0;
}
