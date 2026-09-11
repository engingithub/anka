void putchar(int c);

void puts(char *s) {
    while (*s) {
        putchar(*s);
        s = s + 1;
    }
}

int main() {
    puts("Hello from AnkaCC!\n");
    return 0;
}
