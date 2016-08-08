static const char *digits = "0123456789abcdef";

char *itoa(unsigned int i, int base) {
    if (base < 0 || base > 16) {
        return "(invalid base)";
    }
    static char buf[11] = {0};
    char *pos = &buf[10];
    do {
        *--pos = (char)digits[i % base];
        i /= base;
    } while (i > 0);
    return pos;
}

int atoi(char *str) {
    int i = 0;
    char c;
    while ((c = *str++) != '\0') {
        if (c >= '0' && c <= '9') {
            i *= 10;
            i += (c - 48);
        }
    }
    return i;
}
