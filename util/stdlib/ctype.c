int digittoint(int c) {
    if (isxdigit(c)) {
        if (isdigit(c)) return c - 0x30;
        else            return toupper(c) - 0x37;
    } else {
        return 0;
    }
}

int isalnum(int c) {
    return isalpha(c) || isdigit(c);
}

int isalpha(int c) {
    return islower(c) || isupper(c);
}

int isascii(int c) {
    return c >= 0 && c <= 127;
}

int iscntrl(int c) {
    return (c >= 0 && c <= 0x1f) ||
            c == 0x7f;
}

int isdigit(int c) {
    return c >= '0' && c <= '9';
}

int isgraph(int c) {
    return c >= 0x21 && c <= 0x7e;
}

int ishexnumber(int c) {
    return isxdigit(c);
}

int islower(int c) {
    return c >= 'a' && c <= 'z';
}

int isnumber(int c) {
    return isdigit(c);
}

int isprint(int c) {
    return c >= 0x20 && c <= 0x7e;
}

int ispunct(int c) {
    return (c >= 0x21 && c <= 0x2f) ||
           (c >= 0x3a && c <= 0x3f) ||
            c == '@' ||
           (c >= 0x5b && c <= 0x60) ||
           (c >= 0x7b && c <= 0x7e);
}

int isrune(int c) {
    return isascii(c);
}

int isspace(int c) {
    return c == '\t' ||
           c == '\n' ||
           c == '\v' ||
           c == '\f' ||
           c == '\r' ||
           c == ' ';
}

int isupper(int c) {
    return c >= 'A' && c <= 'Z';
}

int isxdigit(int c) {
    return isdigit(c) ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

int toascii(int c) {
    return c & 0x7f;
}

int tolower(int c) {
    return isupper(c) ? (c + 0x20) : c;
}

int toupper(int c) {
    return islower(c) ? (c - 0x20) : c;
}
