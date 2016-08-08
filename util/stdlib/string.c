size_t strlen(const char *s1) {
    size_t i = 0;
    do i++; while (s1[i] != '\0');
    return i;
}

void *strdup(const char *s1) {
    void *out = malloc(strlen(s1));
    strcpy(out, s1);
    return out;
}

int strcmp(const char *s1, const char *s2) {
    return strncmp(s1, s2, SIZE_MAX);
}

int strncmp(const char *s1, const char *s2, size_t n) {
    for (size_t pos = 0; pos < n; pos++) {
        char c1 = *s1++;
        char c2 = *s2++;
        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
        if (c1 == 0 || c2 == 0) break;
    }
    return 0;
}

char *strcpy(char *dst, const char *src) {
    return strncpy(dst, src, SIZE_MAX);
}

char *strncpy(char *dst, const char *src, size_t n) {
    size_t i = 0;
    do dst[i] = *src; while (*src++ != '\0' && i++ < n);
    return dst;
}

char *strcat(char *s1, const char *s2) {
    return strncat(s1, s2, SIZE_MAX);
}

char *strncat(char *s1, const char *s2, size_t n) {
    strncpy(s1 + strlen(s1), s2, n);
    return s1;
}

char *strupr(char *s1) {
    do *s1 = toupper(*s1); while (*s1++ != '\0');
    return s1;
}
