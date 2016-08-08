int memcmp(const void *p1, const void *p2, size_t len) {
    unsigned char *c1 = (unsigned char *)p1, *c2 = (unsigned char *)p2;
    for (size_t i = 0; i < len; i++) {
        if (c1[i] < c2[i]) {
            return -1;
        } else if (c1[i] > c2[i]) {
            return 1;
        }
    }
    return 0;
}

void *memchr(const void *ptr, int c, size_t n) {
    unsigned const char *cptr = ptr;
    for (size_t i = 0; i < n; i++) {
        if (cptr[i] == c) {
            return (void *)cptr+i;
        }
    }
    return 0;
}

void *memcpy(void *dst, const void *src, size_t len) {
    char *cdst = dst;
    const char *csrc = src;
    for (size_t i = 0; i < len; i++) {
        *cdst++ = *csrc++;
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t len) {
    // TODO: handle overlapping memory
    return memcpy(dst, src, len);
}

void *memset(void *ptr, int val, size_t len) {
    unsigned char *cptr = ptr, c = val;
    for (size_t i = 0; i < len; i++) {
        *cptr++ = c;
    }
    return ptr;
}
