#include <stdint.h>
#include <stdio.h>

void randombytes(uint8_t *buf, uint64_t len) {
    FILE *f = fopen("/dev/urandom", "r");
    fread(buf, len, 1, f);
    fclose(f);
}
