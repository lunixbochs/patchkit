#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tweetnacl.h"
#include "privkey.h"

extern void randombytes(uint8_t *buf, uint64_t len);
#define MLEN 8

int verify(uint8_t *sm, uint64_t smlen) {
    uint8_t *m = malloc(smlen);
    uint64_t mlen;
    int ret = crypto_sign_open(m, &mlen, sm, smlen, pubkey);
    free(m);
    return ret;
}

void sign(uint8_t *msg, uint64_t mlen, uint8_t **sm, uint64_t *smlen) {
    *sm = malloc(mlen + crypto_sign_BYTES);
    crypto_sign(*sm, smlen, msg, mlen, privkey);
}

int main(int argc, char **argv) {
    uint8_t *sm;
    uint64_t smlen;
    if (argc == 2) {
        char *hex = argv[1];
        int hexlen = strlen(hex);
        if (hexlen % 2) {
            printf("odd hex?\n");
            return 1;
        }
        uint64_t mlen = hexlen / 2;
        uint8_t *msg = malloc(mlen);

        for (uint64_t i = 0; i < mlen; i++) {
            sscanf(hex, "%2hhx", &msg[i]);
            hex += 2;
        }
        sign(msg, mlen, &sm, &smlen);

        for (int i = 0; i < smlen; i++) {
            printf("%02x", sm[i]);
        }
        printf("\n");
    } else {
        uint8_t msg[MLEN];
        randombytes(msg, MLEN);

        sign(msg, MLEN, &sm, &smlen);

        printf("msg = ");
        for (int i = 0; i < MLEN; i++) {
            printf("%02x", msg[i]);
        }
        printf("\n");

        printf("sig = ");
        for (int i = 0; i < smlen; i++) {
            printf("%02x", sm[i]);
        }
        printf("\n");

        printf("verify = %d\n", verify(sm, smlen));
    }
}
