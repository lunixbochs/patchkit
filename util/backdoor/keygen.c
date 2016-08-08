#include <stdio.h>
#include <stdint.h>
#include "tweetnacl.h"

void _cdump(uint8_t *msg, uint64_t len) {
    printf("{");
    for (int i = 0; i < len; i++) {
        printf("%d", msg[i]);
        if (i < len - 1) printf(", ");
    }
    printf("};\n");
}
#define cdump(c) _cdump(c, sizeof(c))

int main() {
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];

    crypto_sign_keypair(pk, sk);

    printf("uint8_t pubkey[] = ");
    cdump(pk);
    printf("uint8_t privkey[] = ");
    cdump(sk);
}
