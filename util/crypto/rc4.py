import os

def rc4(key):
    key = map(ord, key)
    # ksa
    S = range(256)
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # prga
    i = j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        yield S[t]

def rc4_decrypt_template(key, addr, size):
    # xor key so they can't just pull it out of memory
    key_otp = os.urandom(len(key))
    key = ''.join([chr(ord(c) ^ ord(key_otp[i])) for i, c in enumerate(key)])
    str2c = lambda x: ', '.join(map(str, map(ord, x)))

    code = r'''
    void _start() {
        uint8_t state[256];
        uint8_t rc4_key[] = {%s};
        uint8_t rc4_otp[] = {%s};
        int keylen = %d;
        for (int i = 0; i < keylen; i++) {
            rc4_key[i] ^= rc4_otp[i];
        }
        ksa(state, rc4_key, keylen);
        rc4(state, (unsigned char *)%d, %d);
    }
    ''' % (str2c(key), str2c(key_otp), len(key), addr, size)
    return code
