import os
from util.crypto.rc4 import rc4, rc4_decrypt_template

rc4_key = os.urandom(16)

def rc4_encrypt(pt):
    xor = rc4(rc4_key)

    seg = pt.binary.patch
    data = pt.elf.read(seg.vaddr, seg.memsz)
    for i in xrange(len(data)):
        data[i] ^= xor.next()
    pt.patch(seg.vaddr, raw=data)

def inject_rc4_decrypt(pt):
    seg = pt.binary.patch
    if seg.memsz == 0:
        pt.error('Skipping inject: patch segment is empty.')
        return

    pt.make_writable(seg.vaddr)
    code = rc4_decrypt_template(rc4_key, seg.vaddr, seg.memsz)
    addr = pt.inject(c=code)
    pt.hook(pt.entry, addr, first=True)
