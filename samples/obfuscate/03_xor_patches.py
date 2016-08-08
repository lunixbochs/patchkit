import os
from util.crypto.xor import xor_mem

def xor_patches(pt):
    seg = pt.binary.patch
    xor_mem(pt, seg.vaddr, seg.memsz, ord(os.urandom(1)))
