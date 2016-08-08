import os
from core import elfutil
from util.crypto.xor import xor_mem

def xor_patches(pt):
    for prog in pt.elf.progs:
        if elfutil.is_load(prog) and prog.offset == 0:
            xor_mem(pt, prog.vaddr, prog.memsz, ord(os.urandom(1)))
            break
