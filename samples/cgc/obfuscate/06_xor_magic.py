import struct
from capstone.x86_const import *

from util.patch.syscall import find_syscall_funcs

def patch(pt):
    for prog in pt.elf.progs:
        if prog.isload and prog.offset == 0:
            magic_addr = prog.vaddr

    receive = pt.resolve('receive')
    for ins in pt.dis(receive, size=1024):
        if ins.id == X86_INS_INT:
            break
    else:
        pt.error('Could not find SYS_receive')
        return

    break_addr = ins.address - 1
    magic = struct.unpack('<I', pt.elf.read(magic_addr, 4))[0]
    data = struct.pack('<I', struct.unpack('<I', pt.elf.read(break_addr, 4))[0] ^ magic)
    pt.make_writable(break_addr)

    pt.patch(break_addr, raw=data)

    pt.hook(pt.entry, pt.inject(asm=r'''
    mov eax, [0x%x]
    xor [0x%x], eax
    ret
    ''' % (magic_addr, break_addr)))
