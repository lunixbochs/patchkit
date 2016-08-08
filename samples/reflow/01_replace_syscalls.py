from capstone.x86_const import *
from collections import OrderedDict

from util.patch.syscall import find_syscall_funcs

def patch(pt):
    for func, syscall, sysname, sysnum in find_syscall_funcs(pt):
        pt.info('[*] Moving syscall %d (%s) function.' % (sysnum, sysname))
        data = func.read()
        func.nop()

        addr = pt.resolve(sysname)
        pt.patch(func.addr, jmp=addr)
