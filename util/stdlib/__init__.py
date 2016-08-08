import os
import re

from util import read

__all__ = ['declare']

header_names = ['stdlib/types.h', 'stdlib/defines.h', 'stdlib/syscall.h']
headers = '\n'.join(map(read, header_names))

def declare(linker):
    if not '_terminate' in linker:
        linker.declare(headers=headers)
        linker.autodecl(read('stdlib/libc.c'))
        linker.autodecl(read('stdlib/syscalls.c'))
        linker.autodecl(read('stdlib/ctype.c'))
        linker.autodecl(read('stdlib/string.c'))
        linker.autodecl(read('stdlib/chk.c'))
        linker.declare(headers='#include <stdarg.h>')
        linker.autodecl(read('stdlib/io.c'))
        linker.declare(symbols={
            'itoa': 'char *itoa(unsigned int i, int base)',
            'atoi': 'int atoi(char *str)',
        }, source=read('stdlib/num.c'))
