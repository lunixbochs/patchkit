import binascii
import re
from capstone import *
from keystone import *

"""
from keystone import *
ks = Ks(KS_ARCH_X86, KS_MODE_64)


"""
class Arch:
    def __init__(self):
        self.cs = Cs(*self._cs)
        self.cs.detail = True
        self.ks = Ks(*self._ks)

    def asm(self, asm, addr=0, att_syntax=False):
        if not asm:
            return ''
        # asm start label for use with relative offsets
        asm = '_PKST_:;\n' + asm

        saved = self.ks.syntax
        if att_syntax:
            self.ks.syntax = KS_OPT_SYNTAX_ATT

        #Keystone doesn't support this instruction
        asm = asm.replace('endbr64', '')

        newasm = ''
        for line in asm.split('\n'):
            if '.long' in line:
                x = line.split('\t')
                if '-' in x[1]:
                    vals = x[1].split('-')
                    new_line = f'{x[0]}\t 0x{vals[0].strip()} - 0x{vals[1].strip()} \n'
                    newasm += new_line
                    continue
            if re.match(r'^\d+:', line):
                continue
            newasm += f'{line}\n'

        #print('------------')
        #import keystone
        #for line in newasm.split('\n'):
        #    print(f'checking line: {line}')
        #    try:
        #        tmp, _ = self.ks.asm(line)
        #        print(tmp)
        #    except keystone.keystone.KsError as e:
        #        print(e)
        #print(newasm)

        # Problematic instructions:
        # https://github.com/keystone-engine/keystone/issues/546
        # leal     -48(%rax,%rdx), %eax
        # movb     (%rcx,%rdx), %dl
        tmp, _ = self.ks.asm(newasm, addr=addr)
        self.ks.syntax = saved
        return ''.join(map(chr, tmp)).encode('latin')

    def dis(self, raw, addr=0):
        if isinstance(raw, bytearray):
            return list(self.cs.disasm(raw, addr))
        elif isinstance(raw, str):
            return list(self.cs.disasm((raw.encode()), addr))
        else:
            return list(self.cs.disasm(raw, addr))

    def jmp(self, dst):
        raise NotImplementedError

    def call(self, dst):
        raise NotImplementedError

    def ret(self):
        raise NotImplementedError

    def nop(self):
        raise NotImplementedError

class x86(Arch):
    _cs = CS_ARCH_X86, CS_MODE_32
    _ks = KS_ARCH_X86, KS_MODE_32

    def call(self, dst): return 'call 0x%x;' % dst
    def jmp(self, dst):
        print(f'debugging jmp: dst:{dst}')
        if isinstance(dst, str):
            return f'jmp {dst}'
        else:
            return 'jmp 0x%x;' % dst

    def ret(self): return 'ret;'
    def nop(self): return 'nop;'

    # memcpy should be pc-relative
    # dst and src are offsets from the _PKST_ label
    def memcpy(self, dst, src, size):
        return '''
        push edi
        push esi
        push ecx

        call ref
        ref: pop edi
        sub edi, ref - _PKST_
        mov esi, edi

        add edi, %d
        add esi, %d
        mov ecx, %d

        rep movsb

        pop ecx
        pop esi
        pop edi
        ''' % (dst, src, size)

class x86_64(x86):
    _cs = CS_ARCH_X86, CS_MODE_64
    _ks = KS_ARCH_X86, KS_MODE_64

    def memcpy(self, dst, src, size):
        return '''
        push rdi
        push rsi
        push rcx

        lea rdi, [rip - _PKST_ + %d]
        lea rsi, [rip - _PKST_ + %d]
        mov rcx, %d

        rep movsb

        pop rcx
        pop rsi
        pop rdi
        ''' % (dst, src, size)

class arm(Arch):
    _cs = CS_ARCH_ARM, CS_MODE_ARM
    _ks = KS_ARCH_ARM, KS_MODE_ARM
