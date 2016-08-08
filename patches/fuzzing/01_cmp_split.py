import struct
from capstone.x86_const import *

def _decompose(ins, jmps):
    invert = {
        'jne': 'je',
        'je': 'jne',
    }
    a, b = ins.operands
    name = ins.reg_name(a.mem.base)
    asm = []
    # TODO: this assumes dword
    # This might not generate instrumentable branches for qemu-user. I haven't tested if these properly count as separate basic blocks in QEMU.
    for i, byte in enumerate(struct.pack('<I', b.imm)):
        asm.append('local_%d: cmp byte ptr [%s + %d + %d * %d], 0x%x' % (i, name, a.mem.disp + i, a.mem.scale, a.mem.index, ord(byte)))
        for jmp in jmps:
            asm.append('%s _ret' % (invert[jmp.mnemonic]))
            asm.append('jmp local_%d' % (i + 1))
    asm.append('local_4:\n_ret: ret')
    print '\n'.join(asm)
    return '\n'.join(asm)

# try to split word-wise cmp into byte-wise cmp so AFL can path through it
def patch(pt):
    for func in pt.funcs():
        cmps = []
        cur = None
        for ins in func.dis():
            if ins.id == X86_INS_CMP:
                a, b = ins.operands
                if a.type == X86_OP_MEM and b.type == X86_OP_IMM:
                    if b.imm > 0xff:
                        cmps.append((ins, []))
                        cur = cmps[-1]
            elif cur is not None:
                if X86_REG_EFLAGS in ins.regs_write:
                    cur = None
                elif ins.id in (X86_INS_JE, X86_INS_JNE):
                    cur[-1].append(ins)

        for cmp, jmps in cmps:
            if len(jmps) != 1:
                continue
            pt.debug('[*] Splitting CMP')
            pt.debug(dis=[cmp] + jmps)
            addr = pt.inject(asm=_decompose(cmp, jmps))

            call = pt.asm(pt.arch.call(addr), addr=cmp.address)
            call += pt.asm(pt.arch.nop() * (len(cmp.bytes) - len(call)))
            pt.patch(cmp.address, raw=call, is_asm=True)
