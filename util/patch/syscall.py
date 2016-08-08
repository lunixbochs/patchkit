from capstone.x86_const import *

from dis import irdis, IR, Ins, Imm, Reg, Mem

syscall_table = {
    1: '_terminate',
    2: 'transmit',
    3: 'receive',
    4: 'fdwait',
    5: 'allocate',
    6: 'deallocate',
    7: 'random',
}

def find_syscall_funcs(pt):
    for func in pt.funcs():
        ir = irdis(func.dis())
        sysnum = None
        sysname = None
        int80 = None
        bad = []
        for ins in ir:
            if ins == Ins('mov', Reg('eax'), Imm(any=True)) and not sysnum:
                # imm to reg is safe
                sysnum = ins.src.val
                sysname = syscall_table.get(sysnum)
            elif ins == pt.ir('mov ebp, esp'):
                # some syscall functions do this
                pass
            elif ins == Ins('push', Reg(any=True)) or ins == Ins('pop', Reg(any=True)) or ins == 'ret':
                # push/pop/ret is safe
                pass
            elif ins == Ins('int', Imm(0x80)) and not int80:
                # of course it'll have an int 0x80
                int80 = ins
            elif ins == Ins('mov', Reg(any=True), Mem(any=True)) and ins.src.base == 'esp':
                # reg = mem is safe if it's stack-relative
                pass
            else:
                bad.append(ins) # assume unsafe

        if int80 is not None:
            if sysname is None or sysnum is None:
                pt.debug('[*] Syscall function skipped (unknown num: %s)' % sysnum)
            if bad:
                pt.debug('[*] Syscall function was marked as bad:')
                pt.debug(ir.asm())
                pt.debug('[*] Offending instructions:')
                # TODO: make this pt.debug(dis=bad)?
                pt.debug(IR(bad).asm())
                continue

            yield (func, int80, sysname, sysnum)
