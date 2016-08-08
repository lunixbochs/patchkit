import random
import re

from util.patch.dis import IR, Ins, Imm, Reg, Mem

op_reg = re.compile(r'^(?P<op>\w+) (?P<reg>\w+), (?P<val>0x[0-9a-f]+|\d+)')

def _int(val):
    if val.startswith('0x'):
        return int(val, 16)
    return int(val)

def _search(ir, ins, skip=(), reverse=False):
    if reverse:
        space = reversed(list(enumerate(ir)))
    else:
        space = enumerate(ir)
    for i, cmp in space:
        if ins in skip:
            continue
        if ins == cmp:
            return i, cmp
    raise ValueError('%s not found in IR' % ins)

def _scan(ir, window):
    for i in xrange(len(ir)):
        if ir[i:i+len(window)] == window:
            return i
    return None

def _asm(pt, ir):
    stack_chk_fail = pt.resolve('stack_chk_fail')
    if len(ir) >= 4:
        # head_match = [Ins('push', Reg('ebp')), Ins('mov', Reg('ebp'), Reg('esp'))]
        head_match = pt.ir('push ebp; mov ebp, esp')
        tail_match = pt.ir('pop ebp; ret')
        tail_pos = _scan(ir, tail_match)
        if ir[:2] == head_match and tail_pos is not None:
            try:
                subi, sub = _search(ir[2:], Ins('sub', Reg('esp'), Imm(any=True)), skip=[Ins('push', any=True)])
                subi += 2
                addi, add = _search(ir[:tail_pos], Ins('add', Reg('esp'), Imm(any=True)), skip=[Ins('pop', any=True)], reverse=True)
            except ValueError:
                return
            if sub.ops[1] > add.ops[1]:
                return

            for ins in ir:
                if not isinstance(ins, Ins):
                    continue
                for op in ins.ops:
                    if isinstance(op, Mem) and op.base == 'ebp' and op.off < 0:
                        op.off -= 4

            before = ir[:subi]
            mid = ir[subi:addi]
            after = ir[addi:]
            addr = pt.inject(raw="ABCD", target='nx')

            pt.hook(pt.entry, pt.inject(c=r"""
            void gen() {
                random((void*) %d, 4, 0);
            }
            """ % addr))

            # TODO: runtime dynamic cookies
            cookie = random.randint(1, 0xffffffff)
            ir = before + pt.ir('''
                mov eax, dword ptr [%d]
                mov [ebp - 4], eax
            ''' % addr) + mid + pt.ir('''
                mov ebp, [ebp - 4]
                cmp ebp, dword ptr [%d]
                jne %d
            ''' % (addr, stack_chk_fail)) + after

    return ir

def patch(pt):
    pt.warn('This patch depends on the ASLR patch.')
    pt.binary.onasm(_asm)
