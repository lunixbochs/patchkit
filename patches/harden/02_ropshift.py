from capstone.x86_const import *
from collections import OrderedDict
import random

def patch(pt):
    for func in pt.funcs():
        dis = func.dis()
        pops = OrderedDict()
        first = True
        for ins in reversed(dis):
            if ins.id in (X86_INS_RET, X86_INS_LEAVE):
                continue
            elif ins.id == X86_INS_POP:
                reg = ins.operands[0].reg
                # ignore a leading ebp pop so we don't screw up the frame restore
                if not (first and reg == X86_REG_EBP):
                    pops[reg] = ins

                first = False
            else:
                break

        if len(pops) == 1:
            ins = pops.values()[0]
            name = ins.reg_name(ins.operands[0].reg)
            pt.warn('Only one POP, function not hardened (reg %s)' % (name))
        elif len(pops) > 1:
            # TODO: bail on pc-relative loads? probably not a problem for CGC as it's not PIE
            pt.info('[*] Hardening (%d) pops.' % (len(pops)))
            remain = set(pops.keys())
            pushes = OrderedDict()
            extra = []
            for ins in dis:
                if ins.id == X86_INS_PUSH:
                    reg = ins.operands[0].reg
                    if reg in remain:
                        remain.remove(reg)
                        pushes[reg] = ins
                        continue
                if not remain:
                    break
                extra.append(ins)

            regs = list(pops.keys())
            new = list(regs)
            while new[-1] == regs[-1]:
                random.shuffle(new)

            head = [pushes[reg] for reg in new] + extra
            head_addr = min(ins.address for ins in head)
            head_data = ''.join(str(ins.bytes) for ins in head)

            tail = [pops[reg] for reg in reversed(new)]
            tail_addr = min(ins.address for ins in tail)
            tail_data = ''.join(str(ins.bytes) for ins in tail)

            pt.patch(head_addr, raw=head_data, is_asm=True)
            pt.patch(tail_addr, raw=tail_data, is_asm=True)
