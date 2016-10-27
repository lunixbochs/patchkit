from capstone.x86_const import *
import random

def patch(pt):
    def is_sp_arith(ins):
        dst, src = ins.operands
        return dst.type == X86_OP_REG and src.type == X86_OP_IMM and dst.reg in (X86_REG_RSP, X86_REG_ESP)

    for func in pt.funcs():
        # initial adjustment, may be reduced so instruction size stays unchanged
        # remains unchanged
        adj = random.randrange(4, 128, 4)
        # total amount adjusted
        total = 0
        dis = func.dis()

        # sanity: check function fingerprint (1+ SUBs, ends with either a single ADD or a LEAVE)
        sub_total = 0
        add_total = 0

        subs = 0
        adds = 0
        leave = False
        good = True
        for ins in dis:
            if ins.id == X86_INS_SUB and is_sp_arith(ins):
                subs += 1
                sub_total += ins.operands[1].imm
                if adds:
                    good = False
                    break

            if ins.id == X86_INS_ADD and is_sp_arith(ins):
                adds += 1
                add_total += ins.operands[1].imm

            if ins.id == X86_INS_LEAVE:
                leave = True

        if not (good and subs and (adds == 1 or leave) and sub_total == add_total):
            if subs:
                pt.warn('Fingerprint failed.')
            continue

        for ins in dis:
            if ins.id == X86_INS_SUB:
                dst, src = ins.operands
                if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                    if dst.reg in (X86_REG_RSP, X86_REG_ESP):
                        # ensure our adjustment fits inside current instr
                        tmp = adj
                        while tmp > 0:
                            asm = 'sub %s, 0x%x' % (ins.reg_name(dst.reg), src.imm+tmp)
                            patch = pt.asm(asm, ins.address)
                            if len(patch) > ins.size:
                                tmp -= 4
                            else:
                                break
                        if tmp < 0:
                            pt.warn('[0x%x] failed to adjust' % ins.address)
                            continue

                        total += tmp
                        patched_sub = True
                        pt.patch(ins.address, asm=asm)

        if patched_sub:
            for ins in dis:
                # use previously adjusted size to readjust
                if ins.id == X86_INS_ADD and total > 0:
                    dst, src = ins.operands
                    if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                        if dst.reg in (X86_REG_RSP, X86_REG_ESP):
                            asm = 'add %s, 0x%x' % (ins.reg_name(dst.reg), src.imm+total)
                            pt.patch(ins.address, asm=asm)
