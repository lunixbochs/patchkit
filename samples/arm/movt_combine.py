from capstone.arm_const import *

def patch(pt):
    for func in pt.funcs():
        dis = func.dis()
        movs = {}

        out = list(dis)
        for i, ins in enumerate(dis):
            # remember the last `mov dst, #imm`
            if ins.id in (ARM_INS_MOV, ARM_INS_MOVS, ARM_INS_MOVW):
                # ignore barrel shifter :(
                if len(ins.operands) == 3:
                    continue
                dst, src = ins.operands
                if dst.type == ARM_OP_REG:
                    movs[dst.reg] = (i, ins)

            # possibly coalesce this movt to the previous mov
            elif ins.id == ARM_INS_MOVT:
                dst, src = ins.operands
                if dst.type == ARM_OP_REG and src.type == ARM_OP_IMM:
                    ppos, prev = movs.get(dst.reg, [0, None])
                    if not prev or ins.address == prev.address + len(prev.bytes):
                        continue
                    if ins.address - prev.address > 16:
                        continue

                    out.pop(i)
                    out.insert(ppos + 1, ins)

            # pop reg's mov if another instruction might use reg as dst
            elif len(ins.operands) > 0:
                op = ins.operands[0]
                if op.type == ARM_OP_REG:
                    movs.pop(op.reg, None)

        if out != dis:
            pt.patch(dis[0].address, raw=''.join(str(ins.bytes) for ins in out), is_asm=True)
