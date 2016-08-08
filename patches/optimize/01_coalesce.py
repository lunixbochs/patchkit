# combine useless adjacent instructions
# like:
# sub esp, 8
# sub esp, 8
# into:
# sub esp, 16

from util.patch.dis import Label, Ins, Imm, Reg, Mem

def _optimize(pt, ir):
    i = 0
    add = Ins('add', Reg(any=True), Imm(any=True))
    sub = Ins('sub', Reg(any=True), Imm(any=True))
    total = 0
    while i < len(ir) - 1:
        ins, nins = ir[i:i+2]
        if (ins, nins) == (add, add) or (ins, nins) == (sub, sub):
            if ins.ops[0] == nins.ops[0]:
                pt.debug('Combining: %s <- %s' % (ins, nins))
                total += 1
                ins.ops[1].val += nins.ops[1].val
                ir.pop(i + 1)
                continue
        i += 1
    if total:
        pt.info('Combined %d instructions.' % total)
    return ir

def defer(pt):
    pt.binary.onasm(_optimize)
