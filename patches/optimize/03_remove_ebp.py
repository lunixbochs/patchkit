# optimize EBP out of a function
# 1. fingerprint if a function has the standard header/footer
# 2. decide if a function otherwise looks "safe"
# 3. remove all references to EBP
# 4. calculate stack offsets at every instruction and replace any ebp lookups with the stack offset

from util.patch.dis import IR, Label, Ins, Mem, Reg, Imm

def _scan(ir, window):
    for i in xrange(len(ir)):
        if ir[i:i+len(window)] == window:
            return i
    return None

def _optimize(pt, ir):
    # TODO: considering functions with internal jumps too scary for now (because I don't have a helper to follow control flow yet)
    for ins in ir:
        if isinstance(ins, Label):
            return

    add_esp = Ins('add', Reg('esp'), Imm(any=True))
    sub_esp = Ins('sub', Reg('esp'), Imm(any=True))

    # make sure ESP is only directly used for ADD (esp, imm); SUB; MOV reg, esp
    for ins in ir:
        if ins == add_esp or ins == sub_esp:
            continue
        if ins == Ins('mov', Reg(any=True), Reg('esp')):
            continue
        for op in ins.ops:
            if op == 'esp':
                return

    # TODO: put "standard header/footer" fingerprint helper in util.patch?
    head_match = pt.ir('push ebp; mov ebp, esp')
    tail_match = pt.ir('pop ebp; ret')
    tail_pos = _scan(ir, tail_match)
    if ir[:2] != head_match or tail_pos is None:
        return

    # make sure EBP is never modified outside the header/footer
    for i, ins in enumerate(ir):
        for op in ins.ops:
            if op == 'ebp' and i != tail_pos and i > 2:
                pt.debug('COWARDLY ABORTING')
                pt.debug(ins)
                return

    push = Ins('push', any=True)
    pop = Ins('pop', any=True)

    pt.info('Removing EBP.')
    ir.pop(tail_pos)
    ir = ir[2:]
    esp = 4
    for ins in ir:
        if ins == add_esp:
            esp += ins.src.val
        elif ins == sub_esp:
            esp -= ins.src.val
        elif ins == push:
            esp -= ins.ins.operands[0].size
        elif ins == pop:
            esp += ins.ins.operands[0].size
        else:
            for op in ins.ops:
                if isinstance(op, Mem) and op.base == 'ebp':
                    op.base = 'esp'
                    op.off -= esp
    return ir

def defer(pt):
    pt.binary.onasm(_optimize)
