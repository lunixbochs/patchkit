# remove useless register stashes
# like:
# call _printf
# mov [ebp - 8], eax
# call _printf
# mov [ebp - 12], eax
# ret
## [ebp - 8] and [ebp - 12] are never used.
## NOTE: If a lower offset is ever loaded with LEA, then all offsets above must be considered tainted (in case of arrays/structs)
## NOTE 2: If the EBP offset is used twice by any instruction in the function, we consider it tainted.

from collections import defaultdict

from util.patch.dis import LabelOp, Label, Ins, Imm, Reg, Mem

def _optimize(pt, ir):
    lea = Ins('lea', Reg(any=True), Mem(any=True))

    counts = defaultdict(int)
    # record used ebp offsets
    for ins in ir:
        for i, op in enumerate(ins.ops):
            if isinstance(op, Mem) and op.base == 'ebp' and op.off < 0:
                # we mix in i so loads will always disqualify an ebp offset
                # also align the offset here and when considering, so byte/word overlap isn't a problem
                counts[op.off & ~3] += 1 + i

    taint = 0
    # LEA blocks any greater EBP offsets
    for i, ins in enumerate(ir):
        if ins == lea and ins.src.base == 'ebp' and ins.src.off < 0:
            taint = min(taint, ins.src.off)

    stash = Ins('mov', Mem(any=True), Reg(any=True))
    i = 0
    total = 0
    while i < len(ir):
        ins = ir[i]
        if ins == stash and ins.dst.base == 'ebp':
            off = ins.dst.off
            if off < taint and counts[off & ~3] <= 1:
                pt.debug('Removing %d: %s' % (i, ins))
                total += 1
                ir.pop(i)
                continue
        i += 1

    if total:
        pt.info('Removed %d stashes.' % total)

def defer(pt):
    pt.binary.onasm(_optimize)
