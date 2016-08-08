import random
from collections import defaultdict

from util.patch.dis import irdis, IR

def aslr(pt, count=3):
    funcs = {}

    saved = []
    holes = []
    pos = pt.binary.next_alloc()
    for func in pt.funcs():
        if func.size < 5:
            continue

        ir = irdis(func.dis())
        size = len(pt.asm(ir.asm(), addr=pos))
        saved.append((func, ir, size))
        holes.append((func.addr + 5, func.size - 5))
        func.nop()
        pt.make_writable(func.addr)

    funcs = defaultdict(list)

    tmp = []
    for func, ir, size in saved:
        for hook in pt.binary.asm_hook:
            pt.info('[ASM Hook] %s.%s() on 0x%x' % (hook.__module__, hook.__name__, func.addr))
            tmpir = hook(pt, ir)
            if tmpir:
                ir = IR(tmpir)
        tmp.append((func, ir, size))
    saved = tmp

    holes.sort(key=lambda x: x[1])
    for i in xrange(count):
        random.shuffle(saved)
        for func, ir, size in saved:
            txt = ir.asm()
            tmp = [h for h in holes if h[0] != func.addr + 5 and h[1] >= size]
            if tmp:
                addr, hsize = tmp[0]
                holes.remove(tmp[0])
                raw = pt.asm(txt, addr=addr)
                if len(raw) <= hsize:
                    pt.patch(addr, raw=raw, is_asm=True)
                    funcs[func].append((addr, len(raw)))
                    continue

            addr, isize = pt.inject(asm=txt, size=True, is_asm=True)
            funcs[func].append((addr, isize))

    return funcs
