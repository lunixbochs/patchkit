from capstone.x86_const import *
from collections import defaultdict

from core import func
from util.emu import Emu

SYS_terminate = 1
SYS_transmit = 2
SYS_receive = 3
SYS_fdwait = 4
SYS_allocate = 5
SYS_deallocate = 6
SYS_random = 7

CONDJMPS = [
    X86_INS_JA,
    X86_INS_JAE,
    X86_INS_JB,
    X86_INS_JBE,
    X86_INS_JCXZ,
    X86_INS_JE,
    X86_INS_JECXZ,
    X86_INS_JG,
    X86_INS_JGE,
    X86_INS_JL,
    X86_INS_JLE,
    X86_INS_JNE,
    X86_INS_JNO,
    X86_INS_JNP,
    X86_INS_JNS,
    X86_INS_JO,
    X86_INS_JP,
    X86_INS_JRCXZ,
    X86_INS_JS,
]

JMPS = CONDJMPS + [
    X86_INS_JMP,

    X86_INS_LOOP,
    X86_INS_LOOPE,
    X86_INS_LOOPNE,
]
CALL = X86_INS_CALL
RET = X86_INS_RET

class Func(func.Func):
    def __init__(self, pt, addr, size=None):
        func.Func.__init__(self, pt, addr, size)
        self.syscall = None
        self.stacks = set()
        self.xrefs = set()
        self.jit = False

def explore(pt, known_funcs=[], backtrack=False):
    seen = set()
    funcs = {}
    regs = defaultdict(int)

    def do_bb(addr, stack=None, func=None, xref=None):
        for prog in pt.elf.progs:
            if addr in prog:
                break
        else:
            return

        if addr in seen:
            if func and xref and xref != func.addr:
                func.xrefs.add(xref)
            return
        seen.add(addr)
        if func is None:
            func = funcs[addr] = Func(pt, addr)
        if xref and xref != func.addr:
            func.xrefs.add(xref)
        if stack is None:
            stack = []
        elif stack:
            func.stacks.add(tuple(f.addr for f in stack))

        pad = ((len(stack) + 3) * ' ')
        pos = addr
        while True:
            dis = pt.dis(pos)
            if not dis:
                break

            for ins in dis:
                pos = ins.address + len(ins.bytes)
                cur_size = pos - func.addr

                pad = ((len(stack) + 3) * ' ')
                if ins.id == X86_INS_MOV:
                    dst, src = ins.operands
                    if dst.type == X86_OP_REG:
                        if src.type == X86_OP_REG:
                            regs[dst.reg] = regs[src.reg]
                        elif src.type == X86_OP_IMM:
                            regs[dst.reg] = src.imm

                func.size = max(func.size, cur_size)
                if ins.id == X86_INS_INT and ins.operands[0].imm == 0x80:
                    sys = regs[X86_REG_EAX]
                    # don't trust the top-level function to be a syscall (it's just a raw _terminate)
                    if len(stack) > 0:
                        func.syscall = sys

                if ins.id in JMPS or ins.id == CALL:
                    tmp = list(stack)
                    branch = ins.operands[0].imm
                    dist = abs(branch - ins.address)
                    longjmp = False
                    if ins.id != CALL and dist > 0x10000:
                        longjmp = True
                    try:
                        # TODO: trampoline jumps aren't handled well
                        # assume no funcs over 10KB
                        if ins.id == CALL or longjmp:
                            stack.append(func)
                            do_bb(branch, stack, xref=addr)
                            if longjmp:
                                return
                            # call to next instruction makes a function split
                            if ins.id == CALL and ins.operands[0].imm == ins.address + ins.size:
                                return
                        else:
                            do_bb(branch, stack, func=func, xref=addr)
                    except Exception:
                        # import traceback
                        # traceback.print_exc()
                        pt.warn('Failed to follow branch: %s' % pt.pdis(ins))
                    finally:
                        stack = tmp
                elif ins.id == RET:
                    try:
                        stack.pop()
                    except Exception:
                        pass # print 'Warning: ret on empty call stack'
                    return

    emu = Emu(pt.binary)
    blocks, modified = emu.explore(backtrack=backtrack)
    for addr, size in blocks:
        do_bb(addr)

    do_bb(pt.entry)
    for f in known_funcs:
        do_bb(f.addr)

    funcs = funcs.values()
    # make sure entry gets its own func
    for f in funcs:
        if f.addr != pt.entry and pt.entry in f:
            f.size = pt.entry - f.addr

    out = []
    for f in funcs:
        if f.addr in [x.addr for x in known_funcs]:
            continue

        # filter out invalid addrs
        for prog in pt.elf.progs:
            if f.addr in prog:
                break
        else:
            if (f.addr, f.size) in blocks:
                func.jit = True
                pt.warn('JIT function detected (will likely crash diff)')
                break
            else:
                continue

        for fb in funcs:
            if f != fb and f.addr in fb and fb > f and not f.addr == pt.entry:
                break
        else:
            if not f.size:
                f.size = 16
            out.append(f)

    out.sort(key=lambda x: x.addr)
    return out, modified
