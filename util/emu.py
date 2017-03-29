import os
import struct
import time
import traceback
from contextlib import contextmanager
from collections import defaultdict, OrderedDict
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86_const import *

def align(addr, size):
    start = addr
    end = addr + size
    end = (end + 0xfff) & ~0xfff
    start = start & ~0xfff
    return start, end - start

X86_REGS = [
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_ESI,
    UC_X86_REG_EDI,
    UC_X86_REG_ESP,
]

class Block:
    def __init__(self, addr, size, data):
        self.addr = addr
        self.size = size
        self.data = str(data)

    def __hash__(self):
        return hash((self.addr, self.size, self.data))

    def __lt__(self, other):
        return self.addr < other.addr

    def __contains__(self, addr):
        return addr >= self.addr and addr < self.addr + self.size

    # other should have a higher addr
    def merge(self, other):
        end = self.addr + self.size
        self.addr = min(self.addr, other.addr)
        self.size = (other.addr + other.size) - self.addr
        if end < other.addr:
            gap = (other.addr - end) * '\0'
            self.data += gap + other.data

class Transaction:
    def __init__(self, uc):
        self.uc = uc
        # save all registers
        self.saved_regs = {}
        for enum in X86_REGS:
            val = uc.reg_read(enum)
            self.saved_regs[enum] = val

        # save memory undo deltas
        self.saved_mem = {}
        def hook_mem(uc, access, addr, size, value, user):
            try:
                data = str(uc.mem_read(addr, size))
            except UcError:
                return
            for i in xrange(size):
                waddr = addr + i
                if not waddr in self.saved_mem:
                    self.saved_mem[waddr] = data[i]

        self.hh = uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem)

    def rewind(self):
        self.uc.hook_del(self.hh)

        # rollback register changes
        for enum in X86_REGS:
            self.uc.reg_write(enum, self.saved_regs[enum])

        # rollback memory writes
        for addr, b in self.saved_mem.items():
            self.uc.mem_write(addr, b)

    def discard(self):
        self.uc.hook_del(self.hh)

class Backtrack:
    def __init__(self, emu, uc):
        self.uc = uc
        self.emu = emu
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True

        uc.hook_add(UC_HOOK_CODE, self.jmp_hook)

        # recursive import :(
        from util.cfg import CONDJMPS
        self.CONDJMPS = CONDJMPS

        self.visited = set()
        self.pending = set()
        self.targets = []
        self.last_addr = 0

    def add(self, prev, addr):
        key = (prev, addr)
        if not key in self.visited and not key in self.pending:
            self.pending.add(key)
            self.targets.append((addr, Transaction(self.uc)))

    def jmp_hook(self, uc, addr, size, user):
        # TODO: caching/skipping here will be huge
        # this is gonna be slow
        data = uc.mem_read(addr, size)
        ins = tuple(self.cs.disasm(str(data), addr))[0]
        if ins.id in self.CONDJMPS:
            dst = ins.operands[0]
            if dst.type == X86_OP_IMM:
                dst = dst.imm
                self.add(addr, addr + len(ins.bytes))
                self.add(addr, dst)

        self.visited.add((self.last_addr, addr))
        self.last_addr = addr

    def run(self, entry):
        uc = self.uc
        self.last_addr = entry

        print '  [BACKTRACK] Running once:'
        self.recv_hist = []
        # stop emulator on receive() spam
        def hook_intr(uc, intno, user):
            if intno == 0x80:
                if self.emu.sysnum == 3: # SYS_receive
                    self.recv_hist.append(time.time())
                    if len(self.recv_hist) > 10:
                        if (self.recv_hist[-1] - self.recv_hist[-11]) < 1:
                            uc.emu_stop()

        hh = uc.hook_add(UC_HOOK_INTR, hook_intr)

        self.emu.verbose = True
        uc.emu_start(entry, 0)
        self.emu.verbose = False
        self.emu.block_timeout = 1

        print '  [BACKTRACK] Backtracking...'
        last = time.time()
        finished = 0
        while self.targets:
            now = time.time()
            if now - last > 1:
                last = now
                print '  [BACKTRACK] %d/%d' % (finished, finished + len(self.targets))

            addr, transaction = self.targets.pop(-1)
            transaction.rewind()
            self.emu.alive = time.time()
            try:
                self.last_addr = addr
                self.recv_hist = []
                uc.emu_start(addr, 0)
            except Exception as e:
                pass
            finished += 1
        print '  [BACKTRACK] Finished (%d/%d)' % (finished, finished + len(self.targets))
        uc.hook_del(hh)

class Emu:
    def __init__(self, binary):
        self.binary = binary
        self.blocks = {}
        self.modified = []
        self.seen_receive = False
        self.alive = 0
        self.block_timeout = 10
        self.verbose = True
        self.sysnum = 0

    @contextmanager
    def emu(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        # map memory
        todo = []
        for prog in self.binary.elf.progs:
            if prog.isload and prog.memsz:
                addr, size = align(prog.vaddr, prog.memsz)
                uc.mem_map(addr, size)
                todo.append(prog)

        for prog in todo:
            uc.mem_write(prog.vaddr, str(prog.data))

        # map stack
        stack_base = 0xbaaab000 - 0x800000
        uc.mem_map(stack_base, 0x800000)
        uc.reg_write(UC_X86_REG_ESP, 0xbaaaaffc)

        # map secret page
        secret_addr = 0x4347c000
        uc.mem_map(secret_addr, 0x1000)
        uc.mem_write(secret_addr, os.urandom(0x1000))

        # initial register(s)
        uc.reg_write(UC_X86_REG_ECX, secret_addr)

        yield uc
        # TODO: cleanup? there's no uc.close() yet

    def explore(self, backtrack=False):
        with self.emu() as uc, self.binary.collect() as pt:
            self.alive = time.time()
            self.alloc_pos = 0x10000

            def hook_block(uc, addr, size, user):
                # pt.debug('[BLOCK] 0x%x - 0x%x' % (addr, size))
                # TODO: xrefs?

                now = time.time()
                key = (addr, size)
                data = str(uc.mem_read(addr, size))
                if data != pt.elf.read(addr, size):
                    tmp = (key, data)
                    if not tmp in self.modified:
                        self.modified.append(tmp)

                if not key in self.blocks:
                    self.alive = now
                    self.blocks[key] = Block(addr, size, data)
                elif now - self.alive > self.block_timeout and self.seen_receive:
                    if self.verbose:
                        pt.debug('[EMU] No recent new blocks, stopping emulation.')
                    uc.emu_stop()

            def hook_code(uc, addr, size, user):
                data = uc.mem_read(addr, size)
                pt.debug(dis=pt.arch.dis(data, addr=addr))

            def handle_syscall():
                num = uc.reg_read(UC_X86_REG_EAX)
                self.sysnum = num
                arg1 = uc.reg_read(UC_X86_REG_EBX)
                arg2 = uc.reg_read(UC_X86_REG_ECX)
                arg3 = uc.reg_read(UC_X86_REG_EDX)
                arg4 = uc.reg_read(UC_X86_REG_ESI)
                arg5 = uc.reg_read(UC_X86_REG_EDI)
                arg6 = uc.reg_read(UC_X86_REG_EBP)

                if num == 1: # _terminate
                    if self.verbose:
                        pt.debug('[EMU] _terminate(%d)' % arg1)
                    uc.emu_stop()
                    return

                if num == 2: # transmit
                    data = str(uc.mem_read(arg2, arg3))
                    if arg4:
                        uc.mem_write(arg4, struct.pack('<I', arg3))
                    if self.verbose:
                        pt.debug('[EMU] transmit(%d, "%s", %d, [0x%x])' % (arg1, repr(data), arg3, arg4))
                elif num == 3: # receive
                    if not self.seen_receive:
                        self.alive = time.time()
                    self.seen_receive = True
                    if arg3 == 0:
                        if self.verbose:
                            pt.debug('[EMU] receive(%d, "", %d, [0x%x])' % (arg1, arg3, arg4))
                        uc.reg_write(UC_X86_REG_EAX, 0xffffffff)
                        return
                    else:
                        uc.mem_write(arg2, '\n')
                        if arg4:
                            uc.mem_write(arg4, struct.pack('<I', 1))
                        if self.verbose:
                            pt.debug('[EMU] receive(%d, "\\n", %d, [0x%x])' % (arg1, arg3, arg4))
                # elif num == 4: # fdwait
                elif num == 5: # allocate
                    addr, size = align(self.alloc_pos, arg1)
                    uc.mem_map(addr, size)
                    self.alloc_pos += size
                    if arg3:
                        uc.mem_write(arg3, struct.pack('<I', addr))
                    if self.verbose:
                        pt.debug('[EMU] allocate(0x%x, is_x=%d, [0x%x]) @0x%x' % (arg1, arg2, arg3, addr))
                elif num == 6: # deallocate
                    if self.verbose:
                        pt.warn('[EMU] stubbed deallocate()')
                elif num == 7: # random
                    uc.mem_write(arg1, os.urandom(arg2))
                    if arg3:
                        uc.mem_write(arg3, struct.pack('<I', arg2))
                    if self.verbose:
                        pt.debug('[EMU] random(0x%x, 0x%x, [0x%x])' % (arg1, arg2, arg3))
                else:
                    if self.verbose:
                        pt.warn('[EMU] stubbed syscall %d' % num)
                    uc.reg_write(UC_X86_REG_EAX, 0xffffffff)
                    return
                uc.reg_write(UC_X86_REG_EAX, 0)

            def hook_intr(uc, intno, user):
                if intno == 0x80:
                    try:
                        handle_syscall()
                    except UcError:
                        # probably a memory error
                        uc.reg_write(UC_X86_REG_EAX, 0xffffffff)
                else:
                    if self.verbose:
                        pt.warn('Unknown interrupt during emulation: 0x%x' % intno)
                    uc.emu_stop()

            uc.hook_add(UC_HOOK_BLOCK, hook_block)
            # uc.hook_add(UC_HOOK_CODE, hook_code)
            uc.hook_add(UC_HOOK_INTR, hook_intr)
            if backtrack:
                engine = Backtrack(self, uc)
                engine.run(self.binary.elf.entry)
            else:
                uc.emu_start(self.binary.elf.entry, 0)
            return sorted(self.blocks), self.modified
