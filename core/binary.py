import contextlib
import os

from util import autolink
from util import elffile
from util.elffile import PT

from context import Context
from linker import Linker

class Binary:
    def __init__(self, path):
        self.path = path
        self.fileobj = open(path, 'rb')
        self.elf = elffile.open(fileobj=self.fileobj)
        self.linker = Linker(self)

        self.final_hook = []
        self.asm_hook = []
        self.c_hook = []

        self.verbose = False
        autolink.declare(self.linker)

        start = 0xFFFFFFFFFFFFFFFF
        end = 0
        # TODO: doesn't handle new mem being mapped or unmapped
        for ph in reversed(self.elf.progs):
            if ph.isload:
                start = min(start, ph.vaddr)
                end = max(ph.vaddr + ph.vsize, end)

        # add patch segment
        def new_segment(addr):
            align = 0x1000
            ph = self.elf.programHeaderClass()
            ph.data = bytearray()
            ph.type = PT['PT_LOAD'].code
            ph.vaddr = (addr + align - 1) & ~(align - 1)
            ph.paddr = ph.vaddr
            # TODO: default is RWX?!
            ph.flags = 7
            ph.align = align
            ph.memsz = 0
            ph.filesz = 0
            self.elf.progs.append(ph)
            return ph

        self.patch = new_segment(end)
        self.nxpatch = new_segment(end + 0x800000)
        self.nxpatch.flags = 6
        self.linkpatch = new_segment(end + 0x1600000)
        self.jitpatch = new_segment(end + 0x2400000)

        self.entry_hooks = []

    def _seg(self, name):
        return {
            'patch': self.patch,
            'nx': self.nxpatch,
            'link': self.linkpatch,
            'jit': self.jitpatch,
        }.get(name, 'patch')

    @contextlib.contextmanager
    def collect(self):
        p = Context(self, verbose=self.verbose)
        yield p

    def next_alloc(self, target='patch'):
        return self._seg(target).vend

    def alloc(self, size, target='patch'):
        ph = self._seg(target)
        tmp = self.next_alloc(target)
        ph.data += '\0' * size
        ph.memsz += size
        ph.filesz += size
        return tmp

    def onfinal(self, cb):
        self.final_hook.append(cb)

    def onasm(self, cb):
        self.asm_hook.append(cb)

    def save(self, path):
        self.nxpatch.flags &= ~1

        print '[+] Saving binary to: %s' % path
        # hooking the entry point is a special case that generates a more efficient call table
        if self.entry_hooks:
            with self.collect() as pt:
                # call each hook addr then jump to original entry point
                calls = map(pt.arch.call, self.entry_hooks) + [pt.arch.jmp(pt.entry)]
                addr = pt.inject(asm=';'.join(calls), internal=True)
                pt.entry = addr

        for cb in self.final_hook:
            with self.collect() as pt:
                cb(pt)

        for prog in (self.patch, self.nxpatch, self.linkpatch, self.jitpatch):
            if not prog.filesz and prog in self.elf.progs:
                self.elf.progs.remove(prog)

        self.elf.save(path)
        os.chmod(path, 0755)
