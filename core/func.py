class Func:
    def __init__(self, pt, addr, size):
        self.pt = pt
        self.addr = addr
        self.size = size

    def dis(self):
        return self.pt.dis(self.addr, self.size)

    def read(self):
        return self.pt.elf.read(self.addr, self.size)

    def nop(self):
        self.pt.patch(self.addr, asm=self.pt.arch.nop() * self.size)

    def __contains__(self, addr):
        if not self.size:
            return False
        return addr >= self.addr and addr < self.addr + self.size

    def __gt__(self, func):
        return self.addr <= func.addr and (not func.size or self.size > func.size)
