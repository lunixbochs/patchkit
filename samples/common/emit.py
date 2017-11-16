# Example of generating an ELF.

from util.elffile import *

def new_segment(elf, addr, data):
	align = 0x1000
	ph = ElfProgramHeader()
	ph.data = bytearray(data)
	ph.type = 'PT_LOAD'
	ph.vaddr = (addr + align - 1) & ~(align - 1)
	ph.paddr = ph.vaddr
	ph.flags = 7 # RWX
	ph.align = align
	ph.memsz = 0
	ph.filesz = 0
	elf.progs.append(ph)

elf32 = ElfFile.create(32, 'little', 'linux', '386')
new_segment(elf32, 0x80000, 'stuff')
elf32.save('test32.out')

elf64 = ElfFile.create(64, 'little', 'linux', '386')
new_segment(elf64, 0x80000, 'stuff')
elf64.save('test64.out')
