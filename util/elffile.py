#!/usr/bin/env python -3
# -*- coding: utf-8 -*-
#
# Copyright 2010 - 2011 K. Richard Pixley.
# See LICENSE for details.
#
# Time-stamp: <01-Jul-2013 10:41:57 PDT by rich@noir.com>

"""
Elffile is a library which reads and writes `ELF format object files
<http://en.wikipedia.org/wiki/Executable_and_Linkable_Format>`_.
Elffile is pure `python <http://python.org>`_ so installation is easy.

.. note:: while this library uses some classes as abstract base
    classes, it does not use :py:mod:`abc`.

.. todo:: need a "copy" method

.. todo:: need a reverse write method, (for testing)

"""

from __future__ import unicode_literals, print_function

__docformat__ = 'restructuredtext en'

#__all__ = []

from collections import defaultdict
import functools
import io
import mmap
import operator
import os
import struct

# simplified reimplementation of coding.Coding
class Code(object):
    def __init__(self, parent, name, code, desc):
        self.parent = parent
        self.name = name
        self.code = code
        self.desc = desc

    def __eq__(self, val):
        return self.name == val or self.code == val

    def __repr__(self):
        return '{} {} {} {}'.format(self.parent, self.name, self.code, self.desc)

class Coding(object):
    def __init__(self, name):
        self.name = name
        self.byname = defaultdict(None)
        self.bycode = defaultdict(None)

    def __call__(self, name='', code=0, desc=''):
        c = Code(self, name, code, desc)
        self.byname[name] = c
        self.bycode[code] = c

    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self.byname[key]
        elif isinstance(key, int):
            return self.bycode[key]
        else:
            raise KeyError(key)

    def __contains__(self, key):
        return key in self.byname or key in self.bycode

    def __repr__(self):
        return '<Coding {}>'.format(self.name)

### START ENUMS ###

ElfClass = Coding('ElfClass')
"""
Encodes the word size of the elf file as from the `ident portion
of the ELF file header
<http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.
This encodes :py:attr:`ElfFileIdent.elfClass`.
"""
ElfClass('ELFCLASSNONE', 0, 'Invalid class')
ElfClass('ELFCLASS32', 1, '32-bit objects')
ElfClass('ELFCLASS64', 2, '64-bit objects')
ElfClass('ELFCLASSNUM', 3, '')          # from libelf

ElfData = Coding('ElfData')
"""
Encodes the byte-wise endianness of the elf file as from the
`ident portion of the elf file header
<http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.
This encodes :py:attr:`ElfFileIdent.elfData`.
"""
ElfData('ELFDATANONE', 0, 'Invalid data encoding')
ElfData('ELFDATA2LSB', 1, 'least significant byte first')
ElfData('ELFDATA2MSB', 2, 'most significant byte first')
ElfData('ELFDATANUM', 3, '')

EV = Coding('EV')
"""
Encodes the elf file format version of this elf file as from the `ident portion of the elf file
header
<http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.
"""
EV('EV_NONE', 0, 'Invalid version')
EV('EV_CURRENT', 1, 'Current version')
EV('EV_NUM', 2, '')

ElfOsabi = Coding('ElfOsabi')
"""
Encodes OSABI values which represent operating system ELF format
extensions as from the `'ident' portion of the elf file header
<http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.

This encodes :py:attr:`ElfFileIdent.osabi`.
"""
ElfOsabi('ELFOSABI_NONE', 0, 'No extensions or unspecified')
ElfOsabi('ELFOSABI_SYSV', 0, 'No extensions or unspecified')
ElfOsabi('ELFOSABI_HPUX', 1, 'Hewlett-Packard HP-UX')
ElfOsabi('ELFOSABI_NETBSD', 2, 'NetBSD')
ElfOsabi('ELFOSABI_LINUX', 3, 'Linux')
ElfOsabi('ELFOSABI_SOLARIS', 6, 'Sun Solaris')
ElfOsabi('ELFOSABI_AIX', 7, 'AIX')
ElfOsabi('ELFOSABI_IRIX', 8, 'IRIX')
ElfOsabi('ELFOSABI_FREEBSD', 9, 'FreeBSD')
ElfOsabi('ELFOSABI_TRU64', 10, 'Compaq TRU64 UNIX')
ElfOsabi('ELFOSABI_MODESTO', 11, 'Novell Modesto')
ElfOsabi('ELFOSABI_OPENBSD', 12, 'Open BSD')
ElfOsabi('ELFOSABI_OPENVMS', 13, 'Open VMS')
ElfOsabi('ELFOSABI_NSK', 14, 'Hewlett-Packard Non-Stop Kernel')
ElfOsabi('ELFOSABI_AROS', 15, 'Amiga Research OS')
ElfOsabi('ELFOSABI_FENIXOS', 16, 'The FenixOS highly scalable multi-core OS')
ElfOsabi('ELFOSABI_ARM_EABI', 64, 'ARM EABI')
ElfOsabi('ELFOSABI_ARM', 97, 'ARM')
ElfOsabi('ELFOSABI_STANDALONE', 255, 'Standalone (embedded) application')

ET = Coding('ET')
"""
Encodes the type of this elf file, (relocatable, executable,
shared library, etc.), as represented in the `ELF file header
<http://www.sco.com/developers/gabi/latest/ch4.eheader.html>`_.
This encodes :py:attr:`ElfFileHeader.type`.
"""
ET('ET_NONE', 0, 'No file type')
ET('ET_REL', 1, 'Relocatable file')
ET('ET_EXEC', 2, 'Executable file')
ET('ET_DYN', 3, 'Shared object file')
ET('ET_CORE', 4, 'Core file')
ET('ET_NUM', 5, '')
ET('ET_LOOS', 0xfe00, 'Operating system-specific')
ET('ET_HIOS', 0xfeff, 'Operating system-specific')
ET('ET_LOPROC', 0xff00, 'Processor-specific')
ET('ET_HIPROC', 0xffff, 'Processor-specific')

EM = Coding('EM')
"""
Encodes the processor type represented in this elf file as
recorded in the `ELF file header <http://www.sco.com/developers/gabi/latest/ch4.eheader.html>`_.

This encodes :py:attr:`ElfFileHeader.machine`.
"""
EM('EM_NONE', 0, 'No machine')
EM('EM_M32', 1, 'AT&T WE 32100')
EM('EM_SPARC', 2, 'SPARC')
EM('EM_386', 3, 'Intel 80386')
EM('EM_68K', 4, 'Motorola 68000')
EM('EM_88K', 5, 'Motorola 88000')
EM('EM_486', 6, 'Reserved for future use (was EM_486)')
EM('EM_860', 7, 'Intel 80860')
EM('EM_MIPS', 8, 'MIPS I Architecture')
EM('EM_S370', 9, 'IBM System/370 Processor')
EM('EM_MIPS_RS3_LE', 10, 'MIPS RS3000 Little-endian')
# 11 - 14 reserved
EM('EM_PARISC', 15, 'Hewlett-Packard PA-RISC')
# 16 reserved
EM('EM_VPP500', 17, 'Fujitsu VPP500')
EM('EM_SPARC32PLUS', 18, 'Enhanced instruction set SPARC')
EM('EM_960', 19, 'Intel 80960')
EM('EM_PPC', 20, 'PowerPC')
EM('EM_PPC64', 21, '64-bit PowerPC')
EM('EM_S390', 22, 'IBM System/390 Processor')
EM('EM_SPU', 23, 'IBM SPU/SPC')
# 24 - 35 reserved
EM('EM_V800', 36, 'NEC V800')
EM('EM_FR20', 37, 'Fujitsu FR20')
EM('EM_RH32', 38, 'TRW RH-32')
EM('EM_RCE', 39, 'Motorola RCE')
EM('EM_ARM', 40, 'Advanced RISC Machines ARM')
EM('EM_ALPHA', 41, 'Digital Alpha')
EM('EM_SH', 42, 'Hitachi SH')
EM('EM_SPARCV9', 43, 'SPARC Version 9')
EM('EM_TRICORE', 44, 'Siemens TriCore embedded processor')
EM('EM_ARC', 45, 'Argonaut RISC Core, Argonaut Technologies Inc.')
EM('EM_H8_300', 46, 'Hitachi H8/300')
EM('EM_H8_300H', 47, 'Hitachi H8/300H')
EM('EM_H8S', 48, 'Hitachi H8S')
EM('EM_H8_500', 49, 'Hitachi H8/500')
EM('EM_IA_64', 50, 'Intel IA-64 processor architecture')
EM('EM_MIPS_X', 51, 'Stanford MIPS-X')
EM('EM_COLDFIRE', 52, 'Motorola ColdFire')
EM('EM_68HC12', 53, 'Motorola M68HC12')
EM('EM_MMA', 54, 'Fujitsu MMA Multimedia Accelerator')
EM('EM_PCP', 55, 'Siemens PCP')
EM('EM_NCPU', 56, 'Sony nCPU embedded RISC processor')
EM('EM_NDR1', 57, 'Denso NDR1 microprocessor')
EM('EM_STARCORE', 58, 'Motorola Star*Core processor')
EM('EM_ME16', 59, 'Toyota ME16 processor')
EM('EM_ST100', 60, 'STMicroelectronics ST100 processor')
EM('EM_TINYJ', 61, 'Advanced Logic Corp. TinyJ embedded processor family')
EM('EM_X86_64', 62, 'AMD x86-64 architecture')
EM('EM_PDSP', 63, 'Sony DSP Processor')
EM('EM_PDP10', 64, 'Digital Equipment Corp. PDP-10')
EM('EM_PDP11', 65, 'Digital Equipment Corp. PDP-11')
EM('EM_FX66', 66, 'Siemens FX66 microcontroller')
EM('EM_ST9PLUS', 67, 'STMicroelectronics ST9+ 8/16 bit microcontroller')
EM('EM_ST7', 68, 'STMicroelectronics ST7 8-bit microcontroller')
EM('EM_68HC16', 69, 'Motorola MC68HC16 Microcontroller')
EM('EM_68HC11', 70, 'Motorola MC68HC11 Microcontroller')
EM('EM_68HC08', 71, 'Motorola MC68HC08 Microcontroller')
EM('EM_68HC05', 72, 'Motorola MC68HC05 Microcontroller')
EM('EM_SVX', 73, 'Silicon Graphics SVx')
EM('EM_ST19', 74, 'STMicroelectronics ST19 8-bit microcontroller')
EM('EM_VAX', 75, 'Digital VAX')
EM('EM_CRIS', 76, 'Axis Communications 32-bit embedded processor')
EM('EM_JAVELIN', 77, 'Infineon Technologies 32-bit embedded processor')
EM('EM_FIREPATH', 78, 'Element 14 64-bit DSP Processor')
EM('EM_ZSP', 79, 'LSI Logic 16-bit DSP Processor')
EM('EM_MMIX', 80, 'Donald Knuth\'s educational 64-bit processor')
EM('EM_HUANY', 81, 'Harvard University machine-independent object files')
EM('EM_PRISM', 82, 'SiTera Prism')
EM('EM_AVR', 83, 'Atmel AVR 8-bit microcontroller')
EM('EM_FR30', 84, 'Fujitsu FR30')
EM('EM_D10V', 85, 'Mitsubishi D10V')
EM('EM_D30V', 86, 'Mitsubishi D30V')
EM('EM_V850', 87, 'NEC v850')
EM('EM_M32R', 88, 'Mitsubishi M32R')
EM('EM_MN10300', 89, 'Matsushita MN10300')
EM('EM_MN10200', 90, 'Matsushita MN10200')
EM('EM_PJ', 91, 'picoJava')
EM('EM_OPENRISC', 92, 'OpenRISC 32-bit embedded processor')
EM('EM_ARC_COMPACT', 93, 'ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)')
EM('EM_XTENSA', 94, 'Tensilica Xtensa Architecture')
EM('EM_VIDEOCORE', 95, 'Alphamosaic VideoCore processor')
EM('EM_TMM_GPP', 96, 'Thompson Multimedia General Purpose Processor')
EM('EM_NS32K', 97, 'National Semiconductor 32000 series')
EM('EM_TPC', 98, 'Tenor Network TPC processor')
EM('EM_SNP1K', 99, 'Trebia SNP 1000 processor')
EM('EM_ST200', 100, 'STMicroelectronics (www.st.com) ST200 microcontroller')
EM('EM_IP2K', 101, 'Ubicom IP2xxx microcontroller family')
EM('EM_MAX', 102, 'MAX Processor')
EM('EM_CR', 103, 'National Semiconductor CompactRISC microprocessor')
EM('EM_F2MC16', 104, 'Fujitsu F2MC16')
EM('EM_MSP430', 105, 'Texas Instruments embedded microcontroller msp430')
EM('EM_BLACKFIN', 106, 'Analog Devices Blackfin (DSP) processor')
EM('EM_SE_C33', 107, 'S1C33 Family of Seiko Epson processors')
EM('EM_SEP', 108, 'Sharp embedded microprocessor')
EM('EM_ARCA', 109, 'Arca RISC Microprocessor')
EM('EM_UNICORE', 110, 'Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University')
EM('EM_EXCESS', 111, 'eXcess: 16/32/64-bit configurable embedded CPU')
EM('EM_DXP', 112, 'Icera Semiconductor Inc. Deep Execution Processor')
EM('EM_ALTERA_NIOS2', 113, 'Altera Nios II soft-core processor')
EM('EM_CRX', 114, 'National Semiconductor CompactRISC CRX microprocessor')
EM('EM_XGATE', 115, 'Motorola XGATE embedded processor')
EM('EM_C166', 116, 'Infineon C16x/XC16x processor')
EM('EM_M16C', 117, 'Renesas M16C series microprocessors')
EM('EM_DSPIC30F', 118, 'Microchip Technology dsPIC30F Digital Signal Controller')
EM('EM_CE', 119, 'Freescale Communication Engine RISC core')
EM('EM_M32C', 120, 'Renesas M32C series microprocessors')
# 121 - 130 reserved
EM('EM_TSK3000', 131, 'Altium TSK3000 core')
EM('EM_RS08', 132, 'Freescale RS08 embedded processor')
# 133 reserved
EM('EM_ECOG2', 134, 'Cyan Technology eCOG2 microprocessor')
EM('EM_SCORE7', 135, 'Sunplus S+core7 RISC processor')
EM('EM_DSP24', 136, 'New Japan Radio (NJR) 24-bit DSP Processor')
EM('EM_VIDEOCORE3', 137, 'Broadcom VideoCore III processor')
EM('EM_LATTICEMICO32', 138, 'RISC processor for Lattice FPGA architecture')
EM('EM_SE_C17', 139, 'Seiko Epson C17 family')
EM('EM_TI_C6000', 140, 'The Texas Instruments TMS320C6000 DSP family')
EM('EM_TI_C2000', 141, 'The Texas Instruments TMS320C2000 DSP family')
EM('EM_TI_C5500', 142, 'The Texas Instruments TMS320C55x DSP family')
# 143 - 159 reserved
EM('EM_MMDSP_PLUS', 160, 'STMicroelectronics 64bit VLIW Data Signal Processor')
EM('EM_CYPRESS_M8C', 161, 'Cypress M8C microprocessor')
EM('EM_R32C', 162, 'Renesas R32C series microprocessors')
EM('EM_TRIMEDIA', 163, 'NXP Semiconductors TriMedia architecture family')
EM('EM_QDSP6', 164, 'QUALCOMM DSP6 Processor')
EM('EM_8051', 165, 'Intel 8051 and variants')
EM('EM_STXP7X', 166, 'STMicroelectronics STxP7x family of configurable and extensible RISC processors')
EM('EM_NDS32', 167, 'Andes Technology compact code size embedded RISC processor family')
EM('EM_ECOG1', 168, 'Cyan Technology eCOG1X family')
EM('EM_ECOG1X', 168, 'Cyan Technology eCOG1X family')
EM('EM_MAXQ30', 169, 'Dallas Semiconductor MAXQ30 Core Micro-controllers')
EM('EM_XIMO16', 170, 'New Japan Radio (NJR) 16-bit DSP Processor')
EM('EM_MANIK', 171, 'M2000 Reconfigurable RISC Microprocessor')
EM('EM_CRAYNV2', 172, 'Cray Inc. NV2 vector architecture')
EM('EM_RX', 173, 'Renesas RX family')
EM('EM_METAG', 174, 'Imagination Technologies META processor architecture')
EM('EM_MCST_ELBRUS', 175, 'MCST Elbrus general purpose hardware architecture')
EM('EM_ECOG16', 176, 'Cyan Technology eCOG16 family')
EM('EM_CR16', 177, 'National Semiconductor CompactRISC CR16 16-bit microprocessor')
EM('EM_ETPU', 178, 'Freescale Extended Time Processing Unit')
EM('EM_SLE9X', 179, 'Infineon Technologies SLE9X core')
# 180-182 Reserved for future Intel use
# 183-184 Reserved for future ARM use
EM('EM_AVR32', 185, 'Atmel Corporation 32-bit microprocessor family')
EM('EM_STM8', 186, 'STMicroeletronics STM8 8-bit microcontroller')
EM('EM_TILE64', 187, 'Tilera TILE64 multicore architecture family')
EM('EM_TILEPRO', 188, 'Tilera TILEPro multicore architecture family')
EM('EM_MICROBLAZE', 189, 'Xilinx MicroBlaze 32-bit RISC soft processor core')
EM('EM_CUDA', 190, 'NVIDIA CUDA architecture')
EM('EM_TILEGX', 191, 'Tilera TILE-Gx multicore architecture family')
EM('EM_CLOUDSHIELD', 192, 'CloudShield architecture family')
EM('EM_COREA_1ST', 193, 'KIPO-KAIST Core-A 1st generation processor family')
EM('EM_COREA_2ND', 194, 'KIPO-KAIST Core-A 2nd generation processor family')

SHN = Coding('SHN')
"""Encodes special section indices into the section header table."""
SHN('SHN_UNDEF', 0, 'marks an undefined, missing, irrelevant, or'
    ' otherwise meaningless section reference')
SHN('SHN_LORESERVE', 0xff00, 'specifies the lower bound of the range'
    ' of reserved indexes')
SHN('SHN_BEFORE', 0xff00, 'Order section before all others (Solaris).')
SHN('SHN_LOPROC', 0xff00, '')
SHN('SHN_AFTER', 0xff01, 'Order section after all others (Solaris).')
SHN('SHN_HIPROC', 0xff1f, '')
SHN('SHN_LOOS', 0xff20, '')
SHN('SHN_HIOS', 0xff3f, '')
SHN('SHN_ABS', 0xfff1, 'specifies absolute values for the corresponding'
    ' reference')
SHN('SHN_COMMON', 0xfff2, 'symbols defined relative to this section are'
    ' common symbols, such as FORTRAN COMMON or unallocated C external variables.')
SHN('SHN_XINDEX', 0xffff, 'This value is an escape value. It indicates'
    ' that the actual section header index is too large to fit in the'
    ' containing field and is to be found in another location (specific'
    ' to the structure where it appears). ')
SHN('SHN_HIRESERVE', 0xffff, 'specifies the upper bound of the range of'
    ' reserved indexes')

SHT = Coding('SHT')
"""
Encodes the type of a section as represented in the section header
entry of `the section header table
<http://www.sco.com/developers/gabi/latest/ch4.sheader.html#section_header>`_.

This encodes :py:attr:`ElfSectionHeader.type`.
"""
SHT('SHT_NULL', 0, 'marks the section header as inactive; it does not have an'
    ' associated section. Other members of the section header have undefined values.')
SHT('SHT_PROGBITS', 1, 'The section holds information defined by the program,'
    ' whose format and meaning are determined solely by the program.')
SHT('SHT_SYMTAB', 2, 'provides symbols for link editing, though it may also'
    ' be used for dynamic linking.')
SHT('SHT_STRTAB', 3, 'section holds a string table. An object file may have'
    ' multiple string table sections.')
SHT('SHT_RELA', 4, 'section holds relocation entries with explicit addends,'
    ' such as type Elf32_Rela for the 32-bit class of object files or type'
    ' Elf64_Rela for the 64-bit class of object files.')
SHT('SHT_HASH', 5, 'section holds a symbol hash table')
SHT('SHT_DYNAMIC', 6, 'section holds information for dynamic linking')
SHT('SHT_NOTE', 7, 'section holds information that marks the file in some way')
SHT('SHT_NOBITS', 8, 'A section of this type occupies no space in the file'
    ' but otherwise resembles SHT_PROGBITS')
SHT('SHT_REL', 9, 'section holds relocation entries without explicit addends')
SHT('SHT_SHLIB', 10, 'section type is reserved but has unspecified semantics')
SHT('SHT_DYNSYM', 11, 'holds a minimal set of dynamic linking symbols,')
SHT('SHT_INIT_ARRAY', 14, 'section contains an array of pointers to initialization functions')
SHT('SHT_FINI_ARRAY', 15, 'section contains an array of pointers to termination functions')
SHT('SHT_PREINIT_ARRAY', 16, 'section contains an array of pointers to functions'
    ' that are invoked before all other initialization functions')
SHT('SHT_GROUP', 17, 'section defines a section group')
SHT('SHT_SYMTAB_SHNDX', 18, 'section is associated with a section of type'
    ' SHT_SYMTAB and is required if any of the section header indexes referenced'
    ' by that symbol table contain the escape value SHN_XINDEX')
SHT('SHT_LOOS', 0x60000000, '')
SHT('SHT_GNU_ATTRIBUTES', 0x6ffffff5, 'Object attributes.')
SHT('SHT_GNU_HASH', 0x6ffffff6, 'GNU-style hash table.')
SHT('SHT_GNU_LIBLIST', 0x6ffffff7, 'Prelink library lis')
SHT('SHT_CHECKSUM', 0x6ffffff8, 'Checksum for DSO content.')
SHT('SHT_LOSUNW', 0x6ffffffa, 'Sun-specific low bound.')
SHT('SHT_SUNW_move', 0x6ffffffa, 'efine SHT_SUNW_COMDAT')
SHT('SHT_SUNW_COMDAT', 0x6ffffffb, '')
SHT('SHT_SUNW_syminfo', 0x6ffffffc, '')
SHT('SHT_GNU_verdef', 0x6ffffffd, 'Version definition section.')
SHT('SHT_GNU_verneed', 0x6ffffffe, 'Version needs section.')
SHT('SHT_GNU_versym', 0x6fffffff, 'Version symbol table.')
SHT('SHT_HISUNW', 0x6fffffff, 'Sun-specific high bound.')
SHT('SHT_HIOS', 0x6fffffff, '')
SHT('SHT_LOPROC', 0x70000000, '')
SHT('SHT_HIPROC', 0x7fffffff, '')
SHT('SHT_LOUSER', 0x80000000, '')
SHT('SHT_HIUSER', 0xffffffff, '')

SHF = Coding('SHF')
"""
Encodes the section flags as represented in the section header
entry of `the section header table
<http://www.sco.com/developers/gabi/latest/ch4.sheader.html#section_header>`_.

This encodes :py:attr:`ElfSectionHeader.flags`.
These are bit flags which are or'd together.
"""
SHF('SHF_WRITE', 0x1, 'section contains data that should be writable'
    ' during process execution')
SHF('SHF_ALLOC', 0x2, 'section occupies memory during process execution')
SHF('SHF_EXECINSTR', 0x4, 'section contains executable machine instructions')
SHF('SHF_MERGE', 0x10, 'data in the section may be merged to eliminate'
    ' duplication')
SHF('SHF_STRINGS', 0x20, 'data elements in the section consist of'
    ' null-terminated character strings')
SHF('SHF_INFO_LINK', 0x40, 'The sh_info field of this section header'
    ' holds a section header table index')
SHF('SHF_LINK_ORDER', 0x80, 'adds special ordering requirements for link editors')
SHF('SHF_OS_NONCONFORMING', 0x100, 'section requires special OS-specific processing')
SHF('SHF_GROUP', 0x200, 'section is a member of a section group')
SHF('SHF_TLS', 0x400, 'section holds Thread-Local Storage')
SHF('SHF_MASKOS', 0x0ff00000, 'All bits included in this mask are reserved'
    ' for operating system-specific semantics')
SHF('SHF_MASKPROC', 0xf0000000, 'All bits included in this mask are reserved'
    ' for processor-specific semantics')
SHF('SHF_ORDERED', (1 << 30), 'Special ordering requirement (Solaris).')
SHF('SHF_EXCLUDE', (1 << 31), 'Section is excluded unless referenced or allocated (Solaris).')

PT = Coding('PT')
"""
Encodes the segment type as recorded in the `program header
<http://www.sco.com/developers/gabi/latest/ch5.pheader.html>`_.

This encodes :py:attr:`ElfProgramHeader.type`.
"""
PT('PT_NULL', 0, 'array element is unused')
PT('PT_LOAD', 1, 'array element specifies a loadable segment')
PT('PT_DYNAMIC', 2, 'array element specifies dynamic linking information')
PT('PT_INTERP', 3, 'array element specifies the location and size'
   ' of a null-terminated path name to invoke as an interpreter')
PT('PT_NOTE', 4, 'array element specifies the location and size of'
   ' auxiliary information')
PT('PT_SHLIB', 5, 'segment type is reserved')
PT('PT_PHDR', 6, 'specifies the location and size of the program'
   ' header table itself')
PT('PT_TLS', 7, 'array element specifies the Thread-Local Storage template')
PT('PT_LOOS', 0x60000000, '')
PT('PT_GNU_EH_FRAME', 0x6474e550, 'GCC .eh_frame_hdr segment')
PT('PT_GNU_STACK', 0x6474e551, 'Indicates stack executability')
PT('PT_GNU_RELRO', 0x6474e552, 'Read only after relocation')
PT('PT_LOSUNW', 0x6ffffffa, '')
PT('PT_SUNWBSS', 0x6ffffffa, 'Sun Specific segment')
PT('PT_SUNWSTACK', 0x6ffffffb, 'Stack segment')
PT('PT_HISUNW', 0x6fffffff, '')
PT('PT_HIOS', 0x6fffffff, '')
PT('PT_LOPROC', 0x70000000, '')
PT('PT_HIPROC', 0x7fffffff, '')

PF = Coding('PF')
"""
Encodes the segment flags as recorded in the `program header
<http://www.sco.com/developers/gabi/latest/ch5.pheader.html>`_.

This encodes :py:attr:`ElfProgramHeader.flags`.
"""
PF('PF_X', 0x1, 'Execute')
PF('PF_W', 0x2, 'Write')
PF('PF_R', 0x4, 'Read')
PF('PF_MASKOS', 0x0ff00000, 'Unspecified')
PF('PF_MASKPROC', 0xf0000000, 'Unspecified')

GRP = Coding('GRP')
GRP('GRP_COMDAT', 0x1, 'This is a COMDAT group')
GRP('GRP_MASKOS', 0x0ff00000, 'All bits included in this mask are'
    ' reserved for operating system-specific semantics')
GRP('GRP_MASKPROC', 0xf0000000, 'All bits included in this mask'
    ' are reserved for processor-specific semantics')

DT = Coding('DT')
DT('DT_NULL', 0, 'Marks the end of the dynamic array')
DT('DT_NEEDED', 1, 'The string table offset of the name of a needed library')
DT('DT_PLTRELSZ', 2, 'Total size, in bytes, of the relocation entries associated with the procedure linkage table.')
DT('DT_PLTGOT', 3, 'Contains an address associated with the linkage table. The specific meaning of this field is processor-dependent.')
DT('DT_HASH', 4, 'Address of the symbol hash table, described below.')
DT('DT_STRTAB', 5, 'Address of the dynamic string table.')
DT('DT_SYMTAB', 6, 'Address of the dynamic symbol table.')
DT('DT_RELA', 7, 'Address of a relocation table with Elf64_Rela entries.')
DT('DT_RELASZ', 8, 'Total size, in bytes, of the DT_RELA relocation table.')
DT('DT_RELAENT', 9, 'Size, in bytes, of each DT_RELA relocation entry.')
DT('DT_STRSZ', 10, 'Total size, in bytes, of the string table.')
DT('DT_SYMENT', 11, 'Size, in bytes, of each symbol table entry.')
DT('DT_INIT', 12, 'Address of the initialization function.')
DT('DT_FINI', 13, 'Address of the termination function.')
DT('DT_SONAME', 14, 'The string table offset of the name of this shared object.')
DT('DT_RPATH', 15, 'The string table offset of a shared library search path string.')
DT('DT_SYMBOLIC', 16, 'The presence of this dynamic table entry modifies the symbol resolution algorithm for references within the library. Symbols defined within the library are used to resolve references before the dynamic linker searches the usual search path.')
DT('DT_REL', 17, 'Address of a relocation table with Elf64_Rel entries.')
DT('DT_RELSZ', 18, 'Total size, in bytes, of the DT_REL relocation table.')
DT('DT_RELENT', 19, 'Size, in bytes, of each DT_REL relocation entry.')
DT('DT_PLTREL', 20, 'Type of relocation entry used for the procedure linkage table. The d_val member contains either DT_REL or DT_RELA.')
DT('DT_DEBUG', 21, 'Reserved for debugger use.')
DT('DT_TEXTREL', 22, 'ignored The presence of this dynamic table entry signals that the relocation table contains relocations for a non-writable segment.')
DT('DT_JMPREL', 23, 'Address of the relocations associated with the procedure linkage table.')
DT('DT_BIND_NOW', 24, 'ignored The presence of this dynamic table entry signals that the dynamic loader should process all relocations for this object before transferring control to the program.')
DT('DT_INIT_ARRAY', 25, 'Pointer to an array of pointers to initialization functions.')
DT('DT_FINI_ARRAY', 26, 'Pointer to an array of pointers to termination functions.')
DT('DT_INIT_ARRAYSZ', 27, 'Size, in bytes, of the array of initialization functions.')
DT('DT_FINI_ARRAYSZ', 28, 'Size, in bytes, of the array of termination functions.')
DT('DT_LOOS', 0x60000000, 'Defines a range of dynamic table tags that are reserved for environment-specific use.')
DT('DT_HIOS', 0x6ffff000, 'Defines a range of dynamic table tags that are reserved for environment-specific use.')
DT('DT_LOPROC', 0x70000000, 'Defines a range of dynamic table tags that are reserved for processor-specific use.')
DT('DT_HIPROC', 0x7fffffff, 'Defines a range of dynamic table tags that are reserved for processor-specific use.')

### END ENUMS ###

def open(name=None, fileobj=None, map=None, block=None):
    """

    The open function takes some form of file identifier and creates
    an :py:class:`ElfFile` instance from it.

    :param :py:class:`str` name: a file name
    :param :py:class:`file` fileobj: if given, this overrides *name*
    :param :py:class:`mmap.mmap` map: if given, this overrides *fileobj*
    :param :py:class:`bytes` block: file contents in a block of memory, (if given, this overrides *map*)

    The file to be used can be specified in any of four different
    forms, (in reverse precedence):

    #. a file name
    #. :py:class:`file` object
    #. :py:mod:`mmap.mmap`, or
    #. a block of memory
    """

    if block:
        if not name:
            name = '<unknown>'

        efi = ElfFileIdent()
        efi.unpack_from(block)

        ef = ElfFile.encodedClass(efi)(name, efi)
        ef.unpack_from(block)

        if fileobj:
            fileobj.close()

        return ef

    if map:
        block = map

    elif fileobj:
        map = mmap.mmap(fileobj.fileno(), 0, mmap.MAP_SHARED, mmap.PROT_READ)

    elif name:
        fileobj = io.open(os.path.normpath(os.path.expanduser(name)), 'rb')

    else:
        assert False
        
    return open(name=name,
                fileobj=fileobj,
                map=map,
                block=block)

class StructBase(object):
    coder = None
    """
    The :py:class:`struct.Struct` used to encode/decode this object
    into a block of memory.  This is expected to be overridden by
    subclasses.
    """

    class _Size(object):
        def __get__(self, obj, t):
            return t.coder.size

    size = _Size()
    """
    Exact size in bytes of a block of memory into which is suitable
    for packing this instance.
    """

    def unpack(self, block):
        return self.unpack_from(block)

    def unpack_from(self, block, offset=0):
        """
        Set the values of this instance from an in-memory
        representation of the struct.

        :param string block: block of memory from which to unpack
        :param int offset: optional offset into the memory block from
            which to start unpacking
        """
        raise NotImplementedError

    def pack(self):
        x = bytearray(self.size)
        self.pack_into(x)
        return x

    def pack_into(self, block, offset=0):
        """
        Store the values of this instance into an in-memory
        representation of the file.

        :param string block: block of memory into which to pack
        :param int offset: optional offset into the memory block into
            which to start packing
        """
        raise NotImplementedError


EI_NIDENT = 16
"""
Length of the byte-endian-independent, word size independent initial
portion of the ELF header file.  This is the portion represented by
:py:class:`ElfFileIdent`.
"""

class ElfFileIdent(StructBase):
    """
    This class corresponds to the first, byte-endian-independent,
    values in an elf file.  These tell us about the encodings for the
    rest of the file.  This is the *e_ident* field of the `elf file
    header
    <http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.

    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`Coding` subclasses.
    """

    magic = None
    elfClass = None
    elfData = None
    fileVersion = None
    osabi = None
    abiversion = None

    coder = struct.Struct(b'=4sBBBBBxxxxxxx')

    # size is EI_IDENT
    assert (coder.size == EI_NIDENT), 'coder.size = {0}({0}), EI_NIDENT = {0}({0})'.format(coder.size, type(coder.size),
                                                                                           EI_NIDENT, type(EI_NIDENT))

    def unpack_from(self, block, offset=0):
        (self.magic, self.elfClass, self.elfData, self.fileVersion, self.osabi,
         self.abiversion) = self.coder.unpack_from(block, offset)
        return self

    def pack_into(self, block, offset=0):
        self.coder.pack_into(block, offset, self.magic, self.elfClass,
                             self.elfData, self.fileVersion,
                             self.osabi, self.abiversion)
        return self

    def __repr__(self):
        return ('<{0}@{1}: coder={2}, magic=\'{3}\', elfClass={4}, elfData={5}, fileVersion={6}, osabi={7}, abiversion={8}>'
                .format(self.__class__.__name__, hex(id(self)), self.coder, self.magic,
                        ElfClass[self.elfClass] if self.elfClass in ElfClass else self.elfClass,
                        ElfData[self.elfData] if self.elfData in ElfData else self.elfData,
                        self.fileVersion, self.osabi, self.abiversion))

class ElfFile(StructBase):
    """
    This class corresponds to an entire ELF format file.  It is an
    abstract base class which is not intended to be instantiated but
    rather subclassed.

    This abstract base class works in tight concert with it's
    subclasses: :py:class:`ElfFile32b`, :py:class:`ElfFile32l`,
    :py:class:`ElfFile64b`, and :py:class:`ElfFile64l`.  This abstract
    base class sets useless defaults and includes byte order and word
    size independent methods while the subclasses define byte order
    and word size dependent methods.
    """

    name = None
    """A :py:class:`str` containing the file name for this ELF format object file."""

    ident = None
    """A :py:class:`ElfFileIdent` representing the :c:data:`e_ident` portion of the ELF format file header."""

    header = None
    """A :py:class:`ElfFileHeader` representing the byte order and word size dependent portion of the ELF format file header."""

    sections = []
    """A :py:class:`list` of section headers.  This corresponds to the section header table."""

    progs = []
    """A :py:class:`list` of the program headers.  This corresponds to the program header table."""

    headerClass = None
    """Intended to be set by the subclasses.  Points to the byte order and word size sensitive class to be used for the ELF file header."""

    class NO_CLASS(Exception):
        """
        Raised when attempting to decode an unrecognized value for
        :py:class:`ElfClass`, (that is, word size).
        """
        pass

    class NO_ENCODING(Exception):
        """
        Raised when attempting to decode an unrecognized value for
        :py:class:`ElfData`, (that is, byte order).
        """

    @staticmethod
    def encodedClass(ident):
        """
        :param :py:class:`ElfFileIdent`:  This is
        :rtype :py:class:`ElfFile`: broken
        .. todo:: file sphinx bug on this once code is released so that they can see it.

        Given an *ident*, return a suitable :py:class:`ElfFile` subclass to represent that file.

        Raises :py:exc:`NO_CLASS` if the :py:class:`ElfClass`, (word size), cannot be represented.

        Raises :py:exc:`NO_ENCODING` if the :py:class:`ElfData`, (byte order), cannot be represented.
        """
        classcode = ident.elfClass
        if classcode in _fileEncodingDict:
            elfclass = _fileEncodingDict[classcode]
        else:
            raise ElfFile.NO_CLASS

        endiancode = ident.elfData
        if endiancode in elfclass:
            return elfclass[endiancode]
        else:
            raise ElfFile.NO_ENCODING

    def __new__(cls, name, ident):
        assert ident

        if cls != ElfFile:
            return object.__new__(cls)

        retval = ElfFile.__new__(ElfFile.encodedClass(ident), name, ident)
        retval.__init__(name, ident)
        return retval

    def __init__(self, name, ident):
        """
        :param :py:class:`str` name
        :param :py:class:`ElfFileIdent`
        """

        self.name = name

        self.ident = ident
        self.header = None
        self.sections = []
        self.progs = []

    def unpack_from(self, block, offset=0):
        """
        Unpack an entire file.

        .. todo:: I don't understand whether segments overlap sections
            or not.
        """

        self._unpack_ident(block, offset)
        self._unpack_file_header(block, offset)
        self._unpack_section_headers(block, offset)
        self._unpack_program_headers(block, offset)
        self._unpack_section_names()

        return self


    def _unpack_ident(self, block, offset):
        if not self.ident:
            self.ident = ElfFileIdent()

        self.ident.unpack_from(block, offset)
        

    def _unpack_file_header(self, block, offset):
        if not self.header:
            self.header = self.headerClass()

        self.header.unpack_from(block, offset + self.ident.size)
        

    def _unpack_section_headers(self, block, offset):
        # section headers
        if self.header.shoff != 0:
            sectionCount = self.header.shnum
            for i in range(sectionCount):
                sh = self.sectionHeaderClass().unpack_from(block,
                        offset + self.header.shoff + (i * self.header.shentsize))
                if sh.addr == 0:
                    base = offset + sh.offset
                    sh.data = bytearray(block[base:base + sh.size])
                else:
                    sh.data = bytearray()
                if i == 0:
                    sh.offset = 0
                if i > 0 and self.header.shstrndx == i:
                    self.header.shstrhdr = sh
                self.sections.append(sh)

    def _unpack_section_names(self):
        # little tricky here - can't read section names until after
        # that section has been read.  So effectively this is two pass.

        for section in self.sections:
            section.name = self.sectionName(section)

    def _unpack_program_headers(self, block, offset):
        if self.header.phoff != 0:
            phnum = self.header.phnum

            # self.progs.append(self.programHeaderClass().unpack_from(block, offset + self.header.phoff))

            if phnum == ElfProgramHeader.PN_XNUM:
                phnum = self.progs[0].info

            for i in range(phnum):
                ph = self.programHeaderClass().unpack_from(
                    block, offset + self.header.phoff + (i * self.header.phentsize),
                )
                base = offset + ph.offset
                ph.data = bytearray(block[base:base + ph.filesz])
                self.progs.append(ph)

    def pack_into(self, block, offset=0):
        """
        Pack the entire file.  Rewrite offsets as necessary.
        """

        total, pdoff, sdoff, shoff, phoff = self._offsets(offset)

        self._pack_program_data(block, pdoff)
        self._pack_section_data(block, sdoff)
        self._pack_file_header(block, offset, shoff, phoff)
        self._pack_program_headers(block, phoff)
        self._pack_section_headers(block, shoff)

        
    def _offsets(self, offset=0):
        """
        Current packing layout is:

        * ident + header
        * program data
          * program headers (in segment with offset 0)
        * section data
        * section headers
        """

        self._regen_section_name_table()

        x = offset
        x += self.header.ehsize

        # find the PHDR
        phdr = None
        for ph in self.progs:
            if PT[ph.type] == PT['PT_PHDR']:
                phdr = ph
                break

        pdoff = x

        for p in self.progs:
            if p.offset == 0 and PT[p.type] == PT['PT_LOAD']:
                # HACK: put PHDR at the end of the first segment
                phoff = p.offset + len(p.data)

                phsize = len(self.progs) * self.header.phentsize
                if phdr:
                    phdr.offset = phoff
                    phdr.vaddr = phdr.paddr = p.vaddr + phoff
                    phdr.filesz = phsize
                    phdr.virtual = True
                break
        else:
            print("Warning: did not relocate PHDR.")
            phoff = x
            phsize = len(self.progs) * self.header.phentsize
            x += phsize

        for p in self.progs:
            if p.virtual or not PT[p.type] == PT['PT_LOAD']:
                continue
            p.filesz = len(p.data)
            # FIXME: repatching a file will spew PHDRs at the end of TEXT
            if p.offset is 0:
                p.filesz += phsize
                x = offset + p.filesz
            else:
                if p.align:
                    # we don't want to make super huge bins, assume everyone is <=8kb pages
                    if p.align > 0x2000:
                         p.align = 0x2000

                    # offset % align == vaddr % align
                    a, b = x % p.align, p.vaddr % p.align
                    if a < b:
                        x += b - a
                    elif a > b:
                        x += p.align - (a - b)
                p.offset = x
                x += p.filesz
            p.memsz = max(p.memsz, p.filesz)

        sdoff = x
        for s in self.sections:
            if s.addr == 0:
                s.size = len(s.data)
                x += s.size

        shoff = x
        x += (len(self.sections) * self.header.shentsize)

        total = x
        return (total, pdoff, sdoff, shoff, phoff)

    def _regen_section_name_table(self):
        """(Re)build the section name table section."""

        # no reason to make a shstrtab
        if self.header.shstrndx == 0 or not self.header.shstrhdr in self.sections:
            self.header.shstrndx = 0
            return
        else:
            strtab = self.header.shstrhdr
            self.header.shstrndx = self.sections.index(strtab)

        strings = []
        data = strtab.data
        if data:
            strings = data.strip(b'\0').split(b'\0')

        for sh in self.sections:
            if not sh.name in strings:
                strings.append(sh.name)

        if not strings:
            strtab.data = bytearray()
            return

        length = sum([len(s) + 1 for s in strings]) + 1
        data = strtab.data = bytearray(length)
        data[0] = b'\0'
        p = 1
        for s in strings:
            data[p:p+len(s)] = s
            p += len(s) + 1
            data[p - 1] = b'\0'

        for s in self.sections:
            s.nameoffset = data.find(s.name + b'\0')

    def _pack_file_header(self, block, offset, shoff, phoff):
        """Determine and set current offsets then pack the file header."""
        self.ident.pack_into(block, offset)

        self.header.phnum = len(self.progs)
        self.header.shnum = len(self.sections)
        self.header.shoff = shoff if len(self.sections) > 0 else 0
        self.header.phoff = phoff if len(self.progs) > 0 else 0
        self.header.pack_into(block, offset + self.ident.size)

    def _pack_program_headers(self, block, offset=0):
        """Pack the program headers."""
        for i, ph in enumerate(self.progs):
            ph.pack_into(block, offset + (i * self.header.phentsize))

    def _pack_program_data(self, block, offset=0):
        """Pack the program header data. As a side effect, set the offset in the program headers."""
        for i, prog in enumerate(self.progs):
            if prog.virtual:
                continue

            if PT[prog.type] == PT['PT_LOAD'] and prog.offset == 0:
                block[offset:len(prog.data) - offset] = prog.data[offset:]
            else:
                block[prog.offset:prog.offset + len(prog.data)] = prog.data

        # fix section and non-LOAD PH offsets
        for ph in self.progs:
            for sh in self.sections:
                if sh.addr and sh.addr in ph:
                    sh.offset = ph.offset + (sh.addr - ph.vaddr)
                    break

            for phd in self.progs:
                if PT[prog.type] == PT['PT_LOAD']:
                    continue
                if phd.vaddr and phd.vaddr in ph:
                    phd.offset = ph.offset + (phd.vaddr - ph.vaddr)

    def _pack_section_data(self, block, offset=0):
        """Pack the section header data. As a side effect, set the offset in the section headers."""
        p = offset
        for i, sh in enumerate(self.sections):
            if sh.addr > 0:
                continue

            sh.offset = p
            block[p:p+sh.size] = sh.data
            p += sh.size

    def _pack_section_headers(self, block, offset):
        """Pack the section header table."""
        # TODO: first section header is reserved and should be all zeroes
        # need to verify and/or force one
        for i, sh in enumerate(self.sections):
            sh.pack_into(block, offset + (i * self.header.shentsize))

    @property
    def size(self):
        return self._offsets()[0]

    def sectionName(self, section):
        """
        Given a section, return its name.

        :param :py:class:`ElfSectionHeader` section:
        """
        try:
            data = self.sections[self.header.shstrndx].data[section.nameoffset:]
            return data.split(b'\0', 1)[0]
        except Exception:
            pass

    def __repr__(self):
        return ('<{0}@{1}: name=\'{2}\', ident={3}, header={4}>'
                .format(self.__class__.__name__, hex(id(self)), self.name, self.ident, self.header))

    # helper methods below
    def save(self, path):
        """Pack and save elf file to path"""
        with io.open(path, 'wb') as f:
            f.write(self.pack())

    @property
    def entry(self):
        return self.header.entry

    @entry.setter
    def entry(self, val):
        self.header.entry = val

    def read(self, vaddr, size):
        """Read data from virtual address space. Won't cross program header boundaries."""
        progs = [p for p in reversed(self.progs) if vaddr in p and PT[p.type] == PT['PT_LOAD']]
        if progs:
            ph = progs[0]
            off = vaddr - ph.vaddr
            size = min(ph.vsize - off, size)
            x = bytearray(size)
            x[:size] = ph.data[off:off+size]
            return x
        raise IOError('could not find segment containing 0x%x' % vaddr)

    def write(self, vaddr, data):
        """Write data to virtual address space. Won't cross program header boundaries."""
        progs = [p for p in reversed(self.progs) if vaddr in p and PT[p.type] == PT['PT_LOAD']]
        if progs:
            ph = progs[0]
            off = vaddr - ph.vaddr
            size = min(ph.memsz - off, len(data))
            if off + ph.vsize >= len(data):
                ph.data[off:off+size] = data[:size]
            else:
                raise IOError('not enough space to write 0x%x bytes at vaddr 0x%x' % (len(data), vaddr))
        else:
            raise IOError('could not find program header for vaddr 0x%x' % vaddr)

class ElfFileHeader(StructBase):
    """
    This abstract base class corresponds to the portion of the `ELF
    file header
    <http://www.sco.com/developers/gabi/latest/ch4.eheader.html>`_
    which follows :c:data:`e_ident`, that is, the word size and byte
    order dependent portion.  This includes thirteen fields.

    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`Coding` subclasses.

    This abstract base class works in tight concert with it's
    subclasses: :py:class:`ElfFileHeader32b`,
    :py:class:`ElfFileHeader32l`, :py:class:`ElfFileHeader64b`, and
    :py:class:`ElfFileHeader64l`.  This base class sets useless
    defaults and includes any byte order and word size independent
    methods while the subclasses define byte order and word size
    dependent methods.
    """

    type = None
    """
    The 'type', (sic), of the file which represents whether this file
    is an executable, relocatable object, shared library, etc.
    Encoded using :py:class:`ET`.
    """

    machine = None
    """Specifies the processor architecture of the file.  Encoded using :py:class:`EM`."""

    version = None
    """
    Specifies the version of the ELF format used for this file.
    Should be 1 in most cases.  Extensions are expected to increment
    the number.
    """

    entry = None
    """Virtual start address when this file is converted into a process.  Zero if not used."""

    phoff = None
    """
    Offset in bytes into this file at which the program header table,
    (:py:class:`ElfProgramHeader`), starts.
    """

    shoff = None
    """
    Offset in bytes into this file at which the section header table,
    (:py:class:`ElfSectionHeader`), starts.
    """

    flags = None
    """Any processor specific flags for this file."""

    ehsize = None
    """
    Size in bytes of the ELF file header, (:py:class:`ElfFileHeader`),
    as represented in this file.
    """
    
    phentsize = None
    """
    Size in bytes of a program header table entry,
    (:py:class:`ElfProgramHeader`), as represented in this file.  All
    entries are the same size.
    """

    phnum = None
    """
    A count of the number of program header table entries,
    (:py:class:`ElfProgramHeader`), in this file.
    """

    shentsize = None
    """
    Size in bytes of a section table entry,
    (:py:class:`ElfSectionHeader`), as represented in this file.  All
    entries aer the same size.
    """

    shnum = None
    """
    A count of the number of section header table entries,
    (:py:class:`ElfSectionHeader`), in this file.
    """

    shstrndx = None
    """
    The section header table index of the section name string table.
    (SHN_UNDEF if there is none).
    """

    shstrhdr = None
    """
    Reference to the shstrtab section, in case you move sections around
    before saving.
    """

    def unpack_from(self, block, offset=0):
        (self.type, self.machine, self.version, self.entry,
         self.phoff, self.shoff, self.flags, self.ehsize,
         self.phentsize, self.phnum, self.shentsize, self.shnum,
         self.shstrndx) = self.coder.unpack_from(block, offset)

        return self

    def pack_into(self, block, offset=0):
        assert(self.type in ET)
        assert(self.machine in EM)

        self.coder.pack_into(block, offset, self.type, self.machine,
                             self.version if self.version != None else 1,
                             self.entry if self.entry != None else 0,
                             self.phoff if self.phoff != None else 0,
                             self.shoff if self.shoff != None else 0,
                             self.flags if self.flags != None else 0,
                             self.ehsize if self.ehsize != None else self.size,
                             self.phentsize if self.phentsize != None else self.programHeaderClass.size,
                             self.phnum if self.phnum != None else 0,
                             self.shentsize if self.shentsize != None else self.sectionHeaderClass.size,
                             self.shnum if self.shnum != None else 0,
                             self.shstrndx if self.shstrndx != None else 0)

        return self

    def __repr__(self):
        return ('<{0}@{1}: type={2}, machine={3}, version={4},'
                ' entry={5}, phoff={6}, shoff={7}, flags={8},'
                ' ehsize={9}, phnum={10}, shentsize={11}, shnum={12},'
                ' shstrndx={13}>'
                .format(self.__class__.__name__, hex(id(self)), ET[self.type], EM[self.machine],
                        self.version, hex(self.entry), self.phoff, self.shoff,
                        hex(self.flags), self.ehsize, self.phnum, self.shentsize,
                        self.shnum, self.shstrndx))


class ElfFileHeader32b(ElfFileHeader):
    """This represents 32-bit, big-endian headers."""
    coder = struct.Struct(b'>HHIIIIIHHHHHH')

class ElfFileHeader32l(ElfFileHeader):
    """This represents 32-bit, little-endian headers."""
    coder = struct.Struct(b'<HHIIIIIHHHHHH')

class ElfFileHeader64b(ElfFileHeader):
    """This represents 64-bit, big-endian headers."""
    coder = struct.Struct(b'>HHIQQQIHHHHHH')

class ElfFileHeader64l(ElfFileHeader):
    """This represents 64-bit, little-endian headers."""
    coder = struct.Struct(b'<HHIQQQIHHHHHH')

class ElfSectionHeader(StructBase):
    """
    This abstract base class corresponds to an entry in `the section
    header table
    <http://www.sco.com/developers/gabi/latest/ch4.sheader.html#section_header>`_.
    This includes ten fields.

    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`Coding` subclasses.

    This abstract base class works in tight concert with it's
    subclasses: :py:class:`ElfSectionHeader32b`,
    :py:class:`ElfSectionHeader32l`, :py:class:`ElfSectionHeader64b`,
    and :py:class:`ElfSectionHeader64l`.  This base class sets useless
    defaults and includes any byte order and word size independent
    methods while the subclasses define byte order and word size
    dependent methods.
    """

    nameoffset = None
    """
    Offset into the `section header string table section
    <http://www.sco.com/developers/gabi/latest/ch4.strtab.html>`_ of
    the name of this section.
    """

    name = None
    """The name of this section."""

    type = None
    """Section type encoded with :py:class:`SHT`."""

    flags = None
    """
    Flags which define miscellaneous attributes.  These are bit flags
    which are or'd together.  The individual bit-flags are encoded
    using :py:class:`SHF`.
    """
    
    addr = None
    """The load address of this section if it will appear in memory during a running process."""

    offset = None
    """Byte offset from the start of the file to the beginning of the content of this section."""

    size = None
    """Size in bytes of the content of this section."""
    
    link = None
    """A section header table index.  It's meaning varies by context."""

    info = None
    """Extra information.  It's meaning varies by context."""

    addralign = None
    """Section alignment constraints."""

    entsize = None
    """If the section holds fixed sized entries then this is the size of each entry."""

    data = None
    """The original contents of the section, if the section has no address."""

    def unpack_from(self, block, offset=0):
        (self.nameoffset, self.type, self.flags, self.addr,
         self.offset, self.size, self.link, self.info,
         self.addralign, self.entsize) = self.coder.unpack_from(block, offset)

        return self

    def pack_into(self, block, offset=0):
        """
        .. note:: this is a special case.  *block* here must be the
            entire file or we won't know how to place our content.
        """
        self.coder.pack_into(block, offset,
                             self.nameoffset, self.type, self.flags, self.addr,
                             self.offset, self.size, self.link, self.info,
                             self.addralign, self.entsize)

        return self

    def __repr__(self):
        # FIXME: I wish I could include the first few bytes of the content as well.
        return ('<{0}@{1}: name=\'{2}\', type={3},'
                ' flags={4}, addr={5}, offset={6}, size={7},'
                ' link={8}, info={9}, addralign={10}, entsize={11}>'
                .format(self.__class__.__name__, hex(id(self)), self.name,
                        SHT[self.type] if self.type in SHT else hex(self.type),
                        hex(self.flags), hex(self.addr), self.offset, self.size,
                        self.link, self.info, self.addralign, self.entsize))

    def __contains__(self, vaddr):
        return vaddr >= self.addr and vaddr < self.addr + self.size

class ElfSectionHeader32b(ElfSectionHeader):
    coder = struct.Struct(b'>IIIIIIIIII')

class ElfSectionHeader32l(ElfSectionHeader):
    coder = struct.Struct(b'<IIIIIIIIII')

class ElfSectionHeader64b(ElfSectionHeader):
    coder = struct.Struct(b'>IIQQQQIIQQ')

class ElfSectionHeader64l(ElfSectionHeader):
    coder = struct.Struct(b'<IIQQQQIIQQ')

class ElfProgramHeader(StructBase):
    """
    This abstract base class corresponds to a `program header
    <http://www.sco.com/developers/gabi/latest/ch5.pheader.html>`_.
    
    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`Coding` subclasses.

    This abstract base class works in tight concert with it's
    subclasses: :py:class:`ElfProgramHeader32b`,
    :py:class:`ElfProgramHeader32l`, :py:class:`ElfProgramHeader64b`,
    and :py:class:`ElfProgramHeader64l`.  This base class sets useless
    defaults and includes any byte order and word size independent
    methods while the subclasses define byte order and word size
    dependent methods.
    """

    PN_XNUM = 0xffff
    """
    Program header overflow number.
    """

    type = None
    """
    Segment type encoded with :py:class:`PT`.
    """

    offset = None
    """
    Offset in bytes from the beginning of the file to the start of this segment.
    """

    vaddr = None
    """
    Virtual address at which this segment will reside in memory when loaded to run.
    """

    paddr = None
    """
    Physical address in memory, when physical addresses are used.
    """

    filesz = None
    """
    Segment size in bytes in file.
    """

    memsz = None
    """
    Segment size in bytes when loaded into memory.  Must be at least
    :py:attr:`ElfProgramHeader.filesz` or greater.  Extra space is
    zero'd out.
    """

    flags = None
    """
    Flags for the segment.  Encoded using :py:class:`PF`.
    """

    align = None
    """
    Alignment of both segments in memory as well as in file.
    """

    data = bytearray(b'')
    """
    Contents of program header.
    """

    virtual = False
    """
    If True, don't try to pack data.
    """

    def __repr__(self):
        return ('<{0}@{1}: type={2},'
                ' offset={3}, vaddr={4}, paddr={5},'
                ' filesz={6}, memsz={7}, flags={8}, align={9}>'
                .format(self.__class__.__name__, hex(id(self)),
                        PT[self.type].name if self.type in PT else self.type,
                        self.offset, hex(self.vaddr), hex(self.paddr),
                        self.filesz, self.memsz, hex(self.flags), self.align))

    @property
    def vsize(self):
        return (self.memsz + self.align) &~(self.align - 1)

    @property
    def vend(self):
        return self.vaddr + self.memsz

    @property
    def isload(self):
        return PT[self.type].name == 'PT_LOAD'

    def __contains__(self, vaddr):
        return vaddr >= self.vaddr and vaddr < self.vaddr + self.vsize

class ElfProgramHeader32(ElfProgramHeader):
    """
    32 vs 64 bit files have differing element orders.  This class
    represents the 32 bit element order.
    """

    def unpack_from(self, block, offset=0):
        (self.type, self.offset, self.vaddr, self.paddr,
         self.filesz, self.memsz, self.flags, self.align) = self.coder.unpack_from(block, offset)

        return self

    def pack_into(self, block, offset=0):
        self.coder.pack_into(block, offset,
                             self.type, self.offset, self.vaddr, self.paddr,
                             self.filesz, self.memsz, self.flags, self.align)

        return self

class ElfProgramHeader64(ElfProgramHeader):
    """
    32 vs 64 bit files have differing element orders.  This class
    represents the 64 bit element order.
    """

    def unpack_from(self, block, offset=0):
        (self.type, self.flags, self.offset, self.vaddr,
         self.paddr, self.filesz, self.memsz, self.align) = self.coder.unpack_from(block, offset)

        return self

    def pack_into(self, block, offset=0):
        self.coder.pack_into(block, offset,
                             self.type, self.flags, self.offset, self.vaddr,
                             self.paddr, self.filesz, self.memsz, self.align)

        return self


class ElfProgramHeader32b(ElfProgramHeader32):
    """Represents big endian byte order."""
    coder = struct.Struct(b'>IIIIIIII')

class ElfProgramHeader32l(ElfProgramHeader32):
    """Represents little endian byte order."""
    coder = struct.Struct(b'<IIIIIIII')

class ElfProgramHeader64b(ElfProgramHeader64):
    """Represents big endian byte order."""
    coder = struct.Struct(b'>IIQQQQQQ')

class ElfProgramHeader64l(ElfProgramHeader64):
    """Represents little endian byte order."""
    coder = struct.Struct(b'<IIQQQQQQ')

class ElfFile32b(ElfFile):
    """Represents 32-bit, big-endian files."""
    headerClass = ElfFileHeader32b
    sectionHeaderClass = ElfSectionHeader32b
    programHeaderClass = ElfProgramHeader32b

class ElfFile32l(ElfFile):
    """Represents 32-bit, little-endian files."""
    headerClass = ElfFileHeader32l
    sectionHeaderClass = ElfSectionHeader32l
    programHeaderClass = ElfProgramHeader32l

class ElfFile64b(ElfFile):
    """Represents 64-bit, big-endian files."""
    headerClass = ElfFileHeader64b
    sectionHeaderClass = ElfSectionHeader64b
    programHeaderClass = ElfProgramHeader64b

class ElfFile64l(ElfFile):
    """Represents 64-bit, little-endian files."""
    headerClass = ElfFileHeader64l
    sectionHeaderClass = ElfSectionHeader64l
    programHeaderClass = ElfProgramHeader64l

_fileEncodingDict = {
    ElfClass['ELFCLASS32'].code: {
        ElfData['ELFDATA2LSB'].code: ElfFile32l,
        ElfData['ELFDATA2MSB'].code: ElfFile32b,
    },
    ElfClass['ELFCLASS64'].code: {
        ElfData['ELFDATA2LSB'].code: ElfFile64l,
        ElfData['ELFDATA2MSB'].code: ElfFile64b,
    },
}
"""
This is a dict of dicts.  The first level keys correspond to
:py:class:`ElfClass` codes and the values are second level dicts.  The
second level dict keys correspond to :py:class:`ElfData` codes and the
second level values are the four :py:class:`ElfFile` subclasses.  It
is used by :py:meth:`ElfClass.encodedClass` to determine an
appropriate subclass to represent a file based on a
:py:class:`ElfFileIdent`.
"""
