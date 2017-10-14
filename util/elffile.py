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

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, val):
        return self.name == val or self.code == val

    def __repr__(self):
        return '<{}:{}={} "{}">'.format(self.parent.name, self.name, self.code, self.desc)

class UnknownCode(Code):
    def __init__(self, parent, code):
        self.parent = parent
        self.name = 'UNKNOWN'
        self.code = code
        self.desc = None

class Coding(object):
    def __init__(self, name):
        self.name = name
        self.byname = {}
        self.bycode = {}

    def __call__(self, name='', code=0, desc=''):
        c = Code(self, name, code, desc)
        self.byname[name] = c
        self.bycode[code] = c

    def __getitem__(self, key):
        if key is None:
            key = 0
        if isinstance(key, Code):
            if key.parent != self:
                raise TypeError('mismatched code assignment {} <- {}'.format(self.name, key.parent.name))
            key = key.code
        if isinstance(key, basestring):
            return self.byname.get(key)
        elif isinstance(key, int):
            return self.bycode.get(key)
        else:
            raise TypeError('key ({}) is {}, but was expecting Code, str, or int'.format(key, type(key)))

    def get(self, key, default=None):
        val = self[key]
        if val is None:
            val = default
        return val

    def fallback(self, key):
        return self.get(key, UnknownCode(self, key))

    def __contains__(self, key):
        if isinstance(key, Code):
            key = key.code
        return key in self.byname or key in self.bycode

    def __repr__(self):
        return '<Coding {}>'.format(self.name)

class Prop(object):
    def __init__(self, coding):
        self.coding = coding
        self.name = '_' + coding.name

    def __get__(self, obj, t=None):
        return getattr(obj, self.name)

    def __set__(self, obj, val):
        setattr(obj, self.name, self.coding.fallback(val))

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
DT('DT_FLAGS', 30)
DT('DT_PREINIT_ARRAY', 32)
DT('DT_PREINIT_ARRAYSZ', 33)
DT('DT_LOOS', 0x60000000, 'Defines a range of dynamic table tags that are reserved for environment-specific use.')
DT('DT_HIOS', 0x6ffff000, 'Defines a range of dynamic table tags that are reserved for environment-specific use.')
DT('DT_LOPROC', 0x70000000, 'Defines a range of dynamic table tags that are reserved for processor-specific use.')
DT('DT_HIPROC', 0x7fffffff, 'Defines a range of dynamic table tags that are reserved for processor-specific use.')

# GNU extensions
DT('DT_GNU_HASH', 0x6ffffef5)
DT('DT_VERNEED', 0x6ffffffe)
DT('DT_VERNEEDNUM', 0x6fffffff)
DT('DT_VERSYM', 0x6ffffff0)

DF = Coding('DF')
DF('DF_ORIGIN', 0x1)
DF('DF_SYMBOLIC', 0x2)
DF('DF_TEXTREL', 0x4)
DF('DF_BIND_NOW', 0x8)

### END ENUMS ###

class ElfHash:
    @staticmethod
    def hash(name):
        h = 0
        for c in name.split('\0', 1)[0]:
            h = (h << 4) + ord(c)
            g = h & 0xf0000000
            if g:
                h ^= g >> 24
                h &= ~g
        return h & 0xffffffff

    @classmethod
    def count(cls, data, addr):
        en = addr.format[0]
        nbucket, nchain = struct.unpack(en + 'II', data[:8])
        buckets = struct.unpack(en + '%dI' % nbucket, data[:nbucket * 4])
        return min(buckets), nchain

    @classmethod
    def build(cls, base, names, addr):
        en = addr.format[0]
        nbucket = max(min(1024, len(names) / 4), 1)
        nchain = len(names) + base
        buckets = [0] * nbucket
        chain = [0] * nchain
        for i, name in enumerate(names):
            i += base
            h = cls.hash(name) % len(buckets)
            n = buckets[h]
            if n == 0:
                buckets[h] = i
            else:
                while chain[n]:
                    n = chain[n]
                chain[n] = i
        fmt = en + '%dIII' % (nbucket + nchain)
        return struct.pack(fmt, *([nbucket, nchain] + buckets + chain))

class ElfGnuHash:
    @staticmethod
    def hash(name):
        h = 5381
        for c in name.split('\0', 1)[0]:
            h = (h << 5) + h + ord(c)
        return h & 0xffffffff

    @staticmethod
    def count(data, addr):
        en = addr.format[0]
        awords = addr.format[-1]
        word = struct.Struct(en + 'I')

        u = lambda n=1, word='I': (struct.unpack_from(en + ('%d%s' % (n, word)), data), data[struct.calcsize(word) * n:])
        (nbuckets, base, bitmask_nwords, shift), data = u(4)
        bitmask, data = u(n=bitmask_nwords, word=awords)
        buckets, data = u(nbuckets)
        top = max(buckets)
        if top:
            last = top
            pos = (top - base) * word.size
            while not word.unpack(data[pos:pos+word.size])[0] & 1:
                pos += word.size
                last += 1
            return base, last
        return base, 0

    @staticmethod
    def build(base, names, addr):
        en = addr.format[0]
        awords = addr.format[-1]
        word = struct.Struct(en + 'I')
        raise NotImplementedError

def open(name=None, fileobj=None, map=None, block=None):
    """The open function takes some form of file identifier and creates
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
    #. a block of memory"""

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
        
    return open(name=name, fileobj=fileobj, map=map, block=block)

class StructBase(object):
    coder = None
    """
    The :py:class:`struct.Struct` used to encode/decode this object
    into a block of memory.  This is expected to be overridden by
    subclasses.
    """

    def unpack_from(self, codec, block, offset=0):
        """
        Set the values of this instance from an in-memory
        representation of the struct.

        :param string block: block of memory from which to unpack
        :param int offset: optional offset into the memory block from
            which to start unpacking
        """
        raise NotImplementedError

    def pack_into(self, codec, block, offset=0):
        """
        Store the values of this instance into an in-memory
        representation of the file.

        :param string block: block of memory into which to pack
        :param int offset: optional offset into the memory block into
            which to start packing
        """
        raise NotImplementedError


EI_NIDENT = 16
"""Length of the byte-endian-independent, word size independent initial
portion of the ELF header file.  This is the portion represented by
:py:class:`ElfFileIdent`."""

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

    elfClass = Prop(ElfClass)
    elfData = Prop(ElfData)
    fileVersion = None
    osabi = Prop(ElfOsabi)
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
        self.coder.pack_into(block, offset, self.magic, self.elfClass.code,
                             self.elfData.code, self.fileVersion,
                             self.osabi.code, self.abiversion)
        return self

    def __repr__(self):
        return ('<{}@{}: magic=\'{}\', elfClass={}, elfData={}, fileVersion={}, osabi={}, abiversion={}>'
                .format(self.__class__.__name__, hex(id(self)), self.magic.encode('hex'),
                        ElfClass[self.elfClass] if self.elfClass in ElfClass else self.elfClass,
                        ElfData[self.elfData] if self.elfData in ElfData else self.elfData,
                        self.fileVersion, self.osabi, self.abiversion))

class ElfFile(StructBase):
    """This class corresponds to an entire ELF format file."""

    name = None
    """A :py:class:`str` containing the file name for this ELF format object file."""

    ident = None
    """A :py:class:`ElfFileIdent` representing the :c:data:`e_ident` portion of the ELF format file header."""

    header = None
    """A :py:class:`ElfFileHeader` representing the byte order and word size dependent portion of the ELF format file header."""

    sections = None
    """A :py:class:`list` of section headers.  This corresponds to the section header table."""

    progs = None
    """A :py:class:`list` of the program headers.  This corresponds to the program header table."""

    codec = None
    """A :py:class:`Codec` containing type packing directives."""

    # start PT_DYNAMIC attrs

    dyn_unk = None
    """A :py:class:`list` of unknown PT_DYNAMIC entries to pass through."""

    dyndata = bytearray(b'')
    """The PT_DYNAMIC data blob, generated immediately before save."""

    # the following attrs will be extracted from the dyn list
    needed = None
    """A :py:class:`list` of DT_NEEDED entries."""

    preinit = None
    """A :py:class:`list` of DT_PREINIT_ARRAY functions"""

    init = None
    """A :py:class:`list` of DT_INIT or DT_INIT_ARRAY entries."""

    fini = None
    """A :py:class:`list` of DT_FINI or DT_FINI_ARRAY entries."""

    dyn_flags = None
    """A :py:class:`int` encoded using bits from :py:class:`DF`."""

    # NOTE: need to convert DT_REL to DT_RELA on load by grabbing addend
    rel = None
    """A :py:class:`list` of DT_REL entries."""

    symtab = None
    """A :py:class:`list` of DT_SYMTAB entries."""

    soname = None
    """A :py:class:`str` of the current library name."""

    # NOTE: If both DT_RPATH and DT_RUNPATH entries appear in a single object's dynamic array, the dynamic linker processes only the DT_RUNPATH entry.
    # NOTE: it is stored colon-separated, but split into a list to allow easy editing
    rpath = None
    """A :py:class:`list` of the binary's RPATH"""

    # end PT_DYNAMIC attrs

    class NO_CLASS(Exception):
        """Raised when attempting to decode an unrecognized value for
        :py:class:`ElfClass`, (that is, word size)."""

    class NO_ENCODING(Exception):
        """Raised when attempting to decode an unrecognized value for
        :py:class:`ElfData`, (that is, byte order)."""

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

    @classmethod
    def create(cls, bits, order, osabi, machine):
        ident = ElfFileIdent()
        if   bits == 32:      ident.elfClass = 'ELFCLASS32'
        elif bits == 64:      ident.elfClass = 'ELFCLASS64'
        else: raise KeyError('unknown bits {} (must be 32 or 64)'.format(bits))

        if   order == 'little': ident.elfData = 'ELFDATA2LSB'
        elif order == 'big':    ident.elfData = 'ELFDATA2MSB'
        else: raise KeyError('unknown order {} (must be big or little)'.format(order))

        for abi, abiobj in ElfOsabi.byname.items():
            if abi.lower().endswith('_' + osabi):
                ident.osabi = abiobj
                break
        else:
            raise KeyError('unknown osabi {}'.format(osabi))

        hdr = ElfFileHeader()
        hdr.type = 'ET_EXEC'

        for em, emobj in EM.byname.items():
            if em.lower().endswith('_' + machine):
                hdr.machine = emobj
                break
        else:
            raise KeyError('unknown machine {}'.format(machine))

        ident.magic = str('\x7fELF')
        ident.fileVersion = 1
        ident.abiversion = 0

        elf = ElfFile(name='', ident=ident)
        elf.header = hdr
        hdr.version = ident.fileVersion
        hdr.ehsize = elf.codec.fileHeader.size + ident.coder.size
        hdr.phentsize = elf.codec.programHeader.size
        hdr.shentsize = elf.codec.sectionHeader.size
        return elf

    def unpack_from(self, block, offset=0):
        """Unpack an entire file."""
        # TODO: I don't understand whether segments overlap sections or not.
        # (they don't), TODO: represent all sections as subsets of segments
        self._unpack_ident(block, offset)
        self._unpack_file_header(block, offset)
        self._unpack_section_headers(block, offset)
        self._unpack_program_headers(block, offset)
        self._unpack_dyn()
        self._unpack_section_names()
        return self

    def _unpack_dyn(self):
        self.dyn_unk = []
        self.preinit = []
        self.init = []
        self.fini = []
        self.needed = []
        self.rel = []
        self.rpath = []
        self.symtab = []
        self.soname = None
        self.dyn_flags = 0
        for ph in self.progs:
            if ph.type == 'PT_DYNAMIC':
                dynd = defaultdict(list)
                # any DT entries not in `known` will be preserved verbatim
                known = [
                    'DT_STRTAB', 'DT_STRSZ',
                    'DT_NEEDED', 'DT_SONAME',
                    'DT_SYMTAB', 'DT_SYMENT', 'DT_HASH', 'DT_GNU_HASH',
                    'DT_INIT', 'DT_FINI', 'DT_INIT_ARRAY', 'DT_INIT_ARRAYSZ',
                    'DT_FINI_ARRAY', 'DT_FINI_ARRAYSZ', 'DT_PRELINK_ARRAY', 'DT_PRELINK_ARRAYSZ',
                    'DT_RUNPATH', 'DT_RPATH',
                    'DT_FLAGS', 'DT_SYMBOLIC', 'DT_TEXTREL', 'DT_BINDNOW',
                    'DT_RELA', 'DT_RELASZ', 'DT_RELAENT',
                    'DT_REL', 'DT_RELSZ', 'DT_RELENT',
                    'DT_VERNEED', 'DT_VERNEEDNUM', 'DT_VERSYM', 'DT_VERDEF', 'DT_VERDEFNUM',
                ]

                off = 0
                while off < len(ph.data):
                    ent = ElfDyn().unpack_from(self.codec, ph.data, off)
                    off += self.codec.dyn.size
                    if ent.tag == 'DT_NULL':
                        break

                    dynd[ent.tag].append(ent)
                    if not ent.tag in known:
                        self.dyn_unk.append(ent)

                dynstr, strsz = dynd['DT_STRTAB'], dynd['DT_STRSZ']
                if all((dynstr, strsz)):
                    strtab, strsz = dynstr[0].val, strsz[0].val
                    # NOTE: readstr doesn't bounds check strtab
                    # strtab = str(self.read(strtab, strsz))
                    self.needed = [self.readstr(strtab + n.val) for n in dynd['DT_NEEDED']]

                    symtab, syment, symhash, gnuhash = dynd['DT_SYMTAB'], dynd['DT_SYMENT'], dynd['DT_HASH'], dynd['DT_GNU_HASH']
                    if all((symtab, syment, any((symhash, gnuhash)))):
                        symtab, syment = symtab[0].val, syment[0].val
                        if gnuhash:
                            addr = gnuhash[0].val
                            s = self.segment(addr)
                            cls = ElfGnuHash
                        elif symhash:
                            addr = symhash[0].val
                            s = self.segment(addr)
                            cls = ElfHash
                        base, count = cls.count(s.data[addr - s.vaddr:], self.codec.addr)

                        assert(syment == self.codec.sym.size)
                        s = self.segment(symtab)
                        symtab = self.read(symtab, count * syment)
                        for i in xrange(count):
                            sym = ElfSym().unpack_from(self.codec, symtab, i * syment)
                            if i >= base:
                                sym.dyn = True
                            sym.name = self.readstr(strtab + sym.name_off)
                            self.symtab.append(sym)

                if dynd['DT_INIT']:
                    self.init.append(dynd['DT_INIT'][0].val)
                if dynd['DT_FINI']:
                    self.fini.append(dynd['DT_FINI'][0].val)

                def read_ptr_arr(vaddr, size):
                    if not vaddr or not size:
                        return []
                    out = []
                    data = self.read(vaddr[0].val, size[0].val)
                    asize = self.codec.addr.size
                    data = data[:len(data) % asize]
                    for i in xrange(0, len(data), asize):
                        out.append(self.codec.addr.unpack(data[i:i+asize])[0])
                    return out

                self.preinit += read_ptr_arr(dynd['DT_PREINIT_ARRAY'], dynd['DT_PREINIT_ARRAYSZ'])
                self.init += read_ptr_arr(dynd['DT_INIT_ARRAY'], dynd['DT_INIT_ARRAYSZ'])
                self.fini += read_ptr_arr(dynd['DT_FINI_ARRAY'], dynd['DT_FINI_ARRAYSZ'])

                # if both RPATH and RUNPATH are set, RUNPATH wins
                runpath = dynd.get('DT_RUNPATH', dynd['DT_RPATH'])
                if runpath:
                    self.rpath = self.readstr(runpath[0].val).split(':')

                if dynd['DT_FLAGS']:
                    self.dyn_flags = dynd['DT_FLAGS']
                if dynd['DT_SYMBOLIC']:
                    self.dyn_flags |= DF['DF_SYMBOLIC'].code
                if dynd['DT_TEXTREL']:
                    self.dyn_flags |= DF['DF_TEXTREL'].code
                if dynd['DT_BINDNOW']:
                    self.dyn_flags |= DF['DF_BINDNOW'].code

                def load_rel(rel, relsz, relent, cls):
                    rels = []
                    if all((rel, relsz, relent)):
                        rel, relsz, relent = rel[0].val, relsz[0].val, relent[0].val
                        data = self.read(rel, relsz)
                        for i in xrange(0, len(data), relent):
                            ent = cls().unpack_from(self.codec, data[i:i+relent])
                            rels.append(ent)
                    return rels

                self.rel = load_rel(dynd['DT_RELA'], dynd['DT_RELASZ'], dynd['DT_RELAENT'], ElfRela)
                rel = load_rel(dynd['DT_REL'], dynd['DT_RELSZ'], dynd['DT_RELENT'], ElfRel)
                for ent in rel:
                    x = ElfRela()
                    x.off = ent.off
                    x.info = ent.info
                    x.addend = self.codec.addr.unpack(self.read(x.off, self.addrCoding.size))[0]
                    self.rel.append(x)

    def _unpack_ident(self, block, offset):
        if not self.ident:
            self.ident = ElfFileIdent()
        self.ident.unpack_from(block, offset)
        
    def _unpack_file_header(self, block, offset):
        if not self.header:
            self.header = ElfFileHeader()
        self.header.unpack_from(self.codec, block, offset + self.ident.coder.size)

    def _unpack_section_headers(self, block, offset):
        if self.header.shoff != 0:
            sectionCount = self.header.shnum
            for i in range(sectionCount):
                sh = ElfSectionHeader().unpack_from(self.codec, block,
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
            if phnum == ElfProgramHeader.PN_XNUM:
                phnum = self.progs[0].info

            for i in range(phnum):
                ph = ElfProgramHeader().unpack_from(
                    self.codec, block,
                    offset + self.header.phoff + (i * self.header.phentsize),
                )
                base = offset + ph.offset
                ph.data = bytearray(block[base:base + ph.filesz])
                self.progs.append(ph)

    def pack_into(self, block, offset=0):
        """Pack the entire file.  Rewrite offsets as necessary."""
        total, pdoff, sdoff, shoff, phoff = self._offsets(offset)

        self._pack_program_data(block, pdoff)
        self._pack_section_data(block, sdoff)
        self._pack_file_header(block, offset, shoff, phoff)
        self._pack_program_headers(block, phoff)
        self._pack_section_headers(block, shoff)

    def _offsets(self, offset=0):
        """Current packing layout is:

        * ident + header
        * program data
          * program headers (in segment with offset 0)
        * section data
        * section headers"""

        x = offset
        x += self.header.ehsize

        # find the PHDR
        phdr = None
        for ph in self.progs:
            if ph.type == 'PT_PHDR':
                phdr = ph
                break

        pdoff = x

        for p in self.progs:
            if p.offset == 0 and p.type == 'PT_LOAD':
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
            phoff = x
            phsize = len(self.progs) * self.header.phentsize
            x += phsize

        for p in self.progs:
            if p.virtual or not p.type == 'PT_LOAD':
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

        # make sure there's shstrtab to update
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

    def _regen_dyn(self):
        for pdyn in self.progs:
            if pdyn.type == 'PT_DYNAMIC':
                break
        else:
            # no PT_DYNAMIC  segment
            return

        for ph in self.progs:
            if ph.flags & PF['PF_W'].code:
                # HACK: PT_DYNAMIC data is moved to the end of the first segment
                # NOTE: the old PT_DYNAMIC is ignored
                break
        else:
            # TODO: we should maybe just add a dedicated LOAD segment for DYNAMIC
            print('WARNING: Could not inject PT_DYNAMIC. The file will likely fail to link.')
            return

        # `dyndata` is all data required by the PT_DYNAMIC segment
        # such as strtab, symtab, etc
        # `dynent` is the actual PT_DYNAMIC table
        dynoff = ph.vaddr + len(ph.data)
        dyndata = bytearray()
        pos = lambda: dynoff + len(dyndata)
        addr = lambda a: self.codec.addr.pack(a)
        dt = []

        strings = [b''] + [sym.name for sym in self.symtab] + self.needed
        if self.soname:
            strings.append(self.soname)
        if self.rpath:
            rpath = ':'.join(self.rpath)
            strings.append(rpath)

        strd = {}
        spos = 0
        for name in strings:
            strd[name] = spos
            spos += len(name) + 1

        if self.needed:
            for name in self.needed:
                dt.append(('DT_NEEDED', strd[name]))

        if self.soname:
            dt.append(('DT_SONAME', strd[self.soname]))

        if self.init:
            initaddr = b''.join(addr(a) for a in self.init)
            dt.append(('DT_INIT_ARRAY', pos()))
            dt.append(('DT_INIT_ARRAYSZ', len(initaddr)))
            dyndata += initaddr

        if self.preinit:
            preinitaddr = b''.join(addr(a) for a in self.init)
            dt.append(('DT_PREINIT_ARRAY', pos()))
            dt.append(('DT_PREINIT_ARRAYSZ', len(preinitaddr)))
            dyndata += preinitaddr

        if self.fini:
            finiaddr = b''.join(addr(a) for a in self.init)
            dt.append(('DT_FINI_ARRAY', pos()))
            dt.append(('DT_FINI_ARRAYSZ', len(finiaddr)))
            dyndata += finiaddr

        # write strtab
        strtab = bytearray(b'\0'.join(strings) + b'\0')
        dt.append(('DT_STRTAB', pos()))
        dt.append(('DT_STRSZ', len(strtab)))
        dyndata += strtab

        # write symtab
        names = []
        dnames = []
        symtab = list(sorted(self.symtab, key=lambda x: x.dyn))
        symbase = 0
        syment = self.codec.sym.size
        symdata = bytearray(syment * len(symtab))
        for i, sym in enumerate(symtab):
            if sym.dyn and not symbase:
                symbase = i
                dnames.append(sym.name)
            names.append(sym.name)
            sym.name_idx = strd[sym.name]
            sym.pack_into(self.codec, symdata, i * syment)

        dt.append(('DT_SYMTAB', pos()))
        dt.append(('DT_SYMENT', syment))
        dyndata += symdata

        dt.append(('DT_HASH', pos()))
        hashtab = ElfHash.build(symbase, dnames, self.codec.addr)
        dyndata += hashtab

        if self.rpath:
            dt.append(('DT_RUNPATH', strd[rpath]))

        dt.append(('DT_FLAGS', self.dyn_flags))

        # TODO: write rels
        dt.append(('DT_RELA', 0))
        dt.append(('DT_RELASZ', 0))
        dt.append(('DT_RELAENT', self.codec.rela.size))

        ph.data += dyndata

        dyn = [ElfDyn(DT[a], b) for a, b in dt]
        dyn.extend(self.dyn_unk)
        dyn.append(ElfDyn(DT['DT_NULL'], 0))

        dynent = bytearray(len(dyn) * self.codec.dyn.size)
        for i, ent in enumerate(dyn):
            ent.pack_into(self.codec, dynent, i * self.codec.dyn.size)

        pdyn.vaddr = ph.vaddr + len(ph.data)
        pdyn.filesz = pdyn.memsz = len(dynent)
        # we don't actually store any data here, it all piggybacks on another segment
        pdyn.virtual = True

        ph.data += dynent
        ph.filesz = ph.memsz = len(ph.data)
        for s in self.sections:
            if s.name == '.dynamic':
                s.addr = pdyn.vaddr
                s.size = pdyn.filesz
                break

    def _pack_file_header(self, block, offset, shoff, phoff):
        """Determine and set current offsets then pack the file header."""
        self.ident.pack_into(block, offset)

        self.header.phnum = len(self.progs)
        self.header.shnum = len(self.sections)
        self.header.shoff = shoff if len(self.sections) > 0 else 0
        self.header.phoff = phoff if len(self.progs) > 0 else 0
        self.header.pack_into(self.codec, block, offset + self.ident.coder.size)

    def _pack_program_headers(self, block, offset=0):
        """Pack the program headers."""
        for i, ph in enumerate(self.progs):
            ph.pack_into(self.codec, block, offset + (i * self.header.phentsize))

    def _pack_program_data(self, block, offset=0):
        """Pack the program header data. As a side effect, set the offset in the program headers."""
        for i, prog in enumerate(self.progs):
            if prog.virtual:
                continue

            if prog.type == 'PT_LOAD' and prog.offset == 0:
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
                if phd.type == 'PT_LOAD':
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
            sh.pack_into(self.codec, block, offset + (i * self.header.shentsize))

    @property
    def _size(self):
        return self._offsets()[0]

    def sectionName(self, section):
        """Given a section, return its name.

        :param :py:class:`ElfSectionHeader` section:"""
        try:
            data = self.sections[self.header.shstrndx].data[section.nameoffset:]
            return str(data.split(b'\0', 1)[0])
        except Exception:
            pass

    def __repr__(self):
        return ('<{0}@{1}: name=\'{2}\', ident={3}, header={4}>'
                .format(self.__class__.__name__, hex(id(self)), self.name, self.ident, self.header))

    # helper methods below
    def save(self, path):
        """Pack and save elf file to path"""
        self._regen_section_name_table()
        self._regen_dyn()

        with io.open(path, 'wb') as f:
            x = bytearray(self._size)
            self.pack_into(x)
            f.write(x)

    @property
    def entry(self):
        return self.header.entry

    @entry.setter
    def entry(self, val):
        self.header.entry = val

    def segment(self, vaddr):
        progs = [p for p in reversed(self.progs) if vaddr in p and p.type == 'PT_LOAD']
        if progs:
            return progs[0]
        raise IOError('could not find segment containing %#x' % vaddr)

    def readstr(self, vaddr):
        """Read a string from virtual address space."""
        ph = self.segment(vaddr)
        off = vaddr - ph.vaddr
        end = ph.data.find(b'\0', off)
        if end < 0:
            end = len(ph.data) - off
        size = end - off
        x = bytearray(size)
        x[:size] = ph.data[off:off+size]
        return str(x)

    def read(self, vaddr, size):
        """Read data from virtual address space. Won't cross program header boundaries."""
        ph = self.segment(vaddr)
        off = vaddr - ph.vaddr
        size = min(ph.vsize - off, size)
        x = bytearray(size)
        x[:size] = ph.data[off:off+size]
        return x

    def write(self, vaddr, data):
        """Write data to virtual address space. Won't cross program header boundaries."""
        ph = self.segment(vaddr)
        off = vaddr - ph.vaddr
        size = min(ph.memsz - off, len(data))
        if off + ph.vsize >= len(data):
            ph.data[off:off+size] = data[:size]
        else:
            raise IOError('not enough space to write 0x%x bytes at vaddr 0x%x' % (len(data), vaddr))

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
    """

    type = Prop(ET)
    """The 'type', (sic), of the file which represents whether this file
    is an executable, relocatable object, shared library, etc.
    Encoded using :py:class:`ET`."""

    machine = Prop(EM)
    """Specifies the processor architecture of the file.  Encoded using :py:class:`EM`."""

    version = None
    """Specifies the version of the ELF format used for this file.
    Should be 1 in most cases.  Extensions are expected to increment
    the number."""

    entry = None
    """Virtual start address when this file is converted into a process.  Zero if not used."""

    phoff = None
    """Offset in bytes into this file at which the program header table,
    (:py:class:`ElfProgramHeader`), starts."""

    shoff = None
    """Offset in bytes into this file at which the section header table,
    (:py:class:`ElfSectionHeader`), starts."""

    flags = None
    """Any processor specific flags for this file."""

    ehsize = None
    """Size in bytes of the ELF file header, (:py:class:`ElfFileHeader`), as represented in this file."""
    
    phentsize = None
    """Size in bytes of a program header table entry, (:py:class:`ElfProgramHeader`),
    as represented in this file.  All entries are the same size."""

    phnum = None
    """A count of the number of program header table entries, (:py:class:`ElfProgramHeader`), in this file."""

    shentsize = None
    """Size in bytes of a section table entry, (:py:class:`ElfSectionHeader`),
    as represented in this file.  All entries are the same size."""

    shnum = None
    """A count of the number of section header table entries, (:py:class:`ElfSectionHeader`), in this file."""

    shstrndx = None
    """The section header table index of the section name string table. (SHN_UNDEF if there is none)."""

    shstrhdr = None
    """Reference to the shstrtab section, in case you move sections around before saving."""

    def unpack_from(self, codec, block, offset=0):
        (self.type, self.machine, self.version, self.entry,
         self.phoff, self.shoff, self.flags, self.ehsize,
         self.phentsize, self.phnum, self.shentsize, self.shnum,
         self.shstrndx) = codec.fileHeader.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        assert(self.type in ET)
        assert(self.machine in EM)

        codec.fileHeader.pack_into(block, offset, self.type.code, self.machine.code,
                             self.version if self.version is not None else 1,
                             self.entry if self.entry is not None else 0,
                             self.phoff if self.phoff is not None else 0,
                             self.shoff if self.shoff is not None else 0,
                             self.flags if self.flags is not None else 0,
                             self.ehsize if self.ehsize is not None else codec.fileHeader.size + ElfIdent.coder.size,
                             self.phentsize if self.phentsize is not None else codec.programHeader.size,
                             self.phnum if self.phnum is not None else 0,
                             self.shentsize if self.shentsize is not None else codec.sectionHeader.size,
                             self.shnum if self.shnum is not None else 0,
                             self.shstrndx if self.shstrndx is not None else 0)
        return self

    def __repr__(self):
        return ('<{0}@{1}: type={2}, machine={3}, version={4},'
                ' entry={5}, phoff={6}, shoff={7}, flags={8},'
                ' ehsize={9}, phnum={10}, shentsize={11}, shnum={12},'
                ' shstrndx={13}>'
                .format(self.__class__.__name__, hex(id(self)), self.type, self.machine,
                        self.version, hex(self.entry or 0), self.phoff, self.shoff,
                        hex(self.flags or 0), self.ehsize, self.phnum, self.shentsize,
                        self.shnum, self.shstrndx))


class ElfSectionHeader(StructBase):
    """
    This abstract base class corresponds to an entry in `the section
    header table
    <http://www.sco.com/developers/gabi/latest/ch4.sheader.html#section_header>`_.
    This includes ten fields.

    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`Coding` subclasses.
    """

    nameoffset = None
    """Offset into the `section header string table section
    <http://www.sco.com/developers/gabi/latest/ch4.strtab.html>`_
    of the name of this section."""

    name = None
    """The name of this section."""

    type = Prop(SHT)
    """Section type encoded with :py:class:`SHT`."""

    flags = None
    """Flags which define miscellaneous attributes.  These are bit flags
    which are or'd together.  The individual bit-flags are encoded using :py:class:`SHF`."""
    
    addr = None
    """The load address of this section if it will appear in memory during a running process."""

    offset = None
    """Byte offset from the start of the file to the beginning of the content of this section."""

    size = None
    """Size in bytes of the content of this section."""
    
    link = None
    """A section header table index. It's meaning varies by context."""

    info = None
    """Extra information. It's meaning varies by context."""

    addralign = None
    """Section alignment constraints."""

    entsize = None
    """If the section holds fixed sized entries then this is the size of each entry."""

    data = None
    """The original contents of the section, if the section has no address."""

    def unpack_from(self, codec, block, offset=0):
        (self.nameoffset, self.type, self.flags, self.addr,
         self.offset, self.size, self.link, self.info,
         self.addralign, self.entsize) = codec.sectionHeader.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        """
        .. note:: this is a special case.  *block* here must be the
            entire file or we won't know how to place our content.
        """
        codec.sectionHeader.pack_into(block, offset,
                             self.nameoffset, self.type.code, self.flags, self.addr,
                             self.offset, self.size, self.link, self.info,
                             self.addralign, self.entsize)
        return self

    def __repr__(self):
        return ('<{0}@{1}: name=\'{2}\', type={3},'
                ' flags={4}, addr={5}, offset={6}, size={7},'
                ' link={8}, info={9}, addralign={10}, entsize={11}>'
                .format(self.__class__.__name__, hex(id(self)), self.name,
                        self.type if self.type in SHT else hex(self.type),
                        hex(self.flags), hex(self.addr), self.offset, self.size,
                        self.link, self.info, self.addralign, self.entsize))

    def __contains__(self, vaddr):
        return vaddr >= self.addr and vaddr < self.addr + self.size


class ElfProgramHeader(StructBase):
    """
    This abstract base class corresponds to a `program header
    <http://www.sco.com/developers/gabi/latest/ch5.pheader.html>`_.
    
    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`Coding` subclasses.
    """

    PN_XNUM = 0xffff
    """Program header overflow number."""

    type = Prop(PT)
    """Segment type encoded with :py:class:`PT`."""

    offset = None
    """Offset in bytes from the beginning of the file to the start of this segment."""

    vaddr = None
    """Virtual address at which this segment will reside in memory when loaded to run."""

    paddr = None
    """Physical address in memory, when physical addresses are used."""

    filesz = None
    """Segment size in bytes in file."""

    memsz = None
    """Segment size in bytes when loaded into memory.  Must be at least
    :py:attr:`ElfProgramHeader.filesz` or greater.  Extra space is zeroed out."""

    flags = None
    """Flags for the segment.  Encoded using :py:class:`PF`."""

    align = None
    """Alignment of both segments in memory as well as in file."""

    data = bytearray(b'')
    """Contents of program header."""

    virtual = False
    """If True, don't try to pack data."""

    def __repr__(self):
        return ('<{0}@{1}: type={2},'
                ' offset={3}, vaddr={4}, paddr={5},'
                ' filesz={6}, memsz={7}, flags={8}, align={9}>'
                .format(self.__class__.__name__, hex(id(self)),
                        self.type,
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
        return self.type == 'PT_LOAD'

    def __contains__(self, vaddr):
        return vaddr >= self.vaddr and vaddr < self.vaddr + self.vsize

    def unpack_from(self, codec, block, offset=0):
        if codec.bits == 64:
            (self.type, self.flags, self.offset, self.vaddr,
             self.paddr, self.filesz, self.memsz, self.align) = codec.programHeader.unpack_from(block, offset)
        else:
            (self.type, self.offset, self.vaddr, self.paddr,
             self.filesz, self.memsz, self.flags, self.align) = codec.programHeader.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        if codec.bits == 64:
            codec.programHeader.pack_into(block, offset,
                                 self.type.code, self.flags, self.offset, self.vaddr,
                                 self.paddr, self.filesz, self.memsz, self.align)
        else:
            codec.programHeader.pack_into(block, offset,
                                 self.type.code, self.offset, self.vaddr, self.paddr,
                                 self.filesz, self.memsz, self.flags, self.align)
        return self


class ElfDyn(StructBase):
    tag = Prop(DT)
    val = None
    coder = None

    def __init__(self, tag=None, val=None):
        self.tag = tag
        self.val = val

    def unpack_from(self, codec, block, offset=0):
        self.tag, self.val = codec.dyn.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        codec.dyn.pack_into(block, offset, self.tag.code, self.val)
        return self

    def __repr__(self):
        return ('<{0}@{1}: tag={2}, val={3}>'
                .format(self.__class__.__name__, hex(id(self)),
                        self.tag.name if self.tag in DT else hex(self.tag.code),
                        self.val))


class ElfRel(StructBase):
    off = None
    info = None

    def unpack_from(self, codec, block, offset=0):
        self.off, self.info = codec.rel.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        codec.rel.pack_into(block, offset, self.off, self.info)
        return self

    def __repr__(self):
        return ('<{0}@{1}: off={2:#x}, info={3:#x}>'
                .format(self.__class__.__name__, hex(id(self)),
                    self.off, self.info))


class ElfRela(StructBase):
    off = None
    info = None
    addend = None

    def unpack_from(self, codec, block, offset=0):
        self.off, self.info, self.addend = codec.rela.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        codec.rela.pack_into(block, offset, self.off, self.info, self.addend)
        return self

    def __repr__(self):
        return ('<{0}@{1}: off={2:#x}, info={3:#x}, addend={4:#x}>'
                .format(self.__class__.__name__, hex(id(self)),
                    self.off, self.info, self.addend))


class ElfSym(StructBase):
    name = None
    name_off = None
    value = None
    size = None
    info = None
    other = None
    shndx = None
    dyn = False

    def unpack_from(self, codec, block, offset=0):
        if codec.bits == 64:
            self.name_off, self.info, self.other, self.shndx, self.value, self.size = codec.sym.unpack_from(block, offset)
        else:
            self.name_off, self.value, self.size, self.info, self.other, self.shndx = codec.sym.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        if codec.bits == 64:
            codec.sym.pack_into(block, offset, self.name_idx, self.info, self.other, self.shndx, self.value, self.size)
        else:
            codec.sym.pack_into(block, offset, self.name_off, self.value, self.size, self.info, self.other, self.shndx)
        return self

    def __repr__(self):
        return ('<{}@{}: name="{}", value={:#x}, size={}>, info={}, other={}, shndx={}, dyn={}'
                .format(self.__class__.__name__, hex(id(self)),
                    self.name, self.value, self.size, self.info, self.other, self.shndx, self.dyn))

class ElfVerDef:
    version = None
    flags = None
    idx = None
    count = None
    hash = None
    aux = None
    next = None

    def unpack_from(self, codec, block, offset=0):
        self.version, self.flags, self.idx, self.count, self.hash, self.aux, self.next = codec.verdef.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        codec.verdef.pack_into(block, offset, self.version, self.flags, self.idx, self.count, self.hash, self.aux, self.next)
        return self

    def __repr__(self):
        return ('<{}@{}: version={}, flags={}, idx={}, count={}, hash={}, aux={}, next={}>'
                .format(self.__class__.__name__, hex(id(self)),
                    self.version, self.flags, self.idx, self.count, self.hash, self.aux, self.next))

class ElfVerdAux:
    name = None
    next = None

    def unpack_from(self, codec, block, offset=0):
        self.name, self.next = codec.verdaux.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        codec.verdaux.pack_into(block, offset, self.name, self.next)
        return self

    def __repr__(self):
        return ('<{}@{}: name={}, next={}>'.format(self.__class__.__name__, hex(id(self)), self.name, self.next))

class ElfVerNeed:
    version = None
    count = None
    file = None
    aux = None
    next = None

    def unpack_from(self, codec, block, offset=0):
        self.version, self.count, self.file, self.aux, self.next = codec.sym.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        codec.sym.pack_into(block, offset, self.version, self.count, self.file, self.aux, self.next)
        return self

    def __repr__(self):
        return ('<{}@{}: version={}, count={}, file={}, aux={}, next={}>'.format(self.__class__.__name__, hex(id(self)),
                    self.version, self.count, self.file, self.aux, self.next))

class ElfVernAux:
    hash = None
    flags = None
    other = None
    name = None
    next = None

    def unpack_from(self, codec, block, offset=0):
        self.hash, self.flags, self.other, self.name, self.next = codec.vernaux.unpack_from(block, offset)
        return self

    def pack_into(self, codec, block, offset=0):
        codec.vernaux.pack_into(block, offset, self.hash, self.flags, self.other, self.name, self.next)
        return self

    def __repr__(self):
        return ('<{}@{}: hash={}, flags={}, other={}, name={}, next={}>'
                .format(self.__class__.__name__, hex(id(self)),
                    self.hash, self.flags, self.other, self.name, self.next))

class Codec:
    """Base codec for all ElfFile objects"""
    def __init__(self, order):
        self.order = order
        self.fileHeader = struct.Struct(order + self.fileHeader)
        self.sectionHeader = struct.Struct(order + self.sectionHeader)
        self.programHeader = struct.Struct(order + self.programHeader)
        self.dyn = struct.Struct(order + self.dyn)
        self.rel = struct.Struct(order + self.rel)
        self.rela = struct.Struct(order + self.rela)
        self.sym = struct.Struct(order + self.sym)
        self.verdef = struct.Struct(order + self.verdef)
        self.verdaux = struct.Struct(order + self.verdaux)
        self.verneed = struct.Struct(order + self.verneed)
        self.vernaux = struct.Struct(order + self.vernaux)
        self.addr = struct.Struct(order + self.addr)

class Codec32(Codec):
    """Base codec for 32-bit ElfFile objects"""
    bits = 32
    fileHeader = 'HHIIIIIHHHHHH'
    sectionHeader = 'IIIIIIIIII'
    programHeader = 'IIIIIIII'
    dyn = 'iI'
    rel = 'II'
    rela = 'III'
    sym = 'IIIBBH'
    verdef = 'HHHHIII'
    verdaux = 'II'
    verneed = 'HHIII'
    vernaux = 'IHHII'
    addr = 'I'

class Codec64(Codec):
    """Base codec for 64-bit ElfFile objects"""
    bits = 64
    fileHeader = 'HHIQQQIHHHHHH'
    sectionHeader = 'IIQQQQIIQQ'
    programHeader = 'IIQQQQQQ'
    dyn = 'qQ'
    rel = 'QQ'
    rela = 'QQQ'
    sym = 'IBBHQQ'
    verdef = 'HHHHIII'
    verdaux = 'II'
    verneed = 'HHIII'
    vernaux = 'IHHII'
    addr = 'Q'

class ElfFile32b(ElfFile):
    """Represents 32-bit, big-endian files."""
    codec = Codec32('>')

class ElfFile32l(ElfFile):
    """Represents 32-bit, little-endian files."""
    codec = Codec32('<')

class ElfFile64b(ElfFile):
    """Represents 64-bit, big-endian files."""
    codec = Codec64('>')

class ElfFile64l(ElfFile):
    """Represents 64-bit, little-endian files."""
    codec = Codec64('<')


_fileEncodingDict = {
    ElfClass['ELFCLASS32']: {
        ElfData['ELFDATA2LSB']: ElfFile32l,
        ElfData['ELFDATA2MSB']: ElfFile32b,
    },
    ElfClass['ELFCLASS64']: {
        ElfData['ELFDATA2LSB']: ElfFile64l,
        ElfData['ELFDATA2MSB']: ElfFile64b,
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
