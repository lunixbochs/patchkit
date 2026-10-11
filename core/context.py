import capstone
import binascii

import arch
import compiler
from func import Func
from util import stdlib
from util.elffile import EM
from util.patch.dis import irdis, IR, IRStream

addedPatchAddress = []

def pfcol(s):
    return '[\033[1m\033[32m%s\033[0m] ' % s

class Context(object):
    def __init__(self, binary, verbose=False):
        self.binary = binary
        self.verbose = verbose
        machine = EM[binary.elf.header.machine]
        cflags = binary.linker.cflags
        if machine == EM['EM_386']:
            self.arch = arch.x86()
            cflags.append('-m32')
        elif machine == EM['EM_X86_64']:
            self.arch = arch.x86_64()
            cflags.append('-m64')
        elif machine == EM['EM_ARM']:
            self.arch = arch.arm()
        else:
            raise NotImplementedError("Unknown machine: %s" % machine)

        self.current_func = None
        self.func_printed = None
        self.marked_funcs = []

    def relopen(self, name, *args, **kwargs):
        return open(self.binary.path + '.' + name, *args, **kwargs)

    @property
    def elf(self):
        return self.binary.elf

    @property
    def entry(self):
        return self.elf.entry

    @entry.setter
    def entry(self, val):
        self.info(pfcol('MOVE ENTRY POINT') + '-> 0x%x' % val)
        self.elf.entry = val

    def funcs(self, marked=False):
        addrs = []
        self.func_printed = None
        try:
            funcs = self.relopen('funcs')
        except IOError:
            return

        for line in funcs:
            s, e = line.strip().split(' ')
            start, end = int(s, 16), int(e, 16)
            func = Func(self, start, end - start)
            self.current_func = func
            yield func
            self.current_func = None

        if marked:
            tmp = self.marked_funcs[:]
            for func in tmp:
                yield func

    def info(self, *args, **kwargs):
        for arg in args:
            for line in arg.split('\n'):
                indent = '  '
                if self.current_func:
                    if self.func_printed != self.current_func:
                        if self.func_printed is not None:
                            print
                        func = self.current_func
                        print indent + '[FUNC] @0x%x-0x%x' % (func.addr, func.addr + func.size)
                        self.func_printed = self.current_func
                    indent += ' '
                if kwargs.get('prefix'):
                    indent += kwargs['prefix'] + ' '
                print indent + line

        dis = kwargs.get('dis', None)
        if dis:
            self.info(self.pdis(dis), prefix=kwargs.get('prefix'))

    # TODO: show warn/error at the end, and colorize
    def warn(self, *args, **kwargs):
        kwargs['prefix'] = '\033[1m\033[33m[WARN]\033[0m'
        self.info(*args, **kwargs)

    def error(self, *args, **kwargs):
        kwargs['prefix'] = '\033[1m\033[31m[ERR]\033[0m'
        self.info(*args, **kwargs)

    def debug(self, *args, **kwargs):
        if self.verbose:
            self.info(*args, **kwargs)

    def pdis(self, dis):
        if not dis: return ''
        if isinstance(dis, capstone.CsInsn):
            dis = [dis]

        out = []
        nop_start = 0
        nop_bytes = ''
        nops = 0
        just = max(len(i.bytes) for i in dis)

        pnop = lambda: ('0x%x: %s nop (x%d)' % (nop_start, binascii.hexlify(nop_bytes).ljust(just * 2), nops))

        for i in dis:
            if i.mnemonic == 'nop':
                if not nops:
                    nop_start = i.address
                nop_bytes += str(i.bytes)
                nops += 1
            else:
                if nops:
                    out.append(pnop())
                    nops = 0
                    nop_bytes = ''
                data = binascii.hexlify(i.bytes).ljust(just * 2)
                out.append('0x%x: %s %s %s' % (i.address, data, i.mnemonic, i.op_str))
        if nops:
            out.append(pnop())
        return '\n'.join(out)

    # patch API below

    def asm(self, asm, addr=0, att_syntax=False):
        return self.arch.asm(asm, addr=addr, att_syntax=att_syntax)

    def dis(self, addr, size=64):
        return self.arch.dis(self.elf.read(addr, size), addr)

    def disiter(self, addr):
        # TODO: handle reading past the end
        dis = self.dis(addr, 128)
        while True:
            if not dis:
                break
            for ins in dis:
                yield ins
            ins = dis[-1]
            addr = ins.address + len(ins.bytes)
            dis = self.dis(addr, 128)

    def irdis(self, addr, size=64):
        return irdis(self.dis(addr, size))

    def irstream(self, addr):
        return IRStream(self.disiter(addr))

    def ir(self, asm, **kwargs):
        return irdis(self.arch.dis(self.asm(asm, **kwargs), addr=kwargs.get('addr', 0)))

    def make_writable(self, addr):
        for prog in self.elf.progs:
            if prog.isload:
                if addr in prog and prog.flags & 2 == 0:
                    self.debug('[!] Segment made writable: 0x%x-0x%x' % (prog.vaddr, prog.vaddr + prog.memsz))
                    prog.flags |= 2

    def search(self, data):
        tmp = data
        if len(data) > 10:
            tmp = data[:8] + '..'

        for segment in self.binary.mem.segments:
            try:
                idx = segment.data.index(data)
                if idx >= 0:
                    addr = segment.addr + idx
                    self.debug(pfcol('SEARCH') + '"%s" found at 0x%x' % (tmp, addr))
                    return addr
            except ValueError:
                pass
        self.error(pfcol('SEARCH') + '"%s" not found.' % tmp)

    def hook(self, src, dst, first=False, noentry=False):
        # hooking the entry point is a special, more efficient case
        if src == self.entry and not noentry:
            if first:
                self.binary.entry_hooks.insert(0, dst)
            else:
                self.binary.entry_hooks.append(dst)
            self.debug(pfcol('HOOK') + 'ENTRY -> 0x%x' % dst)
            return
        self.debug(pfcol('HOOK') + '@0x%x -> 0x%x' % (src, dst))
        self.make_writable(src)

        alloc = self.binary.next_alloc()
        # TODO: what if call(0) is smaller than the call to our hook?
        call = self.asm(self.arch.call(alloc), addr=alloc)

        # our injected code is guaranteed to be sequential and unaligned
        # so we can inject twice and call the first one
        evicted = ''
        # eh we'll just trust that a call won't be anywhere near 64 bytes
        ins = self.dis(src)
        for ins in ins:
            evicted += ins.bytes
            if len(evicted) >= len(call):
                break

        evicted = evicted.strip(self.asm(self.arch.nop())) # your loss
        if len(evicted) == 0 and False:
            self.patch(src, asm=self.arch.call(dst))
            return

        # augh I don't like this, need to double-check how MS works
        # at least recursion works?
        # 1. replace patch-site with call to us
        # 2. call hook addr
        # 3. overwrite patch-site with saved data, then a jmp to us
        # 4. jmp to patch site
        # 5. patch site executes first few instructions, then jmps back to us
        # 6. re-hook the patch site (and remove the jmp)
        # 7. jmp to where the tmp jmp was

        emptyjmp = self.asm(self.arch.jmp(self.binary.next_alloc()), addr=src)
        jmpoff = src + len(evicted)
        jmpevict = str(self.elf.read(jmpoff, len(emptyjmp)))

        stage0 = evicted + jmpevict
        # TODO: self.alloc()?
        stage1_addr = self.binary.alloc(len(stage0), target='patch')
        stage2_addr = self.binary.alloc(len(stage0), target='patch')

        # memcpy needs to be pc-relative
        base = self.binary.next_alloc()
        hook1 = self.inject(asm=';'.join((
            self.arch.call(dst),
            self.arch.memcpy(src - base, stage2_addr - base, len(stage0)),
            self.arch.jmp(src),
        )), internal=True)
        base = self.binary.next_alloc()
        hook2 = self.inject(asm=';'.join((
            self.arch.memcpy(src - base, stage1_addr - base, len(stage0)),
            self.arch.jmp(jmpoff),
        )), internal=True)

        # we need to overwrite both stages because we didn't know the hook addrs at the time
        stage1 = self.asm(';'.join(
            (self.arch.jmp(hook1),) + (self.arch.nop(),) * (len(evicted) - len(emptyjmp)),
        ), addr=src) + jmpevict
        self.patch(stage1_addr, raw=stage1, is_asm=True, internal=True, desc='hook stage 1')
        stage2 = evicted + self.asm(self.arch.jmp(hook2), addr=jmpoff)
        self.patch(stage2_addr, raw=stage2, is_asm=True, internal=True, desc='hook stage 2')

        # TODO: act more like mobile substrate wrt orig calling?
        # that is, make calling orig optional
        self.patch(src, raw=stage1, is_asm=True, internal=True, desc='hook entry point')

    def _lint(self, addr, raw, typ, is_asm=False):
        if typ == 'asm' or is_asm:
            dis = self.arch.dis(raw, addr=addr)
            for ins in dis:
                if ins.bytes == 'ebfe'.decode('hex'):
                    self.warn('JMP 0 emitted!')

    def _compile(self, addr, **kwargs):
        asm, jmp, sym, c, hex, raw = map(kwargs.get, ('asm', 'jmp', 'sym', 'c', 'hex', 'raw'))
        if sym is not None:
            jmp = self.resolve(sym)
        if jmp is not None:
            asm = self.arch.jmp(jmp)

        if asm is not None:
            raw = self.asm(asm, addr=addr)
            typ = 'asm'
        elif c is not None:
            raise NotImplementedError
            typ = 'c'
        elif hex is not None:
            raw = binascii.unhexlify(hex)
            typ = 'raw'
        elif raw is not None:
            typ = 'raw'
        else:
            raise Exception('inject/patch parameter missing: need one of (asm, c, hex, raw)')
        return raw, typ

    def inject(self, **kwargs):
        internal = kwargs.get('internal', False)
        is_asm = kwargs.get('is_asm', False)
        mark_func = kwargs.get('mark_func', False)
        return_size = kwargs.get('size', False)
        target = kwargs.get('target', 'patch')
        desc = kwargs.get('desc', '')
        retWarn = kwargs.get('retWarn', True)
        if desc:
            desc = ' | "%s"' % desc

        addr = self.binary.next_alloc(target)
        c = kwargs.get('c')
        if c:
            asm = compiler.compile(c, self.binary.linker)
            raw = self.asm(asm, addr=addr, att_syntax=True)
            typ = 'c'
            is_asm = True
        else:
            raw, typ = self._compile(addr, **kwargs)

        self._lint(addr, raw, typ, is_asm=kwargs.get('is_asm'))
        if typ == 'asm':
            ret = self.asm(self.arch.ret())
            if retWarn and raw[-len(ret):] != ret and not internal:
                self.warn('Injected asm does not return!')

        self.info(pfcol('INJECT') + '@0x%x-0x%x%s' % (addr, addr + len(raw), desc))
        if not kwargs.get('silent'):
            if typ == 'asm' or is_asm:
                self.debug(dis=self.arch.dis(raw, addr=addr))
            else:
                self.debug(binascii.hexlify(raw))

        addr = self.binary.alloc(len(raw), target=target)
        if mark_func:
            self.marked_funcs.append(Func(self, addr, len(raw)))
        self.elf.write(addr, raw)
        if return_size:
            return addr, len(raw)
        else:
            return addr

    def genNop(self, number):
        if not isinstance(number, int):
            return
        ret = ""
        for x in range(number):
            ret = ret + "nop;"
        return ret

    def checksize(self, addr, **kwargs):
        raw, typ = self._compile(addr, **kwargs)
        return len(raw)

    def autoReplaceString(self, addr, **kwargs):
        newStr = kwargs.get('newStr', "")
        oldStr = kwargs.get('oldStr', "")
        desc = kwargs.get('desc', '')

        if (len(newStr) > len(oldStr) and len(oldStr) > 0):
            self.error(hex(addr) + " " + desc + " new string is too long.")
            return

        if len(oldStr) > len(newStr):
            string_val = "\0" * (len(oldStr) - len(newStr)) * 2
            newStr = newStr + string_val

        hnewStr = "".join([hex(ord(x)) for x in newStr]).replace("0x", "")

        self.patch(addr, hex=hnewStr, desc=desc)


    def autoApplyPatch(self, addr, **kwargs):
        #addr = kwargs.get('addr', '')
        newAsm = kwargs.get('newAsm', "").rstrip().lstrip()
        oldAsm = kwargs.get('oldAsm', "").rstrip().lstrip()
        postAsm = kwargs.get('postAsm', "").rstrip().lstrip()
        desc = kwargs.get('desc', '')
        checkDep = kwargs.get('checkDep', False)
        ijAddr = kwargs.get('ijAddr', 0)
        ignoreDuplicate = kwargs.get('ignoreDuplicate', False)


        lastNewAsm = ""
        newAsm = newAsm.split("\n")
        for i in range(len(newAsm)):
            newAsm[i] = newAsm[i].split(" #")
            newAsm[i] = newAsm[i][0].rstrip().lstrip()
            if len(newAsm[i]) > 0:
                lastNewAsm = newAsm[i]
        s = "\n"
        newAsm = s.join(newAsm)

        lastNewAsm = lastNewAsm.split(" ")

        needAddJump = (lastNewAsm[0].lower() !="jmp" and lastNewAsm[0].lower() !="ret" and lastNewAsm[0].lower() !="retn")

        oldSize = self.checksize(addr, asm=oldAsm, is_asm=True)

        realNextAddress = nextAddress = addr + oldSize

        if not checkDep:
            self.info("")

            if ignoreDuplicate == False and addr in addedPatchAddress:
                self.error('Address already has a patch from ' + hex(addr) + " to " + hex(realNextAddress - 1) + " set ignoreDuplicate to True to ignore this.")
                raise Exception("Add param ignoreDuplicate to ignore this.")

            addedPatchAddress.append(addr)

        if len(postAsm) > 0:
            postAsm = postAsm.replace("0xRealReturnAddress", "0x%x" % realNextAddress)
            nextAddress = self.inject(asm=postAsm + "\njmp 0x%x" % nextAddress , desc = 'post-asm | "%s"' % desc, retWarn = False)

        newAsm = newAsm.replace("0xReturnAddress", "0x%x" % nextAddress)
        newAsm = newAsm.replace("0xRealReturnAddress", "0x%x" % realNextAddress)
        newAsm = newAsm.replace("0xBeginOfBlock", "0x%x" % addr)

        newSize = self.checksize(addr, asm=newAsm, is_asm=True)

        if oldSize == newSize:
            self.patch(addr, asm=newAsm, is_asm=True, desc = desc)
            return 0
        elif oldSize > newSize:
            if checkDep:
                self.patch(addr, asm=newAsm, is_asm=True, desc = desc)
                return addr + newSize + 1

            if needAddJump:
                adding = "jmp 0x%x" % nextAddress
                jmpSize = self.checksize(addr + newSize, asm=adding, is_asm=True)
            else:
                adding = ""
                jmpSize = 0
            #check if we can use jmp instead of nop

            if oldSize - newSize <= jmpSize + 6:    #If the remaining space is less than 6 nop in case we add jmp, just ignore the jump and add nop only
                adding = self.genNop(oldSize - newSize)
            else: #if oldSize - newSize - jmpSize > 0:   #Otherwise, if enough space for jump, just add it
                adding = adding + "\n" + self.genNop(oldSize - newSize - jmpSize)

            self.patch(addr, asm=newAsm + ";" + adding, is_asm=True, desc = desc)
        else: #newSize > oldSize: not enough space to insert
            if checkDep:
                self.error(hex(addr) + " Cannot create jump:\"" + newAsm + "\" (" + str(newSize) + " byte) to replace \"" + oldAsm + "\" (" + str(oldSize) + " byte)")
                quit()
            if desc:
                desc = ' | "%s"' % desc

            self.warn(hex(addr) + " Code space is " + str(oldSize) + " byte, new code need " + str(newSize) + " byte, injecting mode" + desc)

            if needAddJump:
                newAsm = newAsm + "; jmp 0x%x" % nextAddress
            ijAddr = self.inject(asm=newAsm, desc = "", retWarn = False)

            newJump = 'jmp 0x%x' % ijAddr

            return self.autoApplyPatch(addr, newAsm=newJump, oldAsm=oldAsm, desc = "", checkDep=True, ijAddr=ijAddr)

    def patch(self, addr, **kwargs):
        raw, typ = self._compile(addr, **kwargs)
        lRaw = len(raw)
        desc = kwargs.get('desc', '')
        if desc:
            desc = ' | "%s"' % desc

        self.info(pfcol('PATCH') + '@0x%x-0x%x%s' % (addr, addr + lRaw, desc))
        if lRaw == 0:
            self.warn('Empty patch.')
            return

        if typ == 'asm' or kwargs.get('is_asm'):
            size = len(''.join([str(i.bytes) for i in self.dis(addr, lRaw)]))
            if size != lRaw and not kwargs.get('internal'):
                self.warn('Assembly patch is not aligned with underlying instructions. size = ' + str(size) + " raw = " + str(lRaw) + " addr " + hex(addr + lRaw + 1))

        self._lint(addr, raw, typ, is_asm=kwargs.get('is_asm'))
        if not kwargs.get('silent'):
            if typ == 'asm' or kwargs.get('is_asm'):
                # collapse nulls
                old = self.elf.read(addr, lRaw)
                if old == '\0' * lRaw:
                    self.debug('- %s' % ('00' * lRaw))
                else:
                    for line in self.pdis(self.dis(addr, lRaw)).split('\n'):
                        self.debug('- %s' % line)
                for line in self.pdis(self.arch.dis(raw, addr=addr)).split('\n'):
                    self.debug('+ %s' % line)
            else:
                self.debug('- %s' % binascii.hexlify(self.elf.read(addr, lRaw)))
                self.debug('+ %s' % binascii.hexlify(raw))
        self.elf.write(addr, raw)

    def resolve(self, sym):
        return self.binary.linker.resolve(sym)

    def declare(self, symbols=None, headers='', source=''):
        self.binary.linker.declare(symbols, headers, source)

    def final(self, cb):
        self.binary.final(cb)
