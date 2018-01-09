from contextlib import contextmanager

import compiler
import re

STUB_PRE = '__attribute__((noinline,weak)) '
STUB_POST = r' { __asm__ __volatile__ (".ascii \"patchkit-skip\""); }'
STUB_PRAGMA = r'''
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
'''
STUB_PRAGMA_POP = r'''
#pragma GCC diagnostic pop
'''

func_re_1 = r'^(?P<all>(?P<desc>[^\s].+?(?P<name>%s)(?P<args>\(.*?\)))\s*{(?P<body>(.|\n)+?)^})$'

class Decl:
    def __init__(self, syms, source, headers):
        self.syms = syms or {}
        self.source = source
        self._headers = headers
        self.cflags = []

    @property
    def headers(self):
        descs = '\n'.join([desc + ';' for desc in self.syms.values()])
        return '\n'.join([self._headers, descs])

    def inject(self, linker, sym):
        # TODO: alloc pos will shift between inject()
        # could use a separate segment for linker.
        addrs = {}
        with linker.binary.collect() as pt:
            if len(self.syms) > 1:
                pt.info('[LINK] %s (includes [%s])' % (sym, ', '.join(self.syms.keys())))
            else:
                pt.info('[LINK] %s' % sym)
            asm = compiler.compile(self.source, linker, syms=self.syms.keys())

            table = '\n'.join([pt.arch.jmp('_' + sym) for sym in self.syms.keys()])
            sep = 'PATCHKITJMPTABLE'
            asm += ('\n.ascii "%s"\n__JMPTABLE__:\n' % sep) + table
            addr = pt.binary.next_alloc('link')
            raw = pt.asm(asm, addr=addr, att_syntax=True)
            raw, jmps = raw.rsplit(sep, 1)
            for sym, ins in zip(self.syms.keys(), pt.arch.dis(jmps, addr=addr + len(sep) + len(raw))):
                addrs[sym] = ins.operands[0].imm

            pt.inject(raw=raw, is_asm=True, target='link')
            return addrs

class Linker:
    def __init__(self, binary):
        self.binary = binary
        self.decls = []
        self.syms = {}
        self.addrs = {}

        self.pre_hooks = []
        self.post_hooks = []

    def __contains__(self, sym):
        return sym in self.syms

    def onpre(self, cb):
        self.pre_hooks.append(cb)

    def onpost(self, cb):
        self.post_hooks.append(cb)

    # symbol declaration helpers
    def declare(self, symbols=None, source='', headers=''):
        decl = Decl(symbols, source, headers)
        self.decls.append(decl)
        if symbols:
            for sym, desc in symbols.items():
                if sym in self.syms:
                    print 'Warning: duplicate symbol (%s)' % sym
                self.syms[sym] = (desc, decl)

    @staticmethod
    def getfunc(src, name):
        match = re.search(func_re_1 % re.escape(name), src, re.MULTILINE)
        return match.groupdict()

    def declarefuncs(self, src, names):
        for name in names:
            func = self.getfunc(src, name)
            self.declare(symbols={name: func['desc']}, source=func['all'])

    def autodecl(self, src):
        syms = [m[2] for m in re.findall(func_re_1 % '\w+', src, re.MULTILINE)]

        for name in syms:
            func = self.getfunc(src, name)
            self.declare(symbols={name: func['desc']}, source=func['all'])

    # link-time logic
    def inject(self, sym):
        self.addrs.update(self.syms[sym][1].inject(self, sym))

    def resolve(self, sym):
        if not sym in self.addrs:
            if sym in self.syms:
                self.inject(sym)
            else:
                raise NameError(sym)
        return self.addrs[sym]

    # TODO: need a pt context so I can print stuff
    # TODO: should debug the "after" code?
    def pre(self, code, syms=()):
        for cb in self.pre_hooks:
            tmp = cb(code, syms)
            if tmp:
                code = tmp

        headers = '\n'.join([decl.headers for decl in self.decls])
        stubs = []
        for name, (desc, _) in self.syms.items():
            if name in syms:
                continue
            stubs.append(STUB_PRE + desc + STUB_POST)
        stubs = STUB_PRAGMA + '\n'.join(stubs) + STUB_PRAGMA_POP
        code = '\n'.join([headers, code, stubs])
        return code
        # TODO: when does "source" get compiled here?
        # I think it'll get injected in post if a symbol is used

    def post(self, asm, syms=()):
        for cb in self.post_hooks:
            tmp = cb(asm, syms)
            if tmp:
                asm = tmp

        # strip stubs
        stubs = set(self.syms.keys()) - set(syms)
        refs = set()
        out = []
        buf = []
        skip = False
        valid_skip = False
        end_heuristic = re.compile(r'^([^.]\w+:|\s*)$')
        for line in asm.split('\n'):
            line = line.strip()
            if line.startswith(('.globl', '.weak_definition', '.weak', '.type', '.size')):
                continue
            if skip and (end_heuristic.match(line) or line.startswith('.cfi_endproc')):
                if not valid_skip:
                    out += buf
                buf = []
                skip = False
            if line.startswith(('.cfi_startproc', '.cfi_endproc')):
                continue
            for stub in stubs:
                if line.startswith('_%s:' % stub):
                    refs.add(stub)
                    skip = True
                    break

            if skip and 'patchkit-skip' in line:
                valid_skip = True
            if not skip:
                out.append(line)
            else:
                buf.append(line)

        asm = '\n'.join(out)
        while '\n\n\n' in asm:
            asm = asm.replace('\n\n\n', '\n\n')
        # resolve referenced addresses
        for ref in refs:
            # TODO: clean asm first?
            find_ref = r'\b_%s\b' % (re.escape(ref))
            if re.search(find_ref, asm):
                asm = re.sub(find_ref, '0x%x' % self.resolve(ref), asm)

        return asm
