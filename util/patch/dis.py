from capstone.x86_const import *
import re as _re

# TODO: this is all x86_specific :(
JMPS = [
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
    X86_INS_JMP,
    X86_INS_JNE,
    X86_INS_JNO,
    X86_INS_JNP,
    X86_INS_JNS,
    X86_INS_JO,
    X86_INS_JP,
    X86_INS_JRCXZ,
    X86_INS_JS,

    X86_INS_CALL,
    X86_INS_LOOP,
    X86_INS_LOOPE,
    X86_INS_LOOPNE,
]

class Base(object):
    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, repr(str(self)))

def re_match(maybe_re, s):
    pass

class Op(Base):
    ins = None
    op = None

    @classmethod
    def fromop(cls, ins, op):
        i = cls()
        i.any = False
        i.ins = ins
        i.op = op
        i.parse()
        return i

    def __ne__(self, other):
        return not(self == other)

class LabelOp(Op):
    def __init__(self, name=None, any=False):
        if name is None:
            any = True
        self.name = name
        self.any = any

    def __eq__(self, other):
        if other == LabelOp:
            return True
        return isinstance(other, LabelOp) and (other.name == self.name or self.any or other.any)

    def __str__(self):
        return self.name

class Imm(Op):
    def __init__(self, val=None, any=False):
        if val is None:
            val = 0
            any = True
        self.val = val
        self.any = any

    def parse(self):
        self.val = self.op.imm

    def __eq__(self, other):
        if isinstance(other, (int, long)) and (self.val == other):
            return True
        if other == Imm:
            return True
        return isinstance(other, Imm) and (other.val == self.val or self.any or other.any)

    def __cmp__(self, other):
        if not isinstance(other, Imm):
            raise TypeError
        return cmp(self.val, other.val)

    def __str__(self):
        if self.any:
            return '<imm>'
        if self.val >= 0:
            return '0x%x' % self.val
        else:
            return '-0x%x' % abs(self.val)

class Reg(Op):
    def __init__(self, reg=None, any=False, re=None):
        self.re = None
        self.reg = reg or ''
        self.any = any
        if re is not None:
            self.re = _re.compile(re)
        elif reg is None:
            self.any = True

    def parse(self):
        self.reg = self.ins.reg_name(self.op.reg)

    def __eq__(self, other):
        if isinstance(other, basestring) and (self.reg == other or self.re and self.re.match(other)):
            return True
        return isinstance(other, Reg) and (
            other.reg == self.reg or
            self.any or other.any or
            bool(self.re and self.re.match(other.reg)) or
            bool(other.re and other.re.match(self.reg)))

    def __str__(self):
        if self.any:
            return '<reg>'
        if self.re and not self.reg:
            return '/%s/' % self.re.pattern
        return self.reg

class Mem(Op):
    MEM_SIZE = {
        1: 'byte ptr',
        2: 'word ptr',
        4: 'dword ptr',
        8: 'qword ptr',
        10: 'xword ptr',
    }

    def __init__(self, size=0, base=None, index=None, segment=None, scale=1, off=0, any=False):
        self.size = size
        self.base = base
        self.index = index
        self.segment = segment
        self.scale = scale
        self.off = off
        self.any = any

    def parse(self):
        ins = self.ins
        op = self.op.mem

        self.size = self.op.size
        # TODO: op.size = dword ptr?
        if op.base:
            self.base = ins.reg_name(op.base)
        if op.index:
            self.index = ins.reg_name(op.index)
        if op.segment:
            # segment looks like es:[%s]
            self.segment = ins.reg_name(op.segment)
        self.scale = op.scale
        self.off = op.disp

    def __eq__(self, other):
        if other == Mem:
            return True
        return isinstance(other, Mem) and ((
            self.size, self.base, self.index, self.segment, self.scale, self.off,
        ) == (other.size, other.base, other.index, other.segment, other.scale, other.off) or self.any or other.any)

    def __str__(self):
        if self.any:
            return '<mem>'
        tmp = []
        if self.base:
            tmp.append(self.base)
        if self.index:
            if tmp: tmp.append('+')
            tmp.append(self.index)
        if self.scale != 1:
            # you'd better have an index to multiply!
            assert(self.index)
            tmp += ['*', '%d' % self.scale]
        if self.off:
            if tmp:
                if self.off > 0: tmp.append('+')
                else:            tmp.append('-')
            tmp.append('%d' % abs(self.off))

        bracket = '[%s]' % (' '.join(tmp))
        if self.segment:
            bracket = '%s:%s' % (self.segment, bracket)
        final = '%s %s' % (self.MEM_SIZE[self.size], bracket)
        return final

OPS = {
    X86_OP_IMM: Imm,
    X86_OP_REG: Reg,
    X86_OP_MEM: Mem,
}

class Ins(Base):
    addr = None
    ins = None

    @classmethod
    def fromins(cls, ins):
        ops = []
        for op in ins.operands:
            opcls = OPS.get(op.type)
            if opcls:
                ops.append(opcls.fromop(ins, op))
            else:
                print 'UNSUPPORTED OP', op, ins.op_str
                assert(False)

        c = cls(ins.mnemonic, *ops)
        c.ins = ins
        c.addr = ins.address
        return c

    @property
    def dst(self): return self.ops[0]

    @property
    def src(self): return self.ops[1]

    @property
    def a(self): return self.ops[0]

    @property
    def b(self): return self.ops[1]

    @property
    def c(self): return self.ops[2]

    @property
    def d(self): return self.ops[3]

    @property
    def e(self): return self.ops[4]

    @property
    def f(self): return self.ops[5]

    def __init__(self, mne, *ops, **kwargs):
        self.mne = mne
        self.ops = ops
        self.label = None
        self.any = kwargs.get('any', False)
        re = kwargs.pop('re', None)
        self.re = re
        if re is not None:
            self.re = re.compile(re)

    def op_str(self):
        return ', '.join(map(str, self.ops))

    def __eq__(self, other):
        if isinstance(other, basestring) and other == self.mne:
            return True
        elif isinstance(other, Ins):
            return isinstance(other, Ins) and (
                self.any or other.any or
                (self.mne == other.mne or
                    bool(self.re and self.re.match(other.mne)) or
                    bool(other.re and other.re.match(self.mne))) and
                len(other.ops) == len(self.ops) and all(other.ops[i] == op for i, op in enumerate(self.ops)))
        return False

    def __str__(self):
        out = '%s %s' % (self.mne, self.op_str())
        if self.re and not self.mne:
            out = '/%s/ %s' % (self.re.pattern, self.op_str)
        if self.label:
            out = '%s: %s' % self.label
        return out

class Label(Base):
    mne = None
    ops = ()

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return '%s:' % self.name

class IR(list):
    def cs(self):
        'converts IR back to capstone assembly'
        return [ins.ins for ins in self]

    def asm(self):
        'converts IR to assembly source'
        return '\n'.join(map(str, self))

    def findall(self, query, stop=None):
        return IR(IRStream(self).filter(query, stop))

class IRStream:
    def __init__(self, gen):
        self.gen = gen

    def __iter__(self):
        for ins in self.gen:
            if isinstance(ins, Base):
                yield ins
            else:
                yield Ins.fromins(ins)

    def filter(self, query=None, stop=None):
        def fuzzy(a, match):
            if match is None:
                return True
            if isinstance(match, (list, tuple)):
                for other in match:
                    if a == other:
                        return True
            else:
                return a == match

        for ins in self:
            if fuzzy(ins, query):
                yield ins
            if stop and fuzzy(ins, stop):
                break

def irdis(dis):
    if not dis:
        return IR([])
    dis_addr = dis[0].address
    size = dis[-1].address + dis[-1].size - dis_addr

    tmp = []
    next_label = 1
    labels = {}
    # TODO: make more portable (maybe allow arch to do this step)
    # find jumps
    for ins in dis:
        if ins.id in JMPS:
            dst = ins.operands[0]
            if dst.type == X86_OP_IMM:
                addr = dst.imm
                if addr >= dis_addr and addr < dis_addr + size:
                    if addr not in labels:
                        labels[addr] = Label('L%d' % next_label)
                        next_label += 1

                    x = Ins(ins.mnemonic, LabelOp(labels[addr].name))
                    x.addr = ins.address
                    x.ins = ins
                    tmp.append(x)
                    continue
        tmp.append(Ins.fromins(ins))

    out = []
    for i, ins in enumerate(tmp):
        label = labels.get(ins.addr)
        if label:
            out.append(label)
        out.append(ins)

    ir = IR(out)
    return ir
