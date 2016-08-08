import struct

def _final(pt):
    secret = 0x4347c000
    addr = pt.binary.next_alloc()
    raw = pt.arch.asm(r'''
        call label
        add eax, 11
        xor [eax], ecx
        jmp label2
 label: mov eax, [esp]
        ret
label2: xor eax, eax
        jmp 0x%x
    ''' % pt.entry, addr=addr)
    pt.info('[*] Breaking entry point.')
    pt.debug(dis=pt.arch.dis(raw, addr=addr))
    off = len(raw) - 4
    ruin = struct.pack('<I', struct.unpack('<I', raw[off:off+4])[0] ^ secret)
    pt.entry = pt.inject(raw=raw[:off] + ruin + raw[off+4:], is_asm=True)

def load(pt):
    pt.binary.onfinal(_final)
