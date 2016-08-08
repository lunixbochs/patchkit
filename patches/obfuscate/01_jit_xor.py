# TODO: block receive() from working on program segments (because they'll be writable)

# encrypt all functions found in program body in-place
# replace the start of each encrypted function with a `jmp xor_tramp`,
# xor_tramp calls xor_func with the right arguments, then jumps to the original function address

import os

# what if each function is xor'd with its low address byte and a random one-byte key? it's still pretty annoying but way faster to "decrypt"
xor_key = ord(os.urandom(1))

def patch(pt):
    xor_func = r'''
    void xor_func(unsigned char *addr, unsigned long size, unsigned char *restore, unsigned long restore_size) {
        unsigned char xor_key = %d ^ ((unsigned long)addr & 0xff);
        for (unsigned int i = 0; i < restore_size; i++) {
            addr[i] = restore[i];
        }
        for (unsigned int i = 0; i < size; i++) {
            addr[i] ^= xor_key;
        }
    }
    ''' % xor_key
    xor_func_addr = pt.inject(c=xor_func)

    for func in pt.funcs():
        jmp_size = len(pt.arch.asm(pt.arch.jmp(pt.binary.next_alloc()), addr=func.addr))
        if func.size < jmp_size:
            pt.warning('Skipping, function too small.')
            continue

        pt.info('Encoding function.')
        pt.make_writable(func.addr)
        data = func.read()
        local_key = xor_key ^ (func.addr & 0xff)
        for i in xrange(len(data)):
            data[i] ^= local_key

        save_data = data[:jmp_size]
        save_addr = pt.inject(raw=save_data)

        xor_tramp = r'''
        push ebp
        mov ebp, esp
        push %(save_size)d
        push %(save)d
        push %(size)d
        push %(addr)d
        call %(xor_func)d
        leave
        jmp %(addr)d
        ''' % {
            'addr': func.addr,
            'size': func.size,
            'save': save_addr,
            'save_size': len(save_data),
            'xor_func': xor_func_addr,
        }
        xor_tramp_addr = pt.inject(asm=xor_tramp, internal=True)
        pt.patch(func.addr, jmp=xor_tramp_addr)
        pt.patch(func.addr + jmp_size, raw=data[jmp_size:])
