def xor_mem(pt, addr, size, key):
    if size == 0:
        pt.debug('Skipping XOR: patch size is 0.')
        return

    data = pt.elf.read(addr, size)
    for i in xrange(len(data)):
        data[i] ^= key
    pt.debug('[XOR] 0x%x +0x%x ^ 0x%x' % (addr, size, key))
    pt.patch(addr, raw=data)

    pt.make_writable(addr)
    addr = pt.inject(c=r'''
    void _start() {
        char *p = (char *)%d;
        for (unsigned int i = 0; i < %d; i++) {
            *p++ ^= %s;
        }
    }
    ''' % (addr, size, key))
    pt.hook(pt.entry, addr, first=True)
