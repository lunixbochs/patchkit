def patch(pt):
    hello, size = pt.inject(raw='hello world\n', size=True)

    addr = pt.inject(asm=r'''
    push {r0, r1, r2, r7}

    mov r7, 0x4
    mov r0, 0x1
    mov r1, %#x
    mov r2, %#x
    swi #0

    pop {r0, r1, r2, r7}
    bx lr
    ''' % (hello, size))
    pt.hook(pt.entry, addr)
