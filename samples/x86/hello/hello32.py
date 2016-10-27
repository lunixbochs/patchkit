def patch(pt):
    hello, size = pt.inject(raw='hello world\n', size=True)

    addr = pt.inject(asm=r'''
    push eax
    push ebx
    push ecx
    push edx

    mov eax, 4  # SYS_write
    mov ebx, 1  # fd
    mov ecx, %d # buf
    mov edx, %d # size
    int 0x80

    pop edx
    pop ecx
    pop ebx
    pop eax
    ret
    ''' % (hello, size))
    pt.hook(pt.entry, addr)
