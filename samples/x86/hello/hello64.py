def patch(pt):
    hello, size = pt.inject(raw='hello world\n', size=True)

    addr = pt.inject(asm=r'''
    push rax
    push rdi
    push rsi
    push rdx

    mov rax, 1                   # SYS_write
    mov rdi, 1                   # fd
    lea rsi, [rip - _PKST_ - %d] # buf
    mov rdx, %d                  # size
    syscall

    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret
    ''' % (size, size))
    pt.hook(pt.entry, addr)
