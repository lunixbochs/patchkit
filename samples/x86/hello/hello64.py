def patch(pt):
    hello, size = pt.inject(raw='hello world\n', size=True)

    addr = pt.inject(asm=r'''
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    push r11

    mov rax, 1  # SYS_write
    mov rdi, 1  # fd
    mov rsi, %d # buf
    mov rdx, %d # size
    syscall

    pop r11
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret
    ''' % (hello, size))
    pt.hook(pt.entry, addr)
