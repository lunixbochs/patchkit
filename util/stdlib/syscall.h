#define SYS__terminate 1
#define SYS_transmit 2
#define SYS_receive 3
#define SYS_fdwait 4
#define SYS_allocate 5
#define SYS_deallocate 6
#define SYS_random 7

#define __reg(name) register uint32_t name __asm__(#name)

inline int syscall1(uint32_t num, uint32_t arg1) {
    __reg(eax) = num;
    __asm__ volatile ("int $0x80" :"+a"(eax) :: "memory");
    return eax;
}

inline int syscall2(uint32_t num, uint32_t arg1, uint32_t arg2) {
    __reg(eax) = num; __reg(ebx) = arg1; __reg(ecx) = arg2;
    __asm__ volatile ("int $0x80" :"+a"(eax) :"r"(ebx), "r"(ecx) : "memory");
    return eax;
}

inline int syscall3(uint32_t num, uint32_t arg1, uint32_t arg2, uint32_t arg3) {
    __reg(eax) = num; __reg(ebx) = arg1; __reg(ecx) = arg2; __reg(edx) = arg3;
    __asm__ volatile ("int $0x80" :"+a"(eax) :"r"(ebx), "r"(ecx), "r"(edx) : "memory");
    return eax;
}

inline int syscall4(uint32_t num, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4) {
    __reg(eax) = num; __reg(ebx) = arg1; __reg(ecx) = arg2; __reg(edx) = arg3; __reg(esi) = arg4;
    __asm__ volatile ("int $0x80" :"+a"(eax) :"r"(ebx), "r"(ecx), "r"(edx), "r"(esi) : "memory");
    return eax;
}

#undef __reg
