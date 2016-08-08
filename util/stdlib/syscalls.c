void _terminate(int code) {
    syscall1(SYS__terminate, code);
}

int transmit(int fd, const void *buf, uint32_t size, uint32_t *count) {
    return syscall4(SYS_transmit, fd, (uint32_t)buf, size, (uint32_t)count);
}

int receive(int fd, void *buf, uint32_t size, uint32_t *count) {
    return syscall4(SYS_receive, fd, (uint32_t)buf, size, (uint32_t)count);
}

// TODO: not implemented
int fdwait() {
    return 0;
}

int allocate(uint32_t size, int is_x, void *addr) {
    return syscall3(SYS_allocate, size, is_x, (uint32_t)addr);
}

int deallocate(void *addr, uint32_t size) {
    return syscall2(SYS_deallocate, (uint32_t)addr, size);
}

int random(void *buf, uint32_t size, uint32_t *count) {
    return syscall3(SYS_random, (uint32_t)buf, size, (uint32_t)count);
}
