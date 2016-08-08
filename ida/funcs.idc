#include <idc.idc>

static main(void) {
    Wait();

    auto bin = GetInputFile();
    auto start = NextFunction(SegStart(BeginEA()));

    auto fd = fopen(bin + ".funcs", "w");
    while (start != BADADDR) {
        auto end = FindFuncEnd(start);
        fprintf(fd, "0x%08x 0x%08x\n", start, end);
        start = NextFunction(start);
    }
    fclose(fd);
    Exit(0);
}
