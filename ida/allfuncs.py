from idautils import *
from idaapi import *
import idc
autoWait()
start = NextFunction(SegStart(BeginEA()))
filename = '%s.funcs' % get_root_filename()
fp = open(filename, 'w')
while start != BADADDR:
    end = FindFuncEnd(start)
    l = '%08x %08x\n' % (start,end)
    fp.write(l)
    print(l)
    start = NextFunction(start)
idc.Exit(0)
