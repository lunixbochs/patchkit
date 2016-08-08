from util.patch.aslr import aslr

def patch(pt):
    funcs = aslr(pt, count=1)
    for func, addrs in funcs.items():
        pt.patch(func.addr, jmp=addrs[0][0])
