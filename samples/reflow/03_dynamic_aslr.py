import random
from collections import defaultdict

from util.patch.aslr import aslr

COUNT = 3

def patch(pt):
    funcs = aslr(pt, count=COUNT)

    relocs = []
    for func, choices in funcs.items():
        entries = []
        for addr, size in choices:
            jmp = pt.asm(pt.arch.jmp(addr), addr=func.addr)
            jmp = '{%s}' % (', '.join(['%d' % ord(b) for b in jmp]))
            entries.append('{(void *)0x%x, %d, %s}' % (addr, size, jmp))
        relocs.append('(void *)0x%x, {%s}' % (func.addr, ', '.join(entries)))
    relocs = ', '.join(relocs)

    pt.hook(pt.entry, pt.inject(
    c=r'''
    typedef struct {
        void *addr;
        size_t size;
        uint8_t jmp[5];
    } reloc_entry;
    typedef struct {
        void *addr;
        reloc_entry entries[%(choices)d];
    } func_reloc;

    // will be zeroed at the end
    func_reloc relocs[] = {%(relocs)s};
    void _start() {
        uint32_t len = %(funcs)d;
        // will be zeroed at the end
        uint8_t choices[len];
        random(choices, len, 0);

        for (int i = 0; i < len; i++) {
            int choice = choices[i] %% %(choices)d;
            func_reloc *reloc = &relocs[i];
            reloc_entry *entry = &reloc->entries[choice];
            uint8_t *target = entry->jmp;
            memcpy(reloc->addr, target, 5);
            // nop out the other function
            for (int j = 0; j < %(choices)d; j++) {
                if (j != choice) {
                    reloc_entry *entry = &relocs[i].entries[j];
                    memset(entry->addr, 0x0f, entry->size);
                }
            }
        }
        // TODO: these might not actually help anything and just be slow
        // memset(choices, 0, len);
        // memset(relocs, 0, sizeof(relocs));
    }
    ''' % {'funcs': len(funcs), 'choices': COUNT, 'relocs': relocs}))
