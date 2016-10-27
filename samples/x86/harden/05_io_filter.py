from capstone.x86_const import *

# TODO: there's no pt context in here
def _c_pre(code, syms):
    out = []
    if syms == ['transmit']:
        # TODO: this is really gross text parsing
        for line in code.split('\n'):
            out.append(line)
            if line.startswith('int transmit(') and line.endswith('{'):
                out.append(r'''
                if (((uint32_t)buf < 0x4347c000 && (uint32_t)buf + size > 0x4347c000) ||
                    ((uint32_t)buf >= 0x4347c000 && (uint32_t)buf < 0x4347c000 + 0x1000)) {
                    transmit(1, "Try a type 3.\n", 14, 0);
                    _terminate(0);
                }
                ''')
        return '\n'.join(out)
    elif syms == ['receive']:
        return
        # TODO: receive hook can't currently happen at a good time
        # it needs to happen last, and the page list needs to be injected into NX page?

def queue(pt):
    pt.binary.linker.onpre(_c_pre)
