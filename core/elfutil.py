from util.elffile import PT

def is_load(ph):
    return PT[ph.type] == 'PT_LOAD'
