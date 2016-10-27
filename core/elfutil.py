from util.elffile import PT

def is_load(ph):
    return PT.bycode.get(ph.type) == PT.byname['PT_LOAD']
