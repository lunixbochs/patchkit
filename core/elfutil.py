from util.elffile import PT

def is_load(ph):
    return PT.bycode[ph.type] == PT.byname['PT_LOAD']
