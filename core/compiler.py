import re
import subprocess

# TODO: last few args are optional, but clang emits them so I'll deal with it if it breaks
zerofill_re = re.compile(r'^.zerofill\s+' + '(?P<segment>[^,]+),\s*' + '(?P<section>[^,]+),\s*' + '(?P<symbolname>[^,]+),\s*' + '(?P<size>[^,]+),\s*' + '(?P<align>.+)')
zero_re = re.compile(r'^.zero\s+(?P<size>\d+)')
local_re = re.compile(r'^.local\s+(?P<name>[^ ]+)$')
comm_re = re.compile(r'^.comm\s+(?P<name>[^,]+),(?P<size>[^,]+),(?P<align>[^,]+)')
section_re = re.compile(r'^.section\s+(?P<name>.+)$')

class BuildError(Exception): pass

def clean(asm):
    # work around directives that crash Keystone
    strip = (
        '.macosx_version_min',
        '.subsections_via_symbols',
        '.align',
        '.globl',
        '.weak_definition',
        '.p2align',
        '.cfi',
        '.file',
        '#',
    )
    text = []
    data = []
    cur = text
    for line in asm.split('\n'):
        line = line.strip()
        if line.startswith(strip):
            continue
        nocom = line.split('#', 1)[0]

        match = section_re.match(nocom)
        if match:
            section = match.group('name')
            if section.startswith(('.rodata', '.note', '__DATA')):
                cur = data
            elif section.startswith(('.text', '__TEXT')):
                cur = text
            else:
                print 'unknown section', section
            continue

        if line.startswith('.text'):
            cur = text
            continue
        elif line.startswith('.data'):
            cur = data
            continue

        match = zerofill_re.match(nocom)
        if match:
            seg, sec, sym, size, align = match.groups()
            size, align = int(size), int(align)
            cur.append('%s:' % sym)
            cur.append('.byte %s' % (', '.join(['0'] * size)))
            continue

        match = zero_re.match(nocom)
        if match:
            size = int(match.group('size'))
            cur.append('.byte %s' % (', '.join(['0'] * size)))
            continue

        match = local_re.match(nocom)
        if match:
            cur.append('%s:' % match.group('name'))
            continue

        match = comm_re.match(nocom)
        if match:
            size = int(match.group('size'))
            cur.append('.byte %s' % (', '.join(['0'] * size)))
            continue

        '''
        if line.startswith('.') and not line.endswith(':'):
            if not line.startswith(('.long', '.byte')):
                print line
        '''

        cur.append(line)
    return '\n'.join(text + data)

compiler_version = None
def compile(code, linker, syms=()):
    global compiler_version
    cflags = ['-mno-sse', '-Os', '-std=c99', '-fno-pic', '-ffreestanding', '-fno-stack-protector']

    if compiler_version is None:
        compiler_version = subprocess.check_output(['gcc', '--version'])

    if 'gcc' in compiler_version and not 'clang' in compiler_version:
        cflags += ['-fleading-underscore', '-fno-toplevel-reorder']

    cflags += linker.cflags
    code = linker.pre(code, syms=syms)
    p = subprocess.Popen(['gcc', '-xc', '-S', '-o-', '-'] + cflags, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    asm, err = p.communicate(code)
    if 'error:' in err.lower():
        raise BuildError(err)
    elif err:
        print err

    asm = linker.post(asm, syms=syms)
    asm = clean(asm)
    return asm
