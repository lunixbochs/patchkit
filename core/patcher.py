import glob
import inspect
import os
import sys
import traceback

from binary import Binary

class Patcher:
    def __init__(self, binary, verbose=False, cflags=None):
        self.bin = Binary(binary)
        self.bin.verbose = verbose
        self.bin.linker.cflags = cflags
        self.patches = []
        self.patchfiles = []
        self.verbose = verbose
        self.cflags = cflags

    def add(self, path):
        if path.endswith('.py'):
            self.patchfiles.append((path, os.path.basename(path)))
        else:
            base = os.path.basename(path.rstrip(os.path.sep))
            for name in glob.glob(path + '/*.py'):
                if os.path.basename(name).startswith('_'):
                    continue
                self.patchfiles.append((name, os.path.join(base, os.path.basename(name))))

    def patch(self):
        cwd = os.getcwd()
        try:
            for path, pathname in self.patchfiles:
                sys.path.insert(0, os.path.dirname(path))
                print '[*]', pathname
                patchfile = os.path.basename(path).rsplit('.', 1)[0]
                patch = __import__(patchfile)
                sys.path.pop(0)

                # preserve function order
                try:
                    source, _ = inspect.getsourcelines(patch)
                    order = []
                    for line in source:
                        if line.startswith('def'):
                            name = line.split(' ', 1)[1].split('(', 1)[0]
                            try:
                                order.append(getattr(patch, name))
                            except AttributeError:
                                pass
                except Exception:
                    print 'Warning: could not preserve patch function order'
                    traceback.print_exc()
                    order = vars(patch).values()

                for func in order:
                    if func.__name__.startswith('_'):
                        # skip "private" functions
                        continue

                    if hasattr(func, '__call__'):
                        print ' [+] %s()' % func.__name__
                        with self.bin.collect() as patchset:
                            try:
                                func(patchset)
                            except Exception as e:
                                print 'Exception thrown by patch:', path, func.__name__
                                traceback.print_exc()
                                print 'Memory maps:'
                                for prog in self.bin.elf.progs:
                                    if prog.isload:
                                        print '0x%x-0x%x' % (prog.vaddr, prog.vaddr + prog.vsize)
                                sys.exit(1)
                print
        finally:
            os.chdir(cwd)

    def save(self, path):
        self.bin.save(path)
