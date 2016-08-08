from util import stdlib
from util import heap
from util import crypto

__all__ = ['declare']

def declare(linker):
    stdlib.declare(linker)
    heap.declare(linker)
    crypto.declare(linker)
