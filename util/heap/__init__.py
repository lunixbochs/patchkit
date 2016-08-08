import os
import functools
from util import read
"""
Replace a custom heap with dlmalloc

Usage:
  from util import heap

  heap.declare(pt.linker)

  pt.patch(addr, sym='dlmalloc')
  pt.patch(addr, sym='dlcalloc')
  pt.patch(addr, sym='dlfree')
  pt.patch(addr, sym='dlrealloc')
"""

__all__ = ["apply"]

dlmalloc = {'symbols': {
    'dlmalloc': 'void *dlmalloc(size_t size)',
    'dlfree': 'void dlfree(void *addr)',
    'dlcalloc': 'void *dlcalloc(size_t count, size_t size)',
    'dlrealloc': 'void *dlrealloc(void *addr, size_t size)',
}, 'source': read('heap/malloc.c')}

def declare(linker):
    if not 'dlmalloc' in linker:
        linker.declare(**dlmalloc)
