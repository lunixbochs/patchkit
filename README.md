patchkit
----
Patches an ELF binary using one or more simple Python scripts.

Usage:

    patch <binary> <patchdir|file> [patchdir|file...]


patchdir
----
Contains one or more Python patch files, which will be executed in alphabetical order against a binary.


Patch Example
----
    def patch(pt):
        # nop out a jump at the entry point
        pt.patch(pt.entry, hex='90' * 5)

        # inject assembly into the binary and return the address
        addr = pt.inject(asm='mov eax, 1; ret')

        # hook the entry point to make it call addr (ret will run the original entry point)
        pt.hook(pt.entry, addr)


API
----
    addr = search(data)
    hook(addr, new_addr)
    patch(addr, *compile arg*)
    addr = inject(*compile arg*)

    *compile arg* is any of the following:
      raw='data'
      hex='0bfe'
      asm='nop'
      jmp=0xaddr
      c='void func() { int a; a = 1; }' (only supported on inject, not patch)


IDA scripts
----
Some scripts live in the ida/ path. Run them like this:

    /Applications/IDA\ Pro\ 6.8/idaq.app/Contents/MacOS/idaq64 -A -B -Sida/allfuncs.py a.out

When invoked like this, allfuncs.py will generate `a.out.funcs` which is used by hardening scripts.


Tools
----
These are somewhat CGC and x86-specific right now, but will be ported for general use in the future.

- explore: uses a Python CFG and recursive backtracking emulator to find basic blocks in an executable
- bindiff: uses the block boundaries from an explore run, as well as additional analysis to find and output basic block diffs between two binaries


Dependencies
----
- Python coding library: `pip install coding`
- Run `./deps.sh` to automatically install these.
  - Capstone Engine - https://github.com/aquynh/capstone.git
  - Keystone Engine - https://github.com/keystone-engine/keystone.git
  - Unicorn Engine  - https://github.com/unicorn-engine/unicorn.git
