patchkit
----
Patches an ELF binary using one or more simple Python scripts.

Usage:

    patch <binary> <patchdir|file> [patchdir|file...]


patchdir
----
Contains one or more Python patch files, which will be executed in alphabetical order against a binary.


Patch Examples
----

autoApplyPatch:
```python

    def simple_patch(pt):
        pt.autoApplyPatch(addr = 0x1182, newAsm="mov rax, rdi; mov ebx, esi", oldAsm="mov eax, edi; mov ebx, esi", desc="")
```
- Enough code space for the patch: If the old code size is BIGGER or EQUAL than the new code size: patch directly, nop command will be used to fill for the rest, a jmp also be added incase we have too many nop command.
- Not enough code space for the patch: If the old code size is SMALLER than the new code size:
    + Create the new inject code with jmp to return to the next original instruction automatically.
    + Create the new jmp instruction to jump to the new injected code.
        * If the old code size is BIGGER or EQUAL than the jmp code size: patch the jum then finish this patch.
        * If the old code size is SMALLER than the new jmp size: show error and skip this patch, the new injected code still be keep, so you can create the jmp by yourself later.
- This function support comment on the asm code:
```python
    newAsm = """
    # whole line comment
    mov rax, rdi                # this is comment
    mov ebx, esi                # everything after # will be ignored
    xor rax, rax; sub ebx, 1;   # this style also be accepted
    """
    pt.autoApplyPatch(addr = 0x1182, newAsm=newAsm, oldAsm="mov eax, edi; mov ebx, esi", desc="")
```
- This function support 0xReturnAddress variable:
```python
    newAsm = """
    mov rax, rdi
    test rax, rax
    jz 0xReturnAddress          # Check and ignore the rest of custom asm code
    test esi, esi
    jnz 0xReturnAddress         # Check and ignore the rest of custom asm code
    mov ebx, esi
    xor rax, rax
    sub ebx, 1
    """
    pt.autoApplyPatch(addr = 0x1182, newAsm=newAsm, oldAsm="mov eax, edi; mov ebx, esi", desc="")
```

checksize: return the code size for a/a set of instruction(s)

```python

    def simple_patch(pt):
        codeSize = pt.checksize(addr = 0x1182, asm="mov rax, rdi; mov ebx, esi", is_asm=True)
```
genNop: return the number of nop instruction(s)
```python

    def simple_patch(pt):
        asm = genNop(3)
        #asm is now "nop;nop;nop;"
```
Nopping an address, injecting an assembly function, and hooking the entry point:
```python

    def simple_patch(pt):
        # nop out a jump at the entry point
        pt.patch(pt.entry, hex='90' * 5)

        # inject assembly into the binary and return the address
        addr = pt.inject(asm='mov eax, 1; ret')

        # hook the entry point to make it call addr (ret will run the original entry point)
        pt.hook(pt.entry, addr)
```
Replacing a C function:
```python

    def replace_free(pt):
        # pretend free() is at this address:
        old_free = 0x804fc4

        # inject a function to replace free()
        new_free = pt.inject(c=r'''
        void free_stub(void *addr) {
            printf("stubbed free(%p)\n", addr);
        }
        ''')

        # patch the beginning of free() with a jump to our new function
        pt.patch(old_free, jmp=new_free)
```

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

    /Applications/IDA\ Pro\ 6.8/idaq.app/Contents/MacOS/idaq64 -A -Sida/allfuncs.py a.out

When invoked like this, allfuncs.py will generate `a.out.funcs` which is used by hardening scripts.


Tools
----
These are somewhat CGC and x86-specific right now, but will be ported for general use in the future.

- explore: uses a Python CFG and recursive backtracking emulator to find basic blocks in an executable
- bindiff: uses the block boundaries from an explore run, as well as additional analysis to find and output basic block diffs between two binaries


Dependencies
----
- Python 2
- Run `./deps.sh` to automatically install these.
  - Capstone Engine - https://github.com/aquynh/capstone.git
  - Keystone Engine - https://github.com/keystone-engine/keystone.git
  - Unicorn Engine  - https://github.com/unicorn-engine/unicorn.git
