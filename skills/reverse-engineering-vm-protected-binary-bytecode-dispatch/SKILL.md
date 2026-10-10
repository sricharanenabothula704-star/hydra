---
name: reverse-engineering-vm-protected-binary-bytecode-dispatch
description: >-
  Identifies custom bytecode interpreters and recovers opcode semantics by mapping the dispatch table and tracing handlers in Unicorn, angr or Ghidra.
---

# SKILL: Identifies custom bytecode interpreters and recovers opcode semantics by mapping the dispatch table and tracing handlers in Unicorn, angr or Ghidra.

> **AI LOAD INSTRUCTION**: Load when a binary resists static analysis — one dispatch loop, one huge switch, no useful strings — on malware you are analyzing or software you are licensed to reverse.

## 0. RELATED ROUTING
- [reverse-engineering-malware-with-ghidra](#) for the general RE workflow before devirtualization
- [analyzing-cobalt-strike-beacon-configuration](#) for the same recovery problem against a known obfuscator
- [code-obfuscation-deobfuscation](#) for the control-flow and opaque-predicate layers that precede the VM
- [exploiting-elf-binary-rop-gadget-enumeration](#) for recovering the register conventions the dispatcher assumes

## 1. RESPONSIBLE USE AND LEGAL SCOPE

Read this before anything else: commercial VM protection is usually contractually and (depending on
jurisdiction) legally off-limits to reverse. Work on malware samples you are authorized to analyse,
CTF challenges, your own binaries, and software whose licence explicitly permits reverse engineering.

**Do not** devirtualize commercial software to defeat copy protection, license checks, or anti-cheat
without written permission from the rights holder, and do not use a devirtualizer to strip protection
from an EDR agent you do not own. The legitimate high-value cases are malware analysis,
interoperability work, and your own software.

## 2. RECOGNISING A VM IN THE FIRST PLACE

Static heuristics that separate "one binary with a VM" from "a large program". **One function holds
an implausible share of basic blocks** — normal code spreads across many functions, a VM concentrates
thousands of handlers in one. **A small dispatch loop sits at the edge of that cluster**, executing
constantly, with indirect transfers scattered across the whole `.text`. **Almost no cross-references
reach the handler region from outside** — it is a closed world. **The bytecode is a data blob**: a
high-entropy `.rodata` region with no strings, read only by the dispatcher. **Handler sizes are
uniform-ish and tiny** (2–10 instructions), unlike compiled source. In Ghidra, check the decompiler
statistics for a function that is a bare `switch` over a byte load with no business logic.

## 3. THE DISPATCH PATTERNS YOU WILL MEET

**Table-driven indirect jump** (most common):

```asm
loop:
    movzx eax, byte ptr [rbx]         ; fetch opcode from the VM stack
    inc   rbx
    movsxd rdx, dword ptr [tbl+rax*4] ; sign-extended offset
    add   rdx, rbx                    ; relocate relative to a base
    jmp   rdx                         ; dispatch
```

Follow the addressing mode back from the `movsxd` to locate the jump table in `.rodata`, then read it as an array of signed 32-bit offsets.

**Tail-call threading.** Handlers `jmp` to the next handler instead of returning, so call depth stays
flat and the dispatcher disappears; find the cluster by `jmp rax` / `jmp qword [reg]` density.

**Register-file interpreter.** The VM PC and operand stack live in fixed memory slots, not the host
stack; handlers read `[rsp+X]` at unusual constant offsets. **Stack-machine conventions.** Most
bytecode VMs are stack machines — `PUSH a; PUSH b; ADD` leaves one value where three instructions
touched the stack. Recovering that shadow stack offset first makes every handler readable.

## 4. RECOVERING THE OPCODE MAP

Static extraction gives handler *addresses*; semantics require dynamic work. The efficient loop is:
seed one opcode, run it, snapshot the shadow stack, diff.

```python
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
uc = Uc(UC_ARCH_X86, UC_MODE_64)
for base in (0x400000, 0x600000, 0x700000):           # code, VM shadow stack, bytecode
    uc.mem_map(base, 0x10000)
uc.mem_write(0x700000, bytes([opcode]) + b'\x00' * 15)   # one candidate opcode
uc.mem_write(0x400000, bytes(entry_stub))                # dispatch, stop at the handler
uc.emu_start(0x400000, 0x400000 + len(entry_stub), count=1)
before = uc.mem_read(0x600000, 64)                      # snapshot before/after the step
```

The delta between snapshots is the opcode's stack effect. Automate across all 256 values and you get
a machine-readable opcode table — the actual deliverable, and worth far more than one recovered
function. Capstone renders each handler body readably; angr goes further by solving for the byte
buffer that produces a chosen branch outcome:

```python
import angr
proj = angr.Project('./target', auto_load_libs=False)
sm   = proj.factory.simulation_manager(proj.factory.entry_state())
sm.run(until=lambda s: b'HELLO' in s.posix.dumps(0))
```

## 5. THE ANTI-ANALYSIS LAYERS ABOVE THE VM

Virtualisation is rarely the outermost layer. Expect, from the outside in: **packing** (custom UPX
variants, a self-decompressing stub), **import obfuscation** (APIs resolved by hash at runtime via
`GetProcAddress` loops), **control-flow flattening** (a dispatcher replacing structured CFGs),
**opaque predicates** (branches on constants the compiler "cannot" fold), and **handler encryption**,
where opcode bytes are decrypted a block at a time so a static table dump is useless. Rule out
flattening first, because the two look alike in a decompiler: flattening keeps the *original*
bytecode in the instruction stream while a VM re-encodes it into an external byte stream.

## 6. PRACTICAL DISCIPLINE

**Automate the loop, not the tracing** — manual single-stepping through thousands of handlers does
not scale, scripting the per-opcode snapshot does. **Record the dispatch base** once as a named
constant, since every relocated offset depends on it. **Validate against a native build** if you have
one: diffing handler behaviour against the original function confirms a guess fastest. And **budget
time against value** — the five opcodes that decode a config blob answer the real question far
sooner than devirtualising all 256.

## Sources
- CWE-693: https://cwe.mitre.org/data/definitions/693.html
- CWE-506: https://cwe.mitre.org/data/definitions/506.html
- miasm (Python framework for binary analysis/IR lifting): https://github.com/cea-sec/miasm
- angr documentation (symbolic execution and CFG recovery): https://angr.io/angr-doc/
- Ghidra decompiler and analysis framework: https://ghidra-sre.org/
