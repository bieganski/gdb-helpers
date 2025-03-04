import gdb
from enum import Enum
from dataclasses import dataclass

# ./d8 --print-regexp-code  /root/regex-dna-d8.js   -- 2 | grep -C1 Instructions   | grep '^0x' | cut -d ' ' -f 1 | paste -s -d ,
BP_OFFSET_FROM_BASE = (0x3fb8003020,0x3fb80037a0,0x3fb8003f40,0x3fb8004760,0x3fb8004f80,0x3fb80057a0,0x3fb8005fc0,0x3fb80067e0,0x3fb8007000,0x3fb8007800)
BP_OFFSET_FROM_BASE = [x - 0x3fb8003000 for x in BP_OFFSET_FROM_BASE]

PROT_EXEC = 0x4

class CpuArch(Enum):
    x86_64 = "x86_64"
    aarch64 = "aarch64"
    riscv64 = "riscv64"
    unknown = "unknown_not_defined"

def get_arch(raise_on_unknown: bool = False) -> CpuArch:
    arch = gdb.execute("show architecture", to_string=True)
    if 'aarch64' in arch:
        return CpuArch.aarch64
    elif 'x86-64' in arch:
        return CpuArch.x86_64
    elif "riscv:rv64" in arch:
        return CpuArch.riscv64
    else:
        if raise_on_unknown:
            raise RuntimeError(f"Unknown arch: {arch}")
        return CpuArch.unknown

@dataclass
class Abi:
    arg0: str
    arg1: str
    arg2: str
    ret: str

abi_dict = {
    CpuArch.x86_64: Abi(arg0="rdi", arg1="rsi", arg2="rdx", ret="rax"),
    CpuArch.riscv64: Abi(arg0="a0", arg1="a1", arg2="a2", ret="a0"),
    CpuArch.aarch64: Abi(arg0="x0", arg1="x1", arg2="x2", ret="x0"),
}


class MprotectBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super().__init__('mprotect', gdb.BP_BREAKPOINT)
        self.silent = True

        self.first = True

    def stop(self):
        arch = get_arch(raise_on_unknown=True)
        abi = abi_dict[arch]

        addr, length, prot = [int(gdb.parse_and_eval(f"${x}")) for x in [getattr(abi, f"arg{i}") for i in range(3)] ]
        addr_end = addr + length

        if prot & PROT_EXEC:
            gdb.write(f"mprotect+PROT_EXEC detected at region {(hex(addr), hex(addr_end))}")

            if not self.first:
                raise RuntimeError("Only a single mprotect+PROT_EXEC supported")
            self.first = False

            for offset_from_base in BP_OFFSET_FROM_BASE:
                if offset_from_base >= length:
                    raise RuntimeError(f"BP_OFFSET_FROM_BASE={hex(offset_from_base)}, but mprotect'ed length is {hex(length)}")
                bp_addr = addr + offset_from_base
                gdb.Breakpoint(f"*{hex(bp_addr)}")
            # self.delete() # XXX we have assert anyway

        return False  # Continue execution

MprotectBreakpoint()
gdb.execute("set logging enabled on")
gdb.execute("run")
