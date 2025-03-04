import gdb
from enum import Enum
from dataclasses import dataclass


# TARGET_ADDR = 0x3fb8003020
TARGET_ADDR = (0x3fb8003020, 0x3fbc003020)

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

class MmapFinishBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, params):
        gdb.FinishBreakpoint.__init__(self, gdb.newest_frame(), internal=True)
        self.silent = True
        self.params = params

    def stop(self):

        arch = get_arch(raise_on_unknown=True)
        abi = abi_dict[arch]
        
        length = self.params["length"]
        addr = int(gdb.parse_and_eval(f"${abi.ret}"))
        end_addr = addr + length
        
        for target in TARGET_ADDR:
            if addr <= target < end_addr:
                gdb.write(f"target: {hex(target)}, start: {hex(addr)}, end: {hex(end_addr)}, prot: {self.params['prot']}\n")
                gdb.write(f"JIT memory found at {hex(addr)} - setting breakpoint at {hex(target)}\n")
                gdb.Breakpoint(f"*{hex(target)}")
                self.delete()  # Remove mmap breakpoint

class MmapBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super().__init__('mmap', gdb.BP_BREAKPOINT)
        self.silent = True

    def stop(self):
        arch = get_arch(raise_on_unknown=True)
        abi = abi_dict[arch]
        
        # addr not used, as can be any - decision is up to OS anyway.
        addr, length, prot = [int(gdb.parse_and_eval(f"${x}")) for x in [getattr(abi, f"arg{i}") for i in range(3)] ]

        if True: # prot & 0x4:  # PROT_EXEC
            params = {
                "length": length,
                "prot": prot,
            }
            MmapFinishBreakpoint(params)

        return False  # Continue execution

def on_start(stop_event):
    gdb.write("Installing mmap breakpoint watcher.\n")
    MmapBreakpoint()

MmapBreakpoint()
gdb.execute("set logging enabled on")
gdb.execute("run")

# gdb.events.stop.connect(on_start)
