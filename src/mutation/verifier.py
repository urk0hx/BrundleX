"""
Radare2 ESIL Verifier for Predictive Trait Simulation.
Executes original and mutated instruction sequences inside an ESIL virtual machine
from isomorphic initial CPU register states to mathematically verify semantic invariance
across both CPU register states and memory/stack modifications.
"""

import logging
from typing import Any

import r2pipe

from src.mutation.operators import REG_TO_64

logger = logging.getLogger(__name__)

COMPARED_REGISTERS_64 = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]


class ESILVerifier:
    """Verifies behavioral equivalence of instruction sequences using Radare2 ESIL."""

    def __init__(self):
        pass

    def _run_esil_sequence(
        self,
        code_bytes: bytes,
        initial_regs: dict[str, int],
        arch: str = "x86",
        bits: int = 64,
    ) -> tuple[dict[str, Any], str]:
        """Loads and executes a bytecode sequence inside an in-memory ESIL session, returning (regs, stack_mem)."""
        hex_bytes = code_bytes.hex()
        r2 = r2pipe.open("malloc://4096")
        try:
            r2.cmd(f"e asm.arch={arch}")
            r2.cmd(f"e asm.bits={bits}")
            r2.cmd("e io.cache=true")
            r2.cmd(f"wx {hex_bytes}")
            r2.cmd("aei")
            r2.cmd("aeim")
            r2.cmd("aeip")

            for reg, val in initial_regs.items():
                r2.cmd(f"ar {reg}={val}")

            sp_reg = "rsp" if bits == 64 else "esp"
            initial_sp = r2.cmdj("arj").get(sp_reg, 0x100000)

            # Single-step ESIL until rip/eip exceeds buffer length or max steps reached
            ip_reg = "rip" if bits == 64 else "eip"
            max_steps = max(len(code_bytes) * 2, 10)
            for _ in range(max_steps):
                regs = r2.cmdj("arj")
                if not regs or regs.get(ip_reg, 0) >= len(code_bytes):
                    break
                r2.cmd("aes")

            final_regs = r2.cmdj("arj") or {}
            # Sample 256 bytes around initial stack pointer to inspect memory writes
            mem_hex = r2.cmd(f"p8 256 @ {initial_sp - 128}").strip()
            return final_regs, mem_hex
        finally:
            r2.quit()

    def verify_equivalence(
        self,
        original_bytes: bytes,
        mutant_bytes: bytes,
        arch: str = "x86",
        bits: int = 64,
        initial_regs: dict[str, int] | None = None,
        reg_map: dict[str, str] | None = None,
    ) -> tuple[bool, dict[str, int], dict[str, dict[str, Any]]]:
        """
        Runs both sequences from isomorphic initial states.
        Validates both CPU registers and memory modifications.
        Returns: (is_invariant, initial_state, {"original": final_regs, "mutant": final_regs})
        """
        if initial_regs is None:
            initial_regs = {
                "rax": 0x10,
                "rbx": 0x20,
                "rcx": 0x30,
                "rdx": 0x40,
                "rsi": 0x50,
                "rdi": 0x60,
                "r8": 0x70,
                "r9": 0x80,
                "rbp": 0x177000,
            }

        # Normalize register mapping to 64-bit root registers
        clean_reg_map: dict[str, str] = {}
        if reg_map:
            for src_r, dst_r in reg_map.items():
                src_root = REG_TO_64.get(src_r.lower(), src_r.lower())
                dst_root = REG_TO_64.get(dst_r.lower(), dst_r.lower())
                if src_root != dst_root:
                    clean_reg_map[src_root] = dst_root

        # Construct isomorphic initial state for the mutant
        mut_initial_regs = dict(initial_regs)
        for src_root, dst_root in clean_reg_map.items():
            if src_root in initial_regs:
                mut_initial_regs[dst_root] = initial_regs[src_root]

        orig_regs, orig_mem = self._run_esil_sequence(original_bytes, initial_regs, arch=arch, bits=bits)
        mut_regs, mut_mem = self._run_esil_sequence(mutant_bytes, mut_initial_regs, arch=arch, bits=bits)

        is_invariant = True

        # 1. Verify memory / stack state invariance
        if orig_mem != mut_mem:
            is_invariant = False

        # 2. Verify register state invariance
        if clean_reg_map:
            # Check mapped registers
            for src_root, dst_root in clean_reg_map.items():
                if orig_regs.get(src_root) != mut_regs.get(dst_root):
                    is_invariant = False
                    break
            # Check unmapped registers
            mapped_set = set(clean_reg_map.keys()) | set(clean_reg_map.values())
            for reg in COMPARED_REGISTERS_64:
                if reg not in mapped_set and orig_regs.get(reg) != mut_regs.get(reg):
                    is_invariant = False
                    break
        else:
            for reg in COMPARED_REGISTERS_64:
                if orig_regs.get(reg) != mut_regs.get(reg):
                    is_invariant = False
                    break

        final_states = {
            "original": orig_regs,
            "mutant": mut_regs,
        }
        return is_invariant, initial_regs, final_states
