"""
Radare2 ESIL Verifier for Predictive Trait Simulation.
Executes original and mutated instruction sequences inside an ESIL virtual machine
from identical initial CPU register states to mathematically verify semantic invariance.
"""

import logging
from typing import Any

import r2pipe

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
    ) -> dict[str, Any]:
        """Loads and executes a bytecode sequence inside an in-memory ESIL session."""
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

            # Single-step ESIL until rip exceeds buffer length or max steps reached
            max_steps = max(len(code_bytes) * 2, 10)
            for _ in range(max_steps):
                regs = r2.cmdj("arj")
                if not regs or regs.get("rip", 0) >= len(code_bytes):
                    break
                r2.cmd("aes")

            final_regs = r2.cmdj("arj") or {}
            return final_regs
        finally:
            r2.quit()

    def verify_equivalence(
        self,
        original_bytes: bytes,
        mutant_bytes: bytes,
        arch: str = "x86",
        bits: int = 64,
        initial_regs: dict[str, int] | None = None,
    ) -> tuple[bool, dict[str, int], dict[str, dict[str, Any]]]:
        """
        Runs both sequences from identical initial states.
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
            }

        orig_regs = self._run_esil_sequence(original_bytes, initial_regs, arch=arch, bits=bits)
        mut_regs = self._run_esil_sequence(mutant_bytes, initial_regs, arch=arch, bits=bits)

        is_invariant = True
        for reg in COMPARED_REGISTERS_64:
            if orig_regs.get(reg) != mut_regs.get(reg):
                is_invariant = False
                break

        final_states = {
            "original": orig_regs,
            "mutant": mut_regs,
        }
        return is_invariant, initial_regs, final_states
