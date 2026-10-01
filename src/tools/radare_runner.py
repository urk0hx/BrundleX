"""
Radare2 Tool Runner and ESIL Execution Emulation.
Provides interfaces for binary analysis, function disassembly, CFG extraction,
and ESIL CPU emulation using r2pipe.
"""

import logging
import os
from typing import Any

import r2pipe

logger = logging.getLogger(__name__)


class RadareRunner:
    """Wrapper around radare2 via r2pipe."""

    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        self.file_path = file_path
        # -2: disable stderr to keep output clean
        self.r2 = r2pipe.open(file_path, flags=["-2"])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        """Closes the r2pipe subprocess safely."""
        if self.r2:
            try:
                self.r2.quit()
            except (RuntimeError, OSError, ValueError, BrokenPipeError) as e:
                logger.debug(f"Error closing r2pipe: {e}")
            finally:
                self.r2 = None

    def analyze(self, level: str = "aa") -> None:
        """Runs binary analysis (e.g. 'a', 'aa', 'aaa')."""
        if not self.r2:
            return
        self.r2.cmd(level)

    def get_functions(self) -> list[dict[str, Any]]:
        """Returns list of detected functions (aflj) with normalized addr/offset fields."""
        if not self.r2:
            return []
        try:
            res = self.r2.cmdj("aflj")
            if isinstance(res, list):
                for f in res:
                    if isinstance(f, dict):
                        addr = f.get("addr") or f.get("offset")
                        f["offset"] = addr
                        f["addr"] = addr
                return res
            return []
        except (RuntimeError, OSError, ValueError, KeyError) as e:
            logger.debug(f"Error getting functions from r2: {e}")
            return []

    def disassemble_function(self, offset_or_name: str | int) -> dict[str, Any] | None:
        """Disassembles a function at the given offset or name (pdfj)."""
        if not self.r2:
            return None
        try:
            res = self.r2.cmdj(f"pdfj @ {offset_or_name}")
            return res if isinstance(res, dict) else {}
        except (RuntimeError, OSError, ValueError, KeyError) as e:
            logger.debug(f"Error disassembling function at {offset_or_name}: {e}")
            return {}

    def get_basic_blocks(self, offset_or_name: str | int) -> list[dict[str, Any]]:
        """Retrieves basic blocks of a function (afbj)."""
        if not self.r2:
            return []
        try:
            res = self.r2.cmdj(f"afbj @ {offset_or_name}")
            return res if isinstance(res, list) else []
        except (RuntimeError, OSError, ValueError, KeyError) as e:
            logger.debug(f"Error getting basic blocks at {offset_or_name}: {e}")
            return []

    def get_cfg(self, offset_or_name: str | int) -> dict[str, Any]:
        """Retrieves control flow graph of a function (agj)."""
        if not self.r2:
            return {}
        try:
            res = self.r2.cmdj(f"agj @ {offset_or_name}")
            if isinstance(res, list) and res:
                return res[0] if isinstance(res[0], dict) else {}
            return res if isinstance(res, dict) else {}
        except (RuntimeError, OSError, ValueError, KeyError) as e:
            logger.debug(f"Error getting CFG at {offset_or_name}: {e}")
            return {}

    def emulate_esil(
        self,
        offset: int | str,
        num_steps: int = 10,
        initial_registers: dict[str, int] | None = None,
    ) -> dict[str, int]:
        """
        Emulates execution of instructions starting at offset using Radare2 ESIL engine.
        Returns final register states as a dictionary.
        """
        if not self.r2:
            return {}

        try:
            # Initialize ESIL VM
            self.r2.cmd("aei")
            self.r2.cmd("aeim")

            # Seek to target instruction
            self.r2.cmd(f"s {offset}")
            self.r2.cmd(f"aer rip={offset}")

            # Apply any initial register values
            if initial_registers:
                for reg, val in initial_registers.items():
                    self.r2.cmd(f"aer {reg}={val}")

            # Step instructions
            for _ in range(num_steps):
                self.r2.cmd("aes")

            # Read back register values
            reg_dump = self.r2.cmdj("aerj")
            if isinstance(reg_dump, dict):
                return {k: v for k, v in reg_dump.items() if isinstance(v, (int, float))}
            return {}
        except (RuntimeError, OSError, ValueError, KeyError) as e:
            logger.warning(f"ESIL emulation error at {offset}: {e}")
            return {}
