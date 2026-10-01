"""
Tests for Radare2 Tool Runner and ESIL Emulation (src/tools/radare_runner.py).
Failure Modes Covered:
- FM-R2-01: File does not exist
- FM-R2-02: Non-executable / corrupt file handling
- FM-R2-03: Invalid offset or non-existent function disassembly
- FM-R2-04: ESIL emulation execution and register state capture
- FM-R2-05: Clean resource teardown (no process leakage)
"""

import os

import pytest

from src.tools.radare_runner import RadareRunner


def test_fm_r2_01_non_existent_file():
    with pytest.raises(FileNotFoundError), RadareRunner("/path/to/missing_binary_xyz.exe"):
        pass


def test_fm_r2_02_non_executable_file(tmp_path):
    txt_file = tmp_path / "hello.txt"
    txt_file.write_text("plain text, not an ELF or PE executable")
    with RadareRunner(str(txt_file)) as r2:
        functions = r2.get_functions()
        assert isinstance(functions, list)
        assert len(functions) == 0


def test_radare_analysis_and_disassembly():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    with RadareRunner(target) as r2:
        r2.analyze(level="aa")
        functions = r2.get_functions()
        assert isinstance(functions, list)
        assert len(functions) > 0

        # Disassemble main or entry point
        entry_func = functions[0]
        offset = entry_func.get("offset")
        disasm = r2.disassemble_function(offset)
        assert disasm is not None
        assert "ops" in disasm or "instructions" in disasm or "name" in disasm


def test_fm_r2_03_invalid_offset():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    with RadareRunner(target) as r2:
        res = r2.disassemble_function(0xDEADBEEF)
        # Invalid offset should return None or empty dict gracefully
        assert res is None or res == {}


def test_fm_r2_04_esil_emulation():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    with RadareRunner(target) as r2:
        r2.analyze(level="aa")
        functions = r2.get_functions()
        assert len(functions) > 0
        entry_offset = functions[0].get("offset")

        # Step 5 instructions in ESIL VM and capture registers
        regs = r2.emulate_esil(entry_offset, num_steps=5)
        assert isinstance(regs, dict)
        # Check architecture registers exist (e.g., rip/rax or eip/eax)
        reg_keys = {k.lower() for k in regs}
        assert any(r in reg_keys for r in ["rip", "eip", "rax", "eax", "rsp", "esp"])


def test_fm_r2_05_context_manager_cleanup():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    r2 = RadareRunner(target)
    r2.analyze(level="a")
    assert r2.r2 is not None
    r2.close()
    assert r2.r2 is None
