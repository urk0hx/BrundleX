"""
End-to-End Verification Test for Phase 2: Core Tool Wrappers.
Verifies the integration of:
1. Binlex runner: genetic trait extraction & MinHash/TLSH matching against SQLite database.
2. Radare2 runner: function disassembly, basic block CFG retrieval, and ESIL CPU state emulation.
3. Refinery runner: embedded payload carving and XOR decryption scanning.
4. Produces verification artifact: artifacts/phase-2/wrapper_verification.json.
"""

import json
import os

from src.tools.binlex_runner import extract_traits, match_traits_against_db
from src.tools.radare_runner import RadareRunner
from src.tools.refinery_runner import carve_pe_payloads, scan_xor_keys


def test_phase_2_tool_wrappers_e2e():
    db_path = "data/traits.db"
    artifacts_dir = "artifacts/phase-2"
    os.makedirs(artifacts_dir, exist_ok=True)

    # 1. Test Binlex runner trait extraction on a real binary
    target_bin = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    traits = extract_traits(target_bin)
    assert len(traits) > 0, "Binlex runner extracted 0 traits"

    # Match extracted traits against data/traits.db
    matches = match_traits_against_db(traits, db_path, threshold=0.01)
    assert isinstance(matches, list)

    # 2. Test Radare2 runner disassembly & ESIL emulation
    r2_result = {}
    with RadareRunner(target_bin) as r2:
        r2.analyze(level="aa")
        funcs = r2.get_functions()
        assert len(funcs) > 0, "Radare2 found 0 functions"

        entry_offset = funcs[0].get("offset")
        disasm = r2.disassemble_function(entry_offset)
        assert disasm is not None

        cfg = r2.get_cfg(entry_offset)
        assert cfg is not None

        esil_regs = r2.emulate_esil(entry_offset, num_steps=5)
        assert len(esil_regs) > 0, "ESIL emulation returned empty registers"

        r2_result = {
            "functions_found": len(funcs),
            "disassembled_offset": entry_offset,
            "cfg_nodes": len(cfg.get("blocks", [])) if isinstance(cfg, dict) else len(cfg),
            "emulated_registers": list(esil_regs.keys()),
        }

    # 3. Test Refinery runner deobfuscation
    test_string = b"This program cannot be run in DOS mode."
    xor_key = 0x33
    obfuscated = bytes([b ^ xor_key for b in test_string])
    xor_hits = scan_xor_keys(obfuscated, max_key_size=1)
    assert len(xor_hits) > 0, "Refinery XOR scan failed to detect key"

    # Synthetic PE carving
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = (64).to_bytes(4, byteorder="little")
    pe_header = b"PE\x00\x00\x64\x86\x01\x00" + b"\x00" * 200
    blob = b"NOISE" * 20 + bytes(dos_header + pe_header) + b"TRAILING"
    carved_pes = carve_pe_payloads(blob)
    assert len(carved_pes) > 0, "Refinery PE carver found no PEs"

    # 4. Generate verification artifact
    proof_data = {
        "status": "success",
        "phase": 2,
        "binlex": {
            "traits_extracted_from_target": len(traits),
            "top_database_matches": matches[:5],
        },
        "radare2": r2_result,
        "refinery": {
            "xor_scan_detected_key": xor_hits[0].get("key"),
            "pe_carved_count": len(carved_pes),
        },
    }

    out_file = os.path.join(artifacts_dir, "wrapper_verification.json")
    with open(out_file, "w") as f:
        json.dump(proof_data, f, indent=2)

    assert os.path.exists(out_file)
    print(f"\n[PHASE 2 E2E VERIFIED] Artifact written to {out_file}")
