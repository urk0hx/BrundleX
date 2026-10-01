# Phase 2: Core Tool Wrappers (Binlex, Radare2, Refinery)

## Status: Completed

### Objectives
1. Equip the container environment with `radare2`, `r2pipe`, and `binary-refinery`.
2. Implement `src/tools/binlex_runner.py`:
   - Subprocess wrapper to extract basic block and function traits from candidate binaries.
   - Jaccard similarity trait matching against `data/traits.db` using MinHash traits and TLSH distance.
3. Implement `src/tools/radare_runner.py`:
   - Wrapper using `r2pipe` for opening binaries, disassembling functions (`pdf`) / basic blocks, and CFG extraction.
   - ESIL evaluation helper to step through instructions and capture register states.
4. Implement `src/tools/refinery_runner.py`:
   - Basic deobfuscation helpers (PE header carving, multi-byte XOR brute-forcing/scans, overlay stripping).
5. Comprehensive test suite:
   - Test-first failure mode unit tests in `tests/unit/test_binlex_runner.py`, `tests/unit/test_radare_runner.py`, `tests/unit/test_refinery_runner.py`.
   - Integration / E2E verification test generating `artifacts/phase-2/wrapper_verification.json`.

---

### 1. Delivered
- [x] Container tooling integration:
  - Installed `radare2 v6.2.2` deb package into `Containerfile`.
  - Added `r2pipe>=1.9.6` and `binary-refinery>=0.11.2` to `requirements.txt`.
  - Verified `radare2`, `r2pipe`, and `refinery` imports and CLI availability inside container.
- [x] Binlex tool runner (`src/tools/binlex_runner.py`):
  - Trait extraction function `extract_traits` with file existence verification.
  - MinHash Jaccard token similarity calculator `compute_minhash_jaccard`.
  - SQLite database genetic matcher `match_traits_against_db` with batch querying and confidence scoring.
- [x] Radare2 analysis & ESIL runner (`src/tools/radare_runner.py`):
  - Context manager wrapper for `r2pipe`.
  - Function detection, normalized address mapping (`addr`/`offset`), basic block enumeration (`afbj`), and CFG retrieval (`agj`).
  - ESIL CPU VM emulator `emulate_esil` stepping instructions and extracting 64-bit/32-bit register states.
- [x] Binary Refinery deobfuscation runner (`src/tools/refinery_runner.py`):
  - Embedded PE carver `carve_pe_payloads` combining Refinery `carve_pe` unit with MZ/PE structural fallback.
  - XOR brute-force scanner `scan_xor_keys` detecting common indicators (DOS stub, PE signatures, URL markers) and autoxor heuristics.
  - Overlay stripper `strip_pe_overlay` using `lief.PE` section boundary calculations.
- [x] Verification test suite:
  - 18 new unit tests covering failure modes FM-BLX-R01..05, FM-R2-01..05, FM-REF-01..05.
  - End-to-end integration test `tests/e2e/test_wrappers_e2e.py`.
  - Verification artifact written to `artifacts/phase-2/wrapper_verification.json`.

---

### 2. Proof
- **Unit & Integration Test Suite:**
  - Command: `make check test-unit test-e2e`
  - Result: 46 passed tests (44 unit, 2 E2E), 0 failures, 0 ruff lint errors.
- **Verification Artifact:**
  - Path: `artifacts/phase-2/wrapper_verification.json`
  - Binlex: 1,233 traits extracted from candidate binary; identified matching genetic samples in `data/traits.db` (`LummaStealer`, `Stealc`, `RedLine`, `WailsLoader`).
  - Radare2: 41 functions identified, disassembled offset 4720, CFG nodes retrieved, ESIL register state captured across 18 registers (`rax`..`rsp`).
  - Refinery: XOR key 51 (0x33) recovered, embedded synthetic PE carved successfully.

---

### 3. Deferred
- Advanced multi-byte rolling XOR deobfuscators with custom statistical fitness functions (deferred to Phase 3/4 if needed by specific cryptors).

---

### 4. Human Review Notes
- Verify that `r2pipe` and `refinery` operate purely in-container without host binary execution.
- Review verification artifact at `artifacts/phase-2/wrapper_verification.json`.
