# Phase 1: Foundation & Data Harvester

## Status: Completed

### Objectives
1. Establish the repository layout, configuration files, container environment, and dependencies.
2. Initialize the SQLite trait schema (`data/traits.db`) to index samples, traits, and chromosomes per `docs/design.md`.
3. Build the ephemeral MalwareBazaar harvester script (`tools/harvest_traits.py`) with Shannon entropy filtering and automatic cleanup.
4. Seed the database with an initial batch of unpacked samples from at least two distinct malware families.

---

### 1. Delivered
- [x] Project scaffolding:
  - `requirements.txt`: Python 3.10 runtime dependencies (`requests`, `pyzipper`, `python-dotenv`, `pytest`, `pytest-mock`, `ruff`).
  - `Containerfile`: Reproducible Podman container bundling Python 3, `binlex v1.1.1` CLI, and `pybinlex` extension.
  - `Makefile`: Standard lifecycle targets (`preflight`, `build`, `up`, `down`, `check`, `test-unit`, `test-e2e`, `harvest`, `clean`). All executions strictly run inside the container.
  - `.env.example` and local `.env`: Zero-touch environment variable configuration.
  - Directory structure (`src/storage/`, `src/harvester/`, `tools/`, `tests/unit/`, `tests/e2e/`, `data/`, `artifacts/phase-1/`).
- [x] SQLite database storage layer (`src/storage/db.py`):
  - Created schema matching `docs/design.md` Section 4.1 (`samples` and `traits` tables, indices on `tlsh_hash` and `family`, foreign key cascade).
  - Implemented CRUD and batch insertion APIs with atomic rollback and foreign key enforcement.
- [x] Shannon entropy gatekeeper (`src/harvester/entropy.py`):
  - Computes byte-level Shannon entropy $H(X) = -\sum p_i \log_2 p_i$.
  - Rejects packed/crypted malware samples exceeding threshold (default $H > 7.1$).
- [x] Binlex trait extraction runner (`src/harvester/binlex.py`):
  - Integrates `binlex` CLI via pseudo-terminal (`pty`) allocation to satisfy container ioctl requirements.
  - Parses JSON output into normalized trait records (blocks, functions, chromosome wildcard bytes, TLSH, minhash).
- [x] Ephemeral MalwareBazaar harvester (`src/harvester/malwarebazaar.py` and `tools/harvest_traits.py`):
  - AES/ZipCrypto encrypted archive decompression directly in-memory into temporary scratch space `/tmp/<sha256>`.
  - Guaranteed immediate disk cleanup via `try...finally`.
  - Verified live queries and downloads via authenticated MalwareBazaar API, plus offline seeding via `--seed-demo`.
- [x] Verification and test suite:
  - 26 unit tests in `tests/unit/` covering failure modes FM-DB-01..05, FM-ENT-01..05, FM-BLX-01..05, FM-MB-01..07.
  - End-to-end integration test in `tests/e2e/test_harvest_e2e.py`.
  - Verification artifact written to `artifacts/phase-1/harvest_log.json`.

---

### 2. Proof
- **Unit & Integration Test Suite:**
  - Command: `make check test-unit test-e2e`
  - Result: 27 passed tests (26 unit, 1 E2E), 0 failures, 0 ruff lint errors.
- **Verification Artifact:**
  - Path: `artifacts/phase-1/harvest_log.json`
  - Database: `data/traits.db`
  - Total Samples in DB: 6 (including offline seeded samples + live harvested samples from MalwareBazaar)
  - Total Traits in DB: 235,140 traits.
  - Live Samples Harvested: AMOS (Mach-O script payloads) and WailsLoader (PE binary, 156,343 traits, H=6.42).

---

### 3. Deferred
- Multi-threaded parallel downloading from MalwareBazaar (deferred to future optimization; single-threaded is sufficient for MVP seeding).

---

### 4. Human Review Notes
- Verified `binlex` CLI (`v1.1.1`) inside the container via `pty` wrapper.
- Verified live MalwareBazaar API key with live sample download and extraction into `data/traits.db`.
