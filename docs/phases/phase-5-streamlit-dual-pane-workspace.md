# Phase 5: FastAPI + HTMX + Pico.css Single-Page Workspace

## Status: COMPLETED (Decoupled Single-Page Architecture)

### Objectives
1. Build a decoupled, high-performance, single-page web workspace powered by **FastAPI**, **HTMX**, and **Pico.css v2** with **zero custom JavaScript**.
2. Build `server.py` and `templates/index.html`:
   - **Header & Telemetry:** Single-click theme toggle (warm cream light mode / dark mode), Target Binary Hashes card (SHA-256 with 1-click copy, SHA-1, MD5), and dynamic KPI cards for Detected Family, Confidence Score, Entropy, and Status.
   - **Sidebar / Controls:**
     - Target binary selector with pinned library optgroups, custom path toggle, and direct local file upload.
     - Sample library pinning/unpinning lifecycle (`POST /sample/pin`, `POST /sample/unpin`).
     - On-demand "Harvest 10 Samples" button updating `data/traits.db` in real-time.
     - Run Pipeline trigger and Reset Run button (conditionally disabled when idle).
     - PocketFlow Stage Stepper (`Ingest` -> `Peel` -> `Trait Match` -> `Verify` -> `Report`).
     - Analyst Gate Approval / Override action controls (`Approve & Proceed`, `Override Family`, `Skip Layer`).
     - Real-time Analyst Dialogue & Audit Log displaying step-by-step reasoning and LLM attribution thoughts.
   - **Main Studio Tabs:**
     - **Tab 1: Predictive Trait Studio:**
       - Basic block input / auto-load from target sample.
       - Aggression level slider (1 to 5).
       - Operator toggles (Register substitution, peephole optimizations, instruction permutation) and variant count selector.
       - "Simulate Variants & Stress-Test" trigger button.
       - ESIL Invariance verification status table for each generated variant.
       - Synthesized resilient YARA rule with automated `??` wildcards.
       - Configurable YARA metadata (Rule Name, Author, Description, Severity, TLP) and 1-click rule download (`.yar`).
     - **Tab 2: Genetic Lineage:** Table and metrics of nearest-neighbor matches from `data/traits.db`, matching Jaccard scores, and filtered traits count.
     - **Tab 3: Disassembly & ESIL:** Disassembly snippet, function entry symbol, CFG basic block metadata, and emulated register capture.
     - **Tab 4: Execution & Audit Log:** Raw PocketFlow node execution timeline.
3. Verification & Proof:
   - Full FastAPI unit test suite covering headless load (`FM-UI-01`), mutation studio execution & YARA rule download (`FM-UI-02`), theme toggle and reset (`FM-UI-03`), file upload (`FM-UI-04`), and sample pinning (`FM-UI-05`) in `tests/unit/test_server.py`.
   - Complete removal of legacy Streamlit dependencies and artifacts.

---

### 1. Delivered
- **`requirements.txt`**: Added `fastapi`, `uvicorn`, `jinja2`, `python-multipart` and removed `streamlit`.
- **`Makefile`**: Configured `ui` and `ui-bg` targets to launch `uvicorn server:app --host 0.0.0.0 --port 8501` inside the container with `--security-opt label=disable`.
- **`server.py`**: Clean, modular FastAPI application serving server-rendered partials and single-page HTMX responses.
- **`templates/index.html`**: Pure HTMX + Pico.css v2 responsive single-page application with dark and warm cream light themes.
- **`tests/unit/test_server.py`**: Unit test suite covering all UI endpoints and failure modes.

---

### 2. Proof
- **Unit Tests:** All unit tests passing (`make test-unit`).
- **E2E Tests:** All E2E tests passing (`make test-e2e`).
- **Linter:** `make check` passed with 0 errors.
