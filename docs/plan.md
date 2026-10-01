# Implementation Plan: BrundleX Agent & Mutation Studio

## Status Dashboard
* **Phase 1: Foundation & Data Harvesting** -> `COMPLETED` (Proof: `artifacts/phase-1/harvest_log.json`)
* **Phase 2: Tool Wrapper Layer** -> `COMPLETED` (Proof: `artifacts/phase-2/wrapper_verification.json`)
* **Phase 3: PocketFlow Orchestrator & Local LLM Integration** -> `COMPLETED` (Proof: `artifacts/phase-3/flow_execution_trace.json`)
* **Phase 4: Predictive Trait Simulation Engine** -> `COMPLETED` (Proof: `artifacts/phase-4/mutation_verification_sample.json`)
* **Phase 5: FastAPI + HTMX Single-Page Workspace** -> `COMPLETED` (Proof: `tests/unit/test_server.py`)
* **Phase 6: End-to-End Testing & Hardening** -> `COMPLETED` (Proof: `artifacts/phase-6/e2e_evaluation_report.md`)

---

### Phase 1: Foundation & Data Harvesting
* **Goal:** Establish SQLite genetic traits storage, Shannon entropy filter, and fetch initial malware samples safely.
* **Tasks:**
  1. Initialize Podman environment (`Containerfile`, `Makefile`).
  2. Implement SQLite schema (`src/storage/db.py`) for samples and Binlex traits with indexing.
  3. Implement Shannon entropy gatekeeper (`src/harvester/entropy.py`).
  4. Build ephemeral harvester script (`tools/harvest_traits.py`) using MalwareBazaar API.
  5. Harvest and extract traits from 5-10 known malware samples (e.g., Lumma, Stealc).
* **Deliverable Proof:** `artifacts/phase-1/harvest_log.json` showing successfully stored traits and zero host filesystem leaks.

---

### Phase 2: Tool Wrapper Layer
* **Goal:** Create robust Python wrappers around the core reverse engineering toolchain.
* **Tasks:**
  1. `src/tools/binlex_runner.py`: Extract traits, calculate MinHash signatures, query similarity against local DB.
  2. `src/tools/radare_runner.py`: Disassemble functions, extract control flow graphs (CFGs), execute ESIL emulation on basic blocks.
  3. `src/tools/refinery_runner.py`: Carve payloads, brute-force single-byte/multi-byte XOR, strip overlays.
* **Deliverable Proof:** `artifacts/phase-2/wrapper_verification.json` demonstrating programmatic execution of each tool against a sample binary.

---

### Phase 3: PocketFlow Orchestrator & Local LLM Integration
* **Goal:** Implement the guided state machine (Option C) connecting all tools with human approval checkpoints.
* **Tasks:**
  1. Implement `src/agent/state.py` defining `AnalysisState`.
  2. Implement PocketFlow nodes:
     * `IngestNode`: Structural check via magic bytes and Shannon entropy.
     * `PeelNode`: Calls Refinery if packed/layered (XOR, carve, overlay).
     * `TraitMatchNode`: Queries `traits.db` for nearest genetic neighbors via MinHash.
     * `VerifyNode`: Instructs Radare2 to disassemble and validate key basic blocks with ESIL.
     * `ReportNode`: Generates summary markdown and triage attribution.
  3. Implement Analyst Approval Gates allowing manual overrides between nodes.
  4. Create `src/agent/llm_client.py` targeting OpenAI-compatible endpoints with strict JSON schemas, primary and fallback model resilience.
* **Deliverable Proof:** `artifacts/phase-3/flow_execution_trace.json`.

---

### Phase 4: Predictive Trait Simulation Engine
* **Goal:** Build the mutation studio engine that scrambles basic blocks while preserving runtime semantics.
* **Tasks:**
  1. Build `src/mutation/operators.py`:
     * Register substitution based on non-volatile register sets.
     * Peephole optimization rules (semantic equivalents).
     * Instruction permutation for non-interfering instruction pairs.
  2. Build `src/mutation/verifier.py`:
     * Harness to execute original and mutated blocks in Radare2 ESIL, verifying identical end states.
  3. Build `src/mutation/yara_generator.py`:
     * Synthesize resilient YARA signatures with automated wildcarding (`??`) over mutable bytes.
* **Deliverable Proof:** `artifacts/phase-4/mutation_verification_sample.json`.

---

### Phase 5: FastAPI + HTMX Single-Page Workspace
* **Goal:** Deliver an intuitive, server-driven single-page web UI powered by FastAPI, HTMX, and Pico.css with zero custom JavaScript.
* **Tasks:**
  1. Build `server.py` and `templates/index.html`:
     * Dual-Pane layout: 330px fixed sidebar (target selection, direct binary upload, gates, reset) and dynamic studio tabs (Predictive Trait Studio, Genetic Lineage, Disassembly/ESIL, Audit Log).
     * Single-click theme switcher (warm cream light mode / dark mode) without DOM reloads.
     * Predictive Mutation Studio with configurable metadata (Author, Severity, TLP) and 1-click YARA rule download.
  2. Implement unit test suite in `tests/unit/test_server.py` covering all endpoints and UI failure modes.
* **Deliverable Proof:** `tests/unit/test_server.py` (5 passing tests).

---

### Phase 6: End-to-End Testing & Hardening
* **Goal:** Validate the complete workflow from ingestion to simulation on real-world unpacked malware.
* **Tasks:**
  1. Ingest a newly published unpacked sample from MalwareBazaar.
  2. Run the agent end-to-end to verify accurate family attribution.
  3. Run the Predictive Trait Studio on a decryption routine and verify the autogenerated YARA rule matches both original and simulated variants.
* **Deliverable Proof:** `artifacts/phase-6/e2e_evaluation_report.md`.
