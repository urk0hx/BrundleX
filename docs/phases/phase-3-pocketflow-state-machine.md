# Phase 3: PocketFlow Orchestrator & Local LLM Integration

## Status: COMPLETED

### Objectives
1. Implement `src/agent/state.py` defining `AnalysisState` dataclass tracking complete lifecycle:
   - Target sample metadata (path, sha256, format, entropy, file size).
   - Peel/deobfuscation layer history (XOR keys, carved binaries, overlays).
   - Genetic trait extraction and nearest neighbor matches from `data/traits.db`.
   - Radare2 verification traces (functions, CFG nodes, ESIL register states).
   - Analyst gates, approvals, overrides, and execution logs.
   - Dual interface: dataclass attribute access and dict subscripting for PocketFlow shared store.
2. Implement `src/agent/llm_client.py`:
   - Connects to OpenAI-compatible endpoint with bearer auth.
   - Primary (`LLM_MODEL`) and Fallback (`LLM_FALLBACK_MODEL`) model switching.
   - Strict JSON-schema generation and automatic schema repair for structured analyst reasoning.
   - Strict no-mock-data guarantee with explicit error handling.
3. Implement native PocketFlow nodes in `src/agent/nodes.py` (inheriting from `pocketflow.Node`):
   - 3-step lifecycle: `prep(shared)` -> `exec(prep_res)` -> `post(shared, prep_res, exec_res)` with automatic retries and `exec_fallback`.
   - `IngestNode`: Structural PE/ELF inspection via magic bytes, calculating entropy and metadata.
   - `PeelNode`: Obfuscation peeling via `src/tools/refinery_runner.py` (XOR, carving, overlay).
   - `TraitMatchNode`: Genetic trait extraction and attribution via `src/tools/binlex_runner.py`.
   - `VerifyNode`: Disassembly, CFG construction, and ESIL CPU state emulation via `src/tools/radare_runner.py`.
   - `ReportNode`: LLM-assisted synthesis generating structured triage verdict and Markdown report.
   - `AnalystGateNode`: Human-in-the-loop analyst checkpoint gate returning conditional `"pause"` or `"proceed"`.
4. Implement `src/agent/flow.py`:
   - Native `pocketflow.Flow` graph connecting nodes via `>>` and conditional branching (`- "proceed" >>`).
5. Implement `src/agent/orchestrator.py`:
   - Coordinates flow execution, manages pause/resume cycles across analyst approval gates, and logs execution audit trails.
6. Verification & Test Suite:
   - Unit tests covering all failure modes in `tests/unit/test_state.py`, `tests/unit/test_llm_client.py`, `tests/unit/test_orchestrator.py`.
   - End-to-end integration test in `tests/e2e/test_flow_e2e.py` producing `artifacts/phase-3/flow_execution_trace.json`.

---

### 1. Delivered
- **Dependency:** Added `pocketflow>=0.0.3` to `requirements.txt` and rebuilt container.
- **`src/agent/state.py`**: Complete `AnalysisState` dataclass with `NodeStatus` state tracking, JSON/dict serialization roundtrip, and analyst decision recording, supporting PocketFlow shared dictionary access.
- **`src/agent/llm_client.py`**: OpenAI-compatible client supporting live endpoints, primary model execution, automatic fallback failover upon failure or timeout, and robust JSON extraction from conversational outputs and markdown fences.
- **`src/agent/nodes.py`**: Full pipeline nodes (`IngestNode`, `PeelNode`, `TraitMatchNode`, `VerifyNode`, `ReportNode`, `AnalystGateNode`) inheriting from `pocketflow.Node` with strict `prep`/`exec`/`post` separation of concerns.
- **`src/agent/flow.py`**: Idiomatic PocketFlow graph definition wiring nodes using `>>` and conditional branching.
- **`src/agent/orchestrator.py`**: Guided `PocketFlowOrchestrator` coordinating execution and human-in-the-loop analyst approval gates (`gate_peel`, `gate_trait`, `gate_verify`) with pause/resume and parameter overrides.
- **`tools/test_llm_connection.py`** & **`make test-llm`**: Operational diagnostic CLI testing endpoints, enumerating available models, and pinging primary and fallback models.

---

### 2. Proof
- **Artifact:** `artifacts/phase-3/flow_execution_trace.json` (verified with live LLM endpoint)
- **Unit Tests:** 62 tests passing (`tests/unit/`)
- **E2E Tests:** 3 tests passing (`tests/e2e/test_flow_e2e.py`, `tests/e2e/test_harvest_e2e.py`, `tests/e2e/test_wrappers_e2e.py`)
- **Linter:** Clean static analysis via `make check` (ruff)

---

### 3. Deferred
- Phase 4: CLI Interface & Analyst Interaction (Interactive TUI/CLI command line tool wrapping the orchestrator for analysts).

---

### 4. Human Review Notes
- All unit and E2E tests execute inside Podman containers via `make test-unit` and `make test-e2e`.
- Official `pocketflow` framework integration tested and verified with zero external runtime dependencies.
