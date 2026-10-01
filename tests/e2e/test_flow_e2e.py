"""
End-to-End Test for Phase 3 Guided PocketFlow Orchestration.
Executes the full triage flow from Ingest -> Peel -> TraitMatch -> Verify -> Report,
validates analyst checkpoints, and writes artifacts/phase-3/flow_execution_trace.json.
"""

import os

from src.agent.orchestrator import PocketFlowOrchestrator
from src.agent.state import AnalysisState, NodeStatus


def test_phase_3_flow_e2e():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    artifacts_dir = "artifacts/phase-3"
    os.makedirs(artifacts_dir, exist_ok=True)

    state = AnalysisState(sample_path=target)

    # Configure orchestrator with a checkpoint at gate_peel
    orchestrator = PocketFlowOrchestrator(
        require_approval_gates={"gate_peel": True},
        db_path="data/traits.db",
    )

    # 1. Step 1: Run to analyst gate
    state = orchestrator.run_until_pause_or_finish(state)
    assert state.status == NodeStatus.PAUSED_AT_GATE
    assert state.paused_gate_name == "gate_peel"
    assert state.current_stage == "ingest"

    # 2. Step 2: Analyst provides approval with notes
    state = orchestrator.approve_and_resume(
        state,
        gate_name="gate_peel",
        notes="Analyst verified clean unpacked executable. Approved for genetic trait matching.",
        overrides={"analyst_override": "proceed"},
    )

    # 3. Assert pipeline ran to completion
    assert state.status == NodeStatus.COMPLETED
    assert state.final_report is not None
    assert state.current_stage == "report"

    # 4. Save trace artifact
    trace_path = os.path.join(artifacts_dir, "flow_execution_trace.json")
    with open(trace_path, "w") as f:
        f.write(state.to_json(indent=2))

    assert os.path.exists(trace_path)
    print(f"\n[PHASE 3 E2E VERIFIED] Flow trace written to {trace_path}")
