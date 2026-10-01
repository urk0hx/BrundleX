"""
Tests for PocketFlow Guided Orchestrator and Pipeline Nodes (src/agent/orchestrator.py).
Failure Modes Covered:
- FM-ORCH-01: IngestNode with non-existent file sets error status
- FM-ORCH-02: Analyst checkpoint gate pauses execution when gate is active
- FM-ORCH-03: Resuming from analyst checkpoint applies manual override parameters
- FM-ORCH-04: PeelNode detects obfuscation or passes clean binary forward
- FM-ORCH-05: Complete orchestrator pipeline execution
"""

import os

from src.agent.nodes import IngestNode, PeelNode
from src.agent.orchestrator import PocketFlowOrchestrator
from src.agent.state import AnalysisState, NodeStatus


def test_fm_orch_01_ingest_node_missing_file():
    state = AnalysisState(sample_path="/path/to/missing_file.bin")
    node = IngestNode()
    state = node.execute(state)
    assert state.status == NodeStatus.FAILED
    assert "not found" in state.error_message.lower()


def test_ingest_node_valid_binary():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    state = AnalysisState(sample_path=target)
    node = IngestNode()
    state = node.execute(state)
    assert state.status == NodeStatus.COMPLETED
    assert len(state.sample_sha256) == 64
    assert state.entropy > 0
    assert state.file_format in ["ELF", "PE", "UNKNOWN"]


def test_fm_orch_02_analyst_gate_pauses():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    state = AnalysisState(sample_path=target)
    # Enable analyst gate before TraitMatch
    orchestrator = PocketFlowOrchestrator(
        require_approval_gates={"gate_peel": True, "gate_verify": True}
    )

    state = orchestrator.run_until_pause_or_finish(state)
    assert state.status == NodeStatus.PAUSED_AT_GATE
    assert state.paused_gate_name == "gate_peel"


def test_fm_orch_03_resume_with_analyst_override():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    state = AnalysisState(sample_path=target)
    orchestrator = PocketFlowOrchestrator(
        require_approval_gates={"gate_peel": True}
    )

    # Run until first gate
    state = orchestrator.run_until_pause_or_finish(state)
    assert state.status == NodeStatus.PAUSED_AT_GATE

    # Analyst approves and overrides parameters
    state = orchestrator.approve_and_resume(
        state,
        gate_name="gate_peel",
        notes="Analyst confirmed unpacked payload",
        overrides={"custom_flag": "analyst_approved"},
    )
    assert state.status in [NodeStatus.COMPLETED, NodeStatus.PAUSED_AT_GATE]
    assert state.analyst_decisions[-1]["overrides"]["custom_flag"] == "analyst_approved"


def test_fm_orch_04_peel_node_clean_sample():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    state = AnalysisState(sample_path=target)
    state = IngestNode().execute(state)
    state = PeelNode().execute(state)
    assert state.status == NodeStatus.COMPLETED
    assert state.active_payload_path is not None


def test_fm_orch_05_complete_orchestration_run():
    target = "/bin/true" if os.path.exists("/bin/true") else "/bin/ls"
    state = AnalysisState(sample_path=target)
    # Auto-approve all gates for full headless execution
    orchestrator = PocketFlowOrchestrator(
        require_approval_gates={},
        db_path="data/traits.db",
    )
    final_state = orchestrator.run_until_pause_or_finish(state)
    assert final_state.status == NodeStatus.COMPLETED
    assert final_state.final_report is not None
    assert "Triage Verdict" in final_state.final_report or "Report" in final_state.final_report
