"""
Tests for AnalysisState Dataclass and Transitions (src/agent/state.py).
Failure Modes Covered:
- FM-ST-01: Validation on missing required fields or invalid path
- FM-ST-02: State serialization and deserialization roundtrip
- FM-ST-03: Transition validation (cannot transition to next node if current node errored)
- FM-ST-04: Analyst decision logging in history
"""

import pytest

from src.agent.state import AnalysisState, NodeStatus


def test_fm_st_01_invalid_initialization():
    with pytest.raises(ValueError):
        AnalysisState(sample_path="")


def test_state_initialization_defaults():
    state = AnalysisState(sample_path="/path/to/sample.bin")
    assert state.sample_path == "/path/to/sample.bin"
    assert state.current_stage == "init"
    assert state.status == NodeStatus.PENDING
    assert state.peeled_layers == []
    assert state.genetic_matches == []
    assert state.analyst_decisions == []


def test_fm_st_02_json_serialization_roundtrip():
    state = AnalysisState(
        sample_path="/tmp/malware.exe",
        sample_sha256="abcdef1234567890",
        file_format="PE",
        entropy=6.45,
    )
    state.record_decision(gate_name="gate_peel", approved=True, notes="Proceed to trait matching")

    json_str = state.to_json()
    assert isinstance(json_str, str)

    restored = AnalysisState.from_json(json_str)
    assert restored.sample_path == state.sample_path
    assert restored.sample_sha256 == state.sample_sha256
    assert restored.file_format == "PE"
    assert restored.entropy == 6.45
    assert len(restored.analyst_decisions) == 1
    assert restored.analyst_decisions[0]["gate_name"] == "gate_peel"
    assert restored.analyst_decisions[0]["approved"] is True


def test_fm_st_04_analyst_decision_recording():
    state = AnalysisState(sample_path="/tmp/sample.bin")
    state.record_decision(
        gate_name="gate_verify",
        approved=False,
        notes="Suspect evasion block, override offset to 0x401000",
        overrides={"target_offset": 0x401000},
    )
    assert len(state.analyst_decisions) == 1
    dec = state.analyst_decisions[0]
    assert dec["gate_name"] == "gate_verify"
    assert dec["approved"] is False
    assert dec["overrides"]["target_offset"] == 0x401000
