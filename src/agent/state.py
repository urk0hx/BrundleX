"""
AnalysisState: Shared State Store for PocketFlow Orchestrator.
Tracks sample lifecycle, obfuscation peeling layers, genetic traits matching,
Radare2 CFG/ESIL emulation traces, analyst approval checkpoints, and LLM report synthesis.
"""

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class NodeStatus(str, Enum):
    PENDING = "pending"
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED_AT_GATE = "paused_at_gate"


@dataclass
class AnalysisState:
    """
    Central shared state passed between PocketFlow nodes.
    Supports both attribute access and dict-like subscripting for PocketFlow shared store.
    """

    sample_path: str
    active_payload_path: str = ""
    sample_sha256: str = ""
    sample_sha1: str = ""
    sample_md5: str = ""
    pe_hashes: dict[str, str] = field(default_factory=dict)
    file_format: str = "UNKNOWN"
    file_size: int = 0
    entropy: float = 0.0

    current_stage: str = "init"
    status: NodeStatus = NodeStatus.PENDING
    error_message: str | None = None
    paused_gate_name: str | None = None

    peeled_layers: list[dict[str, Any]] = field(default_factory=list)
    genetic_matches: list[dict[str, Any]] = field(default_factory=list)
    traits_extracted_count: int = 0
    candidate_blocks: list[dict[str, Any]] = field(default_factory=list)
    radare_verification: dict[str, Any] = field(default_factory=dict)
    analyst_decisions: list[dict[str, Any]] = field(default_factory=list)
    require_approval_gates: dict[str, bool] = field(default_factory=dict)
    gate_approvals: dict[str, dict[str, Any]] = field(default_factory=dict)

    llm_verdict: dict[str, Any] = field(default_factory=dict)
    final_report: str | None = None
    execution_log: list[str] = field(default_factory=list)
    proactive_yara: str | None = None
    proactive_yara_metrics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.sample_path:
            raise ValueError("sample_path must be a non-empty string.")
        if not self.active_payload_path:
            self.active_payload_path = self.sample_path

    # Dictionary-like subscripting for PocketFlow compatibility
    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key) from None

    def __setitem__(self, key: str, value: Any) -> None:
        if hasattr(self, key):
            # Special conversion for status string
            if key == "status" and isinstance(value, str):
                try:
                    value = NodeStatus(value)
                except ValueError:
                    pass
            setattr(self, key, value)
        else:
            raise KeyError(f"AnalysisState has no field '{key}'")

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def log(self, message: str) -> None:
        """Appends a timestamped audit log string."""
        self.execution_log.append(message)

    def record_decision(
        self,
        gate_name: str,
        approved: bool,
        notes: str = "",
        overrides: dict[str, Any] | None = None,
    ) -> None:
        """Records an analyst decision and approval/rejection at a gate."""
        decision = {
            "gate_name": gate_name,
            "approved": approved,
            "notes": notes,
            "overrides": overrides or {},
        }
        self.analyst_decisions.append(decision)
        self.gate_approvals[gate_name] = decision
        self.log(f"[ANALYST GATE] {gate_name}: approved={approved}, notes='{notes}'")

    def to_dict(self) -> dict[str, Any]:
        """Serializes dataclass to a plain Python dict."""
        data = asdict(self)
        data["status"] = self.status.value if isinstance(self.status, NodeStatus) else self.status
        return data

    def to_json(self, indent: int = 2) -> str:
        """Serializes AnalysisState to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisState":
        """Reconstructs AnalysisState from dictionary."""
        data_copy = dict(data)
        if "status" in data_copy and isinstance(data_copy["status"], str):
            data_copy["status"] = NodeStatus(data_copy["status"])
        return cls(**data_copy)

    @classmethod
    def from_json(cls, json_str: str) -> "AnalysisState":
        """Deserializes AnalysisState from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
