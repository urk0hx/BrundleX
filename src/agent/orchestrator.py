"""
PocketFlow State Machine Orchestrator for BrundleX Triage Agent.
Integrates IngestNode, PeelNode, TraitMatchNode, VerifyNode, ReportNode, and AnalystGateNode.
Supports step execution, human-in-the-loop pause/resume, and override injection.
"""

import logging
from typing import Any

from pocketflow import BaseNode, Flow

from src.agent.flow import create_triage_flow
from src.agent.llm_client import LLMClient
from src.agent.state import AnalysisState, NodeStatus

logger = logging.getLogger(__name__)


class PocketFlowOrchestrator:
    """
    State machine orchestrator managing lifecycle and human-in-the-loop analyst gates.
    Wired directly to native PocketFlow Flow graph.
    """

    def __init__(
        self,
        db_path: str = "data/traits.db",
        require_approval_gates: dict[str, bool] | None = None,
        llm_client: LLMClient | None = None,
    ):
        self.db_path = db_path
        self.require_approval_gates = require_approval_gates or {}
        if llm_client is not None:
            self.llm_client = llm_client
        else:
            try:
                self.llm_client = LLMClient()
            except ValueError:
                self.llm_client = None

        self.flow, self.nodes = create_triage_flow(
            db_path=self.db_path,
            llm_client=self.llm_client,
        )

    @property
    def ingest_node(self) -> BaseNode:
        return self.nodes["ingest"]

    @property
    def peel_node(self) -> BaseNode:
        return self.nodes["peel"]

    @property
    def trait_node(self) -> BaseNode:
        return self.nodes["trait"]

    @property
    def verify_node(self) -> BaseNode:
        return self.nodes["verify"]

    @property
    def report_node(self) -> BaseNode:
        return self.nodes["report"]

    def run_until_pause_or_finish(self, state: AnalysisState) -> AnalysisState:
        """
        Executes the PocketFlow DAG from the start until a gate pauses execution,
        an error occurs, or the entire flow completes.
        """
        # Register configured gates in state
        if self.require_approval_gates:
            state.require_approval_gates.update(self.require_approval_gates)

        if state.status == NodeStatus.NOT_STARTED:
            state.status = NodeStatus.IN_PROGRESS

        # Run the PocketFlow graph
        self.flow.run(state)

        # Ensure terminal status is correctly reflected
        if state.paused_gate_name:
            state.status = NodeStatus.PAUSED_AT_GATE
        elif state.final_report or state.current_stage == "report":
            state.status = NodeStatus.COMPLETED

        return state

    def approve_and_resume(
        self,
        state: AnalysisState,
        gate_name: str,
        notes: str = "",
        overrides: dict[str, Any] | None = None,
    ) -> AnalysisState:
        """
        Records analyst approval for a paused gate and resumes execution of the flow.
        """
        # Record analyst decision in state
        state.record_decision(
            gate_name=gate_name,
            approved=True,
            notes=notes,
            overrides=overrides,
        )
        state.status = NodeStatus.IN_PROGRESS
        state.paused_gate_name = None

        gate_to_next = {
            "gate_peel": "peel",
            "gate_trait": "trait",
            "gate_verify": "verify",
        }
        next_node_name = gate_to_next.get(gate_name)
        if next_node_name and next_node_name in self.nodes:
            resume_flow = Flow(start=self.nodes[next_node_name])
            resume_flow.run(state)

        # Ensure terminal status is correctly reflected after resumed flow
        if state.paused_gate_name:
            state.status = NodeStatus.PAUSED_AT_GATE
        elif state.final_report or state.current_stage == "report":
            state.status = NodeStatus.COMPLETED

        return state

    def run(self, state: AnalysisState) -> AnalysisState:
        """Alias for run_until_pause_or_finish."""
        return self.run_until_pause_or_finish(state)
