"""
PocketFlow Graph Definitions for BrundleX Triage Agent.
Connects Ingest -> GatePeel -> Peel -> GateTrait -> TraitMatch -> GateVerify -> Verify -> Report
using PocketFlow operator syntax.
"""

from pocketflow import BaseNode, Flow

from src.agent.llm_client import LLMClient
from src.agent.nodes import (
    AnalystGateNode,
    IngestNode,
    PeelNode,
    ReportNode,
    TraitMatchNode,
    VerifyNode,
)


def create_triage_flow(
    db_path: str = "data/traits.db",
    llm_client: LLMClient | None = None,
) -> tuple[Flow, dict[str, BaseNode]]:
    """
    Constructs the standard triage flow graph.
    Returns the Flow starting at IngestNode, and a dict of instantiated nodes.
    """
    ingest = IngestNode()
    gate_peel = AnalystGateNode("gate_peel")
    peel = PeelNode()
    gate_trait = AnalystGateNode("gate_trait")
    trait = TraitMatchNode(db_path=db_path)
    gate_verify = AnalystGateNode("gate_verify")
    verify = VerifyNode()
    report = ReportNode(llm_client=llm_client)

    # Ingest -> GatePeel
    ingest >> gate_peel

    # GatePeel: on "proceed" -> peel (pause terminates)
    gate_peel - "proceed" >> peel

    # Peel -> GateTrait
    peel >> gate_trait

    # GateTrait: on "proceed" -> trait (pause terminates)
    gate_trait - "proceed" >> trait

    # Trait -> GateVerify
    trait >> gate_verify

    # GateVerify: on "proceed" -> verify (pause terminates)
    gate_verify - "proceed" >> verify

    # Verify -> Report
    verify >> report

    flow = Flow(start=ingest)
    node_registry: dict[str, BaseNode] = {
        "ingest": ingest,
        "gate_peel": gate_peel,
        "peel": peel,
        "gate_trait": gate_trait,
        "trait": trait,
        "gate_verify": gate_verify,
        "verify": verify,
        "report": report,
    }
    return flow, node_registry
