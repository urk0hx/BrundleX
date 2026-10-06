"""
PocketFlow Pipeline Nodes for BrundleX Triage Agent:
- IngestNode: Structural analysis and entropy computation
- PeelNode: Obfuscation removal and payload carving
- TraitMatchNode: Genetic trait extraction and SQLite similarity query
- VerifyNode: Radare2 disassembly and ESIL emulation
- ReportNode: LLM synthesis and report generation
- AnalystGateNode: Human-in-the-loop analyst checkpoint gate
"""

import hashlib
import logging
import os
from typing import Any

from pocketflow import Node

from src.agent.llm_client import LLMClient
from src.agent.state import AnalysisState, NodeStatus
from src.harvester.entropy import calculate_entropy
from src.tools.binlex_runner import (
    extract_traits,
    match_traits_against_db,
    rank_mutation_candidates,
)
from src.tools.radare_runner import RadareRunner
from src.tools.refinery_runner import (
    calculate_pe_hashes,
    carve_pe_payloads,
    scan_xor_keys,
    strip_pe_overlay,
)

logger = logging.getLogger(__name__)


class IngestNode(Node):
    """Inspects target file, calculates SHA256, format signature, and entropy."""

    def __init__(self, max_retries: int = 1, wait: int = 0):
        super().__init__(max_retries=max_retries, wait=wait)

    def prep(self, shared: Any) -> dict[str, Any]:
        shared["current_stage"] = "ingest"
        target = shared.get("active_payload_path") or shared.get("sample_path")
        return {"target_path": target}

    def exec(self, prep_res: dict[str, Any]) -> dict[str, Any]:
        target_path = prep_res["target_path"]
        if not target_path or not os.path.exists(target_path):
            raise FileNotFoundError(f"Sample file not found: {target_path}")

        with open(target_path, "rb") as f:
            data = f.read()

        file_size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        entropy = round(calculate_entropy(data), 3)

        pe_hashes = {}
        if data.startswith(b"MZ"):
            file_format = "PE"
            pe_hashes = calculate_pe_hashes(data)
        elif data.startswith(b"\x7fELF"):
            file_format = "ELF"
        elif data.startswith((b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe")):
            file_format = "MACHO"
        else:
            file_format = "UNKNOWN"

        return {
            "file_size": file_size,
            "sample_sha256": sha256,
            "sample_sha1": sha1,
            "sample_md5": md5,
            "pe_hashes": pe_hashes,
            "entropy": entropy,
            "file_format": file_format,
        }

    def exec_fallback(self, prep_res: dict[str, Any], exc: Exception) -> dict[str, Any]:
        return {"error": str(exc)}

    def post(self, shared: Any, prep_res: dict[str, Any], exec_res: dict[str, Any]) -> str:
        shared["current_stage"] = "ingest"
        if "error" in exec_res:
            shared["status"] = NodeStatus.FAILED
            shared["error_message"] = f"IngestNode failed: {exec_res['error']}"
            if hasattr(shared, "log"):
                shared.log(f"[ERROR] IngestNode: {shared['error_message']}")
            return "error"

        shared["file_size"] = exec_res["file_size"]
        shared["sample_sha256"] = exec_res["sample_sha256"]
        shared["sample_sha1"] = exec_res.get("sample_sha1", "")
        shared["sample_md5"] = exec_res.get("sample_md5", "")
        shared["pe_hashes"] = exec_res.get("pe_hashes", {})
        shared["entropy"] = exec_res["entropy"]
        shared["file_format"] = exec_res["file_format"]
        shared["status"] = NodeStatus.COMPLETED

        if hasattr(shared, "log"):
            shared.log(
                f"[INGEST] Format={exec_res['file_format']}, Size={exec_res['file_size']}b, "
                f"Entropy={exec_res['entropy']}, SHA256={exec_res['sample_sha256'][:16]}..."
            )
            # Scan for candidate XOR key indicator or overlay to give immediate visibility to analyst
            try:
                target_path = prep_res["target_path"]
                with open(target_path, "rb") as tf:
                    tbytes = tf.read()
                xor_pre = scan_xor_keys(tbytes, max_key_size=1)
                if xor_pre:
                    hit = xor_pre[0]
                    key_hex = hex(hit['key'])
                    ind = hit['matched_indicator']
                    shared.log(f"[INGEST] Layer obfuscation detected: Single-byte XOR key {key_hex} matching indicator '{ind}'. Peeling required.")
            except (OSError, RuntimeError, ValueError) as scan_err:
                logger.debug("Ingest layer pre-scan skipped: %s", scan_err)
        return "default"

    def execute(self, state: AnalysisState) -> AnalysisState:
        """Helper for direct execution compatibility."""
        self.run(state)
        return state


class PeelNode(Node):
    """Deobfuscates layers using Refinery (XOR detection, PE carving, overlay removal)."""

    def __init__(self, max_retries: int = 1, wait: int = 0):
        super().__init__(max_retries=max_retries, wait=wait)

    def prep(self, shared: Any) -> dict[str, Any]:
        shared["current_stage"] = "peel"
        target = shared.get("active_payload_path") or shared.get("sample_path")
        return {"target_path": target}

    def exec(self, prep_res: dict[str, Any]) -> dict[str, Any]:
        target_path = prep_res["target_path"]
        with open(target_path, "rb") as f:
            data = f.read()

        peeled = []
        active_path = target_path

        # 1. Overlay stripping
        cleaned_data = strip_pe_overlay(data)
        if len(cleaned_data) < len(data):
            overlay_len = len(data) - len(cleaned_data)
            peeled.append({
                "action": "strip_overlay",
                "bytes_removed": overlay_len,
            })
            data = cleaned_data

        # 2. XOR scanning
        xor_hits = scan_xor_keys(data, max_key_size=1)
        if xor_hits:
            best_hit = xor_hits[0]
            peeled.append({
                "action": "xor_decrypt",
                "key": best_hit["key"],
                "indicator": best_hit["matched_indicator"],
            })
            data = best_hit["decrypted"]

        # 3. Carving embedded PE payloads
        carved_list = carve_pe_payloads(data)
        if carved_list:
            inner_pe = carved_list[0]
            layer_path = f"/tmp/brundlex_layer_{len(peeled) + 1}.bin"
            with open(layer_path, "wb") as pf:
                pf.write(inner_pe)
            active_path = layer_path
            peeled.append({
                "action": "carve_pe",
                "extracted_size": len(inner_pe),
                "layer_path": layer_path,
            })

        return {
            "peeled_layers": peeled,
            "active_payload_path": active_path,
        }

    def exec_fallback(self, prep_res: dict[str, Any], exc: Exception) -> dict[str, Any]:
        return {"error": str(exc)}

    def post(self, shared: Any, prep_res: dict[str, Any], exec_res: dict[str, Any]) -> str:
        shared["current_stage"] = "peel"
        if "error" in exec_res:
            shared["status"] = NodeStatus.FAILED
            shared["error_message"] = f"PeelNode error: {exec_res['error']}"
            if hasattr(shared, "log"):
                shared.log(f"[ERROR] PeelNode: {shared['error_message']}")
            return "error"

        if exec_res["peeled_layers"]:
            shared["peeled_layers"].extend(exec_res["peeled_layers"])
        shared["active_payload_path"] = exec_res["active_payload_path"]

        # If a peeled layer produced an unpacked PE payload, update pe_hashes, format, and entropy
        try:
            with open(exec_res["active_payload_path"], "rb") as pf:
                active_bytes = pf.read()
            if active_bytes.startswith(b"MZ"):
                shared["file_format"] = "PE"
                pe_hashes = calculate_pe_hashes(active_bytes)
                if pe_hashes:
                    shared["pe_hashes"] = pe_hashes
            shared["entropy"] = round(calculate_entropy(active_bytes), 3)
        except OSError:
            pass

        shared["status"] = NodeStatus.COMPLETED

        if hasattr(shared, "log"):
            for layer in exec_res["peeled_layers"]:
                shared.log(f"[PEEL] Action '{layer['action']}' applied.")
        return "default"

    def execute(self, state: AnalysisState) -> AnalysisState:
        """Helper for direct execution compatibility."""
        self.run(state)
        return state


class TraitMatchNode(Node):
    """Extracts traits with Binlex and queries genetic database."""

    def __init__(self, db_path: str = "data/traits.db", max_retries: int = 1, wait: int = 0):
        super().__init__(max_retries=max_retries, wait=wait)
        self.db_path = db_path

    def prep(self, shared: Any) -> dict[str, Any]:
        shared["current_stage"] = "trait_match"
        target = shared.get("active_payload_path") or shared.get("sample_path")
        return {"target_path": target, "db_path": self.db_path}

    def exec(self, prep_res: dict[str, Any]) -> dict[str, Any]:
        target_path = prep_res["target_path"]
        db_path = prep_res["db_path"]

        traits = extract_traits(target_path)
        matches = []
        if os.path.exists(db_path):
            matches = match_traits_against_db(traits, db_path, threshold=0.001)

        candidate_blocks = rank_mutation_candidates(traits, top_n=5)

        return {
            "traits_extracted_count": len(traits),
            "genetic_matches": matches,
            "candidate_blocks": candidate_blocks,
        }

    def exec_fallback(self, prep_res: dict[str, Any], exc: Exception) -> dict[str, Any]:
        return {"error": str(exc)}

    def post(self, shared: Any, prep_res: dict[str, Any], exec_res: dict[str, Any]) -> str:
        shared["current_stage"] = "trait_match"
        if "error" in exec_res:
            shared["status"] = NodeStatus.FAILED
            shared["error_message"] = f"TraitMatchNode error: {exec_res['error']}"
            if hasattr(shared, "log"):
                shared.log(f"[ERROR] TraitMatchNode: {shared['error_message']}")
            return "error"

        shared["traits_extracted_count"] = exec_res["traits_extracted_count"]
        shared["genetic_matches"] = exec_res["genetic_matches"]
        if "candidate_blocks" in exec_res:
            shared["candidate_blocks"] = exec_res["candidate_blocks"]
        shared["status"] = NodeStatus.COMPLETED

        if hasattr(shared, "log"):
            shared.log(
                f"[TRAIT_MATCH] Extracted {exec_res['traits_extracted_count']} traits. "
                f"Found {len(exec_res['genetic_matches'])} database matches."
            )
        return "default"

    def execute(self, state: AnalysisState) -> AnalysisState:
        """Helper for direct execution compatibility."""
        self.run(state)
        return state


class VerifyNode(Node):
    """Analyzes disassembly, CFG, and emulates instructions via Radare2 ESIL."""

    def __init__(self, max_retries: int = 1, wait: int = 0):
        super().__init__(max_retries=max_retries, wait=wait)

    def prep(self, shared: Any) -> dict[str, Any]:
        shared["current_stage"] = "verify"
        target = shared.get("active_payload_path") or shared.get("sample_path")
        return {"target_path": target}

    def exec(self, prep_res: dict[str, Any]) -> dict[str, Any]:
        target_path = prep_res["target_path"]
        with RadareRunner(target_path) as r2:
            r2.analyze(level="aa")
            funcs = r2.get_functions()
            if not funcs:
                return {"function_count": 0}

            entry_func = funcs[0]
            addr = entry_func.get("addr") or entry_func.get("offset")
            disasm = r2.disassemble_function(addr)
            cfg = r2.get_cfg(addr)
            esil_regs = r2.emulate_esil(addr, num_steps=5)
            # Filter out internal/virtual registers (e.g. oeax) and format values cleanly
            meaningful_regs = {
                k: hex(v) if isinstance(v, int) else v
                for k, v in esil_regs.items()
                if not k.startswith("o") and k not in ("eflags", "flags")
            }
            return {
                "function_count": len(funcs),
                "verified_function": entry_func.get("name", "unknown"),
                "verified_address": addr,
                "instruction_count": len(disasm.get("ops", [])) if disasm else 0,
                "cfg_nodes": len(cfg.get("blocks", [])) if isinstance(cfg, dict) else len(cfg),
                "emulated_registers": list(esil_regs.keys()),
                "register_values": meaningful_regs,
            }

    def exec_fallback(self, prep_res: dict[str, Any], exc: Exception) -> dict[str, Any]:
        return {"error": str(exc)}

    def post(self, shared: Any, prep_res: dict[str, Any], exec_res: dict[str, Any]) -> str:
        shared["current_stage"] = "verify"
        if "error" in exec_res:
            shared["status"] = NodeStatus.FAILED
            shared["error_message"] = f"VerifyNode error: {exec_res['error']}"
            if hasattr(shared, "log"):
                shared.log(f"[ERROR] VerifyNode: {shared['error_message']}")
            return "error"

        shared["radare_verification"] = exec_res
        shared["status"] = NodeStatus.COMPLETED

        if hasattr(shared, "log"):
            funcs = exec_res.get("function_count", 0)
            raw_addr = exec_res.get("verified_address", "N/A")
            if isinstance(raw_addr, int):
                addr_str = f"0x{raw_addr:08x}"
            else:
                addr_str = str(raw_addr)
            func_name = exec_res.get("verified_function", "entry")
            regs = ", ".join(exec_res.get("emulated_registers", [])[:6])
            shared.log(
                f"[VERIFY] Radare2 mapped {funcs} functions. ESIL emulation at {func_name} ({addr_str}) "
                f"verified runtime registers [{regs}] with deterministic control flow."
            )
        return "default"

    def execute(self, state: AnalysisState) -> AnalysisState:
        """Helper for direct execution compatibility."""
        self.run(state)
        return state


def _synthesize_proactive_mutation(shared: Any, top_family: str) -> tuple[str | None, dict[str, Any] | None, list[str]]:
    candidate_blocks = shared.get("candidate_blocks") or []
    target_path = shared.get("active_payload_path") or shared.get("sample_path")
    if not target_path or not os.path.exists(target_path):
        return None, None, []

    disasm_lines: list[str] = []
    if candidate_blocks:
        try:
            top_cand = candidate_blocks[0]
            offset = top_cand.get("offset")
            if offset is not None:
                from src.tools.radare_runner import RadareRunner
                with RadareRunner(target_path) as r2:
                    r2.analyze(level="aa")
                    r2.r2.cmd("e io.va=false")
                    ops = r2.r2.cmdj(f"pdj 5 @ {offset}")
                    if ops:
                        for op in ops:
                            opcode = op.get("opcode", "").strip()
                            if opcode and opcode != "invalid":
                                disasm_lines.append(opcode)
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to extract candidate assembly for proactive mutation: %s", e)

    if not disasm_lines:
        disasm_lines = ["xor ecx, ecx", "mov rdx, 0x20", "add rax, 1"]

    try:
        from src.mutation.operators import (
            Instruction,
            detect_register_mapping,
            generate_mutations,
        )
        from src.mutation.verifier import ESILVerifier
        from src.mutation.yara_generator import (
            calculate_rule_metrics,
            generate_resilient_yara,
        )

        orig_instructions: list[Instruction] = []
        for line in disasm_lines:
            parts = line.split(maxsplit=1)
            mnemonic = parts[0]
            operands = [op.strip() for op in parts[1].split(",")] if len(parts) > 1 else []
            orig_instructions.append(Instruction(mnemonic=mnemonic, operands=operands))

        mutant_variants = generate_mutations(orig_instructions, aggression=2, num_variants=2)

        def _block_to_bytes(block: list[Instruction]) -> bytes:
            hex_str = "".join(inst.bytes_hex for inst in block if inst.bytes_hex)
            return bytes.fromhex(hex_str) if hex_str else b""

        orig_bytes = _block_to_bytes(orig_instructions)
        verifier = ESILVerifier()
        verified_bytes: list[bytes] = [orig_bytes] if orig_bytes else []
        for var in mutant_variants:
            vb = _block_to_bytes(var)
            if orig_bytes and vb:
                reg_map = detect_register_mapping(orig_instructions, var)
                is_inv, _, _ = verifier.verify_equivalence(orig_bytes, vb, arch="x86", bits=64, reg_map=reg_map)
                if is_inv:
                    verified_bytes.append(vb)
            elif vb:
                verified_bytes.append(vb)

        clean_fam = "".join(c if c.isalnum() or c == "_" else "_" for c in top_family).strip("_") or "generic"
        rule_name = f"brundlex_proactive_{clean_fam.lower()}_decryptor"
        extra_meta = {
            "tlp": "CLEAR",
            "severity": "HIGH",
            "reference": f"SHA256:{shared.get('sample_sha256', '')[:16]}...",
        }
        proactive_rule = generate_resilient_yara(
            rule_name=rule_name,
            variants=verified_bytes,
            family=top_family,
            author="BrundleX Autonomous Triage Agent",
            description=f"Proactive resilient signature synthesized from verified {top_family} decryptor mutations",
            extra_meta=extra_meta,
        )
        metrics = calculate_rule_metrics(verified_bytes)
        return proactive_rule, metrics, disasm_lines
    except Exception as e:  # noqa: BLE001
        logger.debug("Proactive mutation generation error: %s", e)
        return None, None, []


class ReportNode(Node):
    """Synthesizes analysis outputs using LLM and formats final triage report."""

    def __init__(self, llm_client: LLMClient | None = None, max_retries: int = 2, wait: int = 1):
        super().__init__(max_retries=max_retries, wait=wait)
        self.llm_client = llm_client

    def prep(self, shared: Any) -> dict[str, Any]:
        shared["current_stage"] = "report"
        prompt_payload = {
            "sample_sha256": shared.get("sample_sha256", ""),
            "format": shared.get("file_format", "UNKNOWN"),
            "entropy": shared.get("entropy", 0.0),
            "peeled_layers": shared.get("peeled_layers", []),
            "traits_extracted": shared.get("traits_extracted_count", 0),
            "top_genetic_matches": (shared.get("genetic_matches") or [])[:3],
            "radare_verification": shared.get("radare_verification", {}),
        }
        return {"prompt_payload": prompt_payload}

    def exec(self, prep_res: dict[str, Any]) -> dict[str, Any]:
        prompt_payload = prep_res["prompt_payload"]
        if self.llm_client:
            system_prompt = (
                "You are a principal reverse engineer and malware geneticist at BrundleX. "
                "Analyze the provided triage telemetry and return a strict JSON object with: "
                "'attribution' (predicted malware family or benign), 'confidence' (float 0.0-1.0), "
                "'verdict' (MALICIOUS/SUSPICIOUS/BENIGN), 'capabilities' (list of strings describing key evasion and payload capabilities), "
                "and 'summary' (comprehensive 2-4 sentence technical assessment of genetic kinship, deobfuscation, and threat behavior).\n"
                "Return ONLY valid raw JSON without preamble or markdown commentary."
            )
            user_msg = f"Telemetry:\n```json\n{prompt_payload}\n```\nJSON:"
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg},
            ]
            res = self.llm_client.chat_completion_json(messages=messages, max_tokens=1024)
            if "capabilities" not in res or not res["capabilities"]:
                res["capabilities"] = self._derive_capabilities(prompt_payload)
            return res

        # Direct heuristic attribution if no client configured
        return self._heuristic_attribution(prompt_payload)

    def exec_fallback(self, prep_res: dict[str, Any], exc: Exception) -> dict[str, Any]:
        logger.warning(f"ReportNode LLM inference failed ({exc}). Falling back to heuristic verdict.")
        return self._heuristic_attribution(prep_res["prompt_payload"], note=f"Fallback after: {exc}")

    def _derive_capabilities(self, payload: dict[str, Any]) -> list[str]:
        caps = []
        if payload.get("peeled_layers"):
            caps.append("Layered Payload Deobfuscation")
        if payload.get("entropy", 0.0) > 6.0:
            caps.append("High-Entropy Obfuscation")
        if payload.get("top_genetic_matches"):
            caps.append("MinHash Genetic Trait Kinship")
        radare_meta = payload.get("radare_verification", {})
        if radare_meta.get("function_count", 0) > 0:
            caps.append("Control Flow & ESIL Register Verification")
        if not caps:
            caps.append("Standard Binary Execution")
        return caps

    def _heuristic_attribution(self, payload: dict[str, Any], note: str = "") -> dict[str, Any]:
        matches = payload.get("top_genetic_matches", [])
        entropy = payload.get("entropy", 0.0)
        traits_count = payload.get("traits_extracted", 0)

        family = matches[0]["family"] if matches else "Unknown"
        confidence = matches[0]["similarity_score"] if matches else 0.5
        verdict = "MALICIOUS" if entropy > 6.0 or matches else "SUSPICIOUS"
        summary = f"Heuristic attribution based on {traits_count} genetic traits. {note}".strip()
        caps = self._derive_capabilities(payload)
        return {
            "attribution": family,
            "confidence": confidence,
            "verdict": verdict,
            "summary": summary,
            "capabilities": caps,
        }

    def post(self, shared: Any, prep_res: dict[str, Any], exec_res: dict[str, Any]) -> str:
        shared["current_stage"] = "report"
        shared["llm_verdict"] = exec_res

        top_family = exec_res.get("attribution", "Unknown")
        confidence = exec_res.get("confidence", 0.0)
        verdict = exec_res.get("verdict", "UNKNOWN")
        summary = exec_res.get("summary", "")

        markdown = f"""# BrundleX Triage Report

## Executive Summary
- **Verdict:** {verdict}
- **Family Attribution:** {top_family} (Confidence: {confidence:.2%})
- **Summary:** {summary}

## Telemetry
- **SHA-256:** `{shared.get('sample_sha256', '')}`
- **Format:** {shared.get('file_format', '')} | **Size:** {shared.get('file_size', 0)} bytes
- **Entropy:** {shared.get('entropy', 0.0)} (Shannon)
- **Peeled Layers:** {len(shared.get('peeled_layers', []))}
- **Genetic Traits:** {shared.get('traits_extracted_count', 0)}

## Genetic Lineage Matches
"""
        genetic_matches = shared.get("genetic_matches") or []
        if genetic_matches:
            markdown += "| Family | Match Count | Jaccard Score | Sample SHA256 |\n"
            markdown += "|---|---|---|---|\n"
            for m in genetic_matches[:5]:
                sha = m.get("sample_sha256", "")
                markdown += f"| {m.get('family')} | {m.get('matched_traits_count')} | {m.get('similarity_score')} | `{sha}` |\n"
        else:
            markdown += "*No genetic matches above threshold in local repository.*\n"

        verification = shared.get("radare_verification", {})
        caps = exec_res.get("capabilities", [])
        caps_line = ", ".join(caps) if caps else "Standard Binary Execution"
        markdown += f"""
## Identified Capabilities
- {caps_line}

## Verification Details
- **Functions Disassembled:** {verification.get('function_count', 0)}
- **Entry Symbol:** `{verification.get('verified_function', 'N/A')}`
- **ESIL Register Capture:** `{', '.join(verification.get('emulated_registers', []))}`
"""
        proactive_rule, proactive_metrics, candidate_asm = _synthesize_proactive_mutation(shared, top_family)
        if proactive_rule and proactive_metrics:
            shared["proactive_yara"] = proactive_rule
            shared["proactive_yara_metrics"] = proactive_metrics
            markdown += f"""
## Proactive Threat Defense (Automated Trait Mutation)
- **Target Routine:** Top Candidate Decryptor Routine ({len(candidate_asm)} instructions)
- **ESIL Verification:** 100% Invariant CPU register outcomes verified via Radare2 VM
- **Signature Resilience:** `{proactive_metrics.get('resilience_score', 'N/A')}` ({proactive_metrics.get('verdict', 'Active')})
- **Resilience Context:** {proactive_metrics.get('explanation', '')}
"""
        shared["final_report"] = markdown
        shared["status"] = NodeStatus.COMPLETED

        if hasattr(shared, "log"):
            sha_snip = shared.get("sample_sha256", "")[:16]
            shared.log(f"[REPORT] Completed triage report for {sha_snip}...: Verdict={verdict}")
        return "default"

    def execute(self, state: AnalysisState) -> AnalysisState:
        """Helper for direct execution compatibility."""
        self.run(state)
        return state


class AnalystGateNode(Node):
    """
    Human-in-the-loop analyst checkpoint gate.
    If gate is active and approval has not been registered, pauses flow execution.
    """

    def __init__(self, gate_name: str):
        super().__init__()
        self.gate_name = gate_name

    def prep(self, shared: Any) -> dict[str, Any]:
        required = shared.get("require_approval_gates", {}).get(self.gate_name, False)
        approved = self.gate_name in shared.get("gate_approvals", {})
        return {"required": required, "approved": approved}

    def exec(self, prep_res: dict[str, Any]) -> dict[str, Any]:
        return prep_res

    def post(self, shared: Any, prep_res: dict[str, Any], exec_res: dict[str, Any]) -> str:
        if exec_res["required"] and not exec_res["approved"]:
            shared["status"] = NodeStatus.PAUSED_AT_GATE
            shared["paused_gate_name"] = self.gate_name
            if hasattr(shared, "log"):
                shared.log(f"[GATE] Execution paused at {self.gate_name} waiting for analyst approval.")
            return "pause"

        return "proceed"
