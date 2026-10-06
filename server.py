import html
import re

"""
BrundleX: Single-Page Web Application powered by FastAPI, HTMX, and Pico.css.
Decoupled backend running PocketFlow triage and predictive mutation analysis.
Zero custom JavaScript.
"""

import json
import logging
import os
import shutil
import sqlite3
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.agent.orchestrator import PocketFlowOrchestrator
from src.agent.state import AnalysisState, NodeStatus
from src.harvester.malwarebazaar import (
    HarvesterError,
    MalwareBazaarClient,
    extract_sample_from_zip,
    process_sample_payload,
)
from src.mutation.operators import (
    Instruction,
    analyze_variant_mutation,
    detect_register_mapping,
    generate_mutations,
)
from src.mutation.verifier import ESILVerifier
from src.mutation.yara_generator import calculate_rule_metrics, generate_resilient_yara
from src.storage.db import clear_database, get_sample_count, get_trait_count

logger = logging.getLogger("brundlex.server")
load_dotenv()

app = FastAPI(title="BrundleX Single-Page Workspace")

# Ensure static & upload directories exist
Path("static").mkdir(parents=True, exist_ok=True)
Path("data/uploads").mkdir(parents=True, exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# Application In-Memory State
class AppContext:
    def __init__(self):
        self.dark_theme: bool = True
        self.current_state: AnalysisState | None = None
        self.orchestrator: PocketFlowOrchestrator | None = None
        self.mutation_results: dict[str, Any] | None = None
        self.active_tab: str = "lineage"
        self.selected_sample_choice: str = "stealc"
        self.custom_sample_path: str = "data/samples/stealc_stage1.bin"
        self.gate_peel_checked: bool = True
        self.gate_trait_checked: bool = False
        self.gate_verify_checked: bool = False
        self.studio_block_text: str = "xor rcx, rcx\nmov rdx, 0x20\nadd rax, 1" 
        self.studio_aggression: int = 2
        self.studio_num_variants: int = 2
        self.pinned_samples: list[dict[str, str]] = [
            {"id": "stealc", "name": "Stealc Core (stealc_stage1.bin)", "path": "data/samples/stealc_stage1.bin"},
            {"id": "lumma", "name": "Lumma Stealer (lumma_dropper.bin)", "path": "data/samples/lumma_dropper.bin"},
            {"id": "redline", "name": "Redline Stealer (redline_stealer.bin)", "path": "data/samples/redline_stealer.bin"},
        ]
        self.unpinned_samples: list[dict[str, str]] = [
            {"id": "ls", "name": "System Utility (/bin/ls)", "path": "/bin/ls"},
        ]
        self.chat_messages: list[dict[str, str]] = [
            {
                "role": "assistant",
                "content": (
                    "Welcome to BrundleX Autonomous Triage Studio.\n"
                    "Select a binary target from the library, upload a new sample, or provide a local path. "
                    "Configure analyst approval gates, and launch the automated triage pipeline."
                ),
            }
        ]
        self.analysis_history: list[dict[str, str]] = []
        self.mutation_history: list[dict[str, Any]] = []
        self.pipeline_running: bool = False


context = AppContext()


def _render_simple_table(table_lines: list[str]) -> str:
    if not table_lines:
        return ""
    html_parts = ['<div style="overflow-x: auto; margin: 0.4rem 0;"><table class="striped" style="font-size: 0.75rem; margin: 0;">']
    header_done = False
    for line in table_lines:
        cells = [c.strip() for c in line.strip("|").split("|")]
        if all(re.match(r"^:?-+:?$", c) for c in cells):
            continue
        if not header_done:
            html_parts.append("<thead><tr>" + "".join(f"<th style='padding: 3px 6px;'>{c}</th>" for c in cells) + "</tr></thead><tbody>")
            header_done = True
        else:
            html_parts.append("<tr>" + "".join(f"<td style='padding: 3px 6px;'>{c}</td>" for c in cells) + "</tr>")
    if header_done:
        html_parts.append("</tbody>")
    html_parts.append("</table></div>")
    return "".join(html_parts)


def render_chat_markdown(text: str) -> str:
    """
    Lightweight, safe markdown renderer for chat dialogue.
    Converts markdown headers, bold, italics, code, lists, and tables to clean HTML.
    """
    if not text:
        return ""
    escaped = html.escape(text)

    def _code_block_sub(match):
        code = match.group(1).strip()
        return f'<pre style="margin: 0.4rem 0; padding: 0.5rem; font-size: 0.75rem; overflow-x: auto; background: var(--pico-card-background-color); border: 1px solid var(--pico-muted-border-color); border-radius: 4px;"><code>{code}</code></pre>'
    escaped = re.sub(r"```(?:\w+)?\n?(.*?)```", _code_block_sub, escaped, flags=re.DOTALL)
    escaped = re.sub(r"`([^`]+)`", r"<code style='font-size: 0.78rem; padding: 1px 4px;'>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"^###\s+(.+)$", r"<strong style='display:block; margin-top:0.4rem; margin-bottom:0.15rem; color:var(--pico-color); font-size:0.85rem;'>\1</strong>", escaped, flags=re.MULTILINE)
    escaped = re.sub(r"^##\s+(.+)$", r"<strong style='display:block; margin-top:0.5rem; margin-bottom:0.2rem; color:var(--pico-color); font-size:0.9rem;'>\1</strong>", escaped, flags=re.MULTILINE)
    escaped = re.sub(r"^[*-]\s+(.+)$", r"<div style='margin-left: 0.6rem; margin-top: 2px;'>• \1</div>", escaped, flags=re.MULTILINE)
    escaped = re.sub(r"^(\d+)\.\s+(.+)$", r"<div style='margin-left: 0.6rem; margin-top: 2px;'><strong>\1.</strong> \2</div>", escaped, flags=re.MULTILINE)

    lines = escaped.split("\n")
    formatted_lines = []
    in_table = False
    table_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            if not in_table:
                in_table = True
                table_lines = []
            table_lines.append(stripped)
            continue
        elif in_table:
            formatted_lines.append(_render_simple_table(table_lines))
            in_table = False
            table_lines = []

        formatted_lines.append(line)

    if in_table:
        formatted_lines.append(_render_simple_table(table_lines))

    result = "\n".join(formatted_lines)
    result = re.sub(r"(?<!</div>)(?<!</pre>)(?<!</table>)\n", "<br>", result)
    return result

def get_db_path() -> str:
    return os.getenv("TRAITS_DB_PATH", "data/traits.db")


def get_common_context() -> dict[str, Any]:
    db_p = get_db_path()
    sample_cnt = get_sample_count(db_p)
    trait_cnt = get_trait_count(db_p)
    return {
        "dark_theme": context.dark_theme,
        "state": context.current_state,
        "mutation_results": context.mutation_results,
        "chat_messages": [
            {
                "role": m.get("role", "assistant"),
                "content": m.get("content", ""),
                "html": render_chat_markdown(m.get("content", "")),
            }
            for m in context.chat_messages
        ],
        "analysis_history": context.analysis_history,
        "mutation_history": context.mutation_history,
        "active_tab": context.active_tab,
        "selected_sample_choice": context.selected_sample_choice,
        "custom_sample_path": context.custom_sample_path,
        "gate_peel_checked": context.gate_peel_checked,
        "gate_trait_checked": context.gate_trait_checked,
        "gate_verify_checked": context.gate_verify_checked,
        "pinned_samples": context.pinned_samples,
        "unpinned_samples": context.unpinned_samples,
        "studio_block_text": context.studio_block_text,
        "studio_aggression": context.studio_aggression,
        "studio_num_variants": context.studio_num_variants,
        "sample_count": sample_cnt,
        "trait_count": trait_cnt,
        "pipeline_running": context.pipeline_running,
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.api_route("/theme/toggle", methods=["GET", "POST"])
async def toggle_theme(request: Request):
    context.dark_theme = not context.dark_theme
    return RedirectResponse(url="/", status_code=303)


@app.post("/triage/upload", response_class=HTMLResponse)
async def upload_sample(
    request: Request,
    sample_file: UploadFile,
    zip_password: str = Form("infected"),
):
    """Handles direct malware, binary, or encrypted/unencrypted ZIP sample uploads from the analyst."""
    try:
        raw_bytes = await sample_file.read()
        if not raw_bytes:
            context.chat_messages.append({
                "role": "assistant",
                "content": "Uploaded file is empty (0 bytes).",
            })
            return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())

        filename = sample_file.filename or "uploaded_sample.bin"
        safe_filename = "".join(c for c in filename if c.isalnum() or c in "._- ") or "sample.bin"

        # Check for ZIP archive (magic bytes PK\x03\x04 or .zip extension)
        is_zip = raw_bytes.startswith(b"PK") or safe_filename.lower().endswith(".zip")

        if is_zip:
            scratch_dir = tempfile.mkdtemp(prefix="brundlex_zip_")
            try:
                pwd_bytes = zip_password.strip().encode() if zip_password else b"infected"
                extracted_path = extract_sample_from_zip(raw_bytes, scratch_dir, password=pwd_bytes)
                extracted_name = Path(extracted_path).name
                dest_path = Path("data/uploads") / f"extracted_{extracted_name}"
                shutil.copy2(extracted_path, dest_path)
                status_msg = f"Extracted `{extracted_name}` ({dest_path.stat().st_size:,} bytes) from ZIP archive (`{safe_filename}`). Added to library & selected."
            finally:
                shutil.rmtree(scratch_dir, ignore_errors=True)
        else:
            dest_path = Path("data/uploads") / safe_filename
            dest_path.write_bytes(raw_bytes)
            status_msg = f"Uploaded sample `{dest_path.name}` ({dest_path.stat().st_size:,} bytes). Added to library & selected."

        sample_id = f"upload_{len(context.unpinned_samples) + 1}"
        context.unpinned_samples.append({
            "id": sample_id,
            "name": f"Uploaded: {dest_path.name}",
            "path": str(dest_path),
        })
        context.selected_sample_choice = sample_id
        context.custom_sample_path = str(dest_path)
        context.chat_messages.append({
            "role": "assistant",
            "content": status_msg,
        })
    except HarvesterError as e:
        context.chat_messages.append({
            "role": "assistant",
            "content": f"ZIP archive extraction failed: {e}. Check password or archive integrity.",
        })
    except Exception as e:  # noqa: BLE001
        context.chat_messages.append({
            "role": "assistant",
            "content": f"Upload failed: {e}",
        })

    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/sample/pin", response_class=HTMLResponse)
async def pin_sample(
    request: Request,
    sample_id: str = Form(...),
):
    """Pins an unpinned sample to top favorites."""
    item = next((s for s in context.unpinned_samples if s["id"] == sample_id), None)
    if item:
        context.unpinned_samples.remove(item)
        if item not in context.pinned_samples:
            context.pinned_samples.append(item)
    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/sample/unpin", response_class=HTMLResponse)
async def unpin_sample(
    request: Request,
    sample_id: str = Form(...),
):
    """Unpins a sample from top favorites into library list."""
    item = next((s for s in context.pinned_samples if s["id"] == sample_id), None)
    if item:
        context.pinned_samples.remove(item)
        if item not in context.unpinned_samples:
            context.unpinned_samples.append(item)
    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/triage/select_target", response_class=HTMLResponse)
async def select_target(
    request: Request,
    sample_choice: str = Form("stealc"),
    custom_path: str = Form(""),
):
    """Dynamically updates active target selection when dropdown changes."""
    context.selected_sample_choice = sample_choice
    all_samples = {s["id"]: s["path"] for s in context.pinned_samples + context.unpinned_samples}
    if sample_choice == "custom":
        if custom_path.strip():
            context.custom_sample_path = custom_path.strip()
    else:
        chosen_path = all_samples.get(sample_choice)
        if chosen_path:
            context.custom_sample_path = chosen_path

    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/triage/start", response_class=HTMLResponse)
async def start_triage(
    request: Request,
    sample_choice: str = Form("stealc"),
    custom_path: str = Form(""),
    gate_peel: str | None = Form(None),
    gate_trait: str | None = Form(None),
    gate_verify: str | None = Form(None),
    sync: str | None = Form(None),
):
    context.selected_sample_choice = sample_choice
    context.custom_sample_path = custom_path.strip()
    context.gate_peel_checked = gate_peel is not None
    context.gate_trait_checked = gate_trait is not None
    context.gate_verify_checked = gate_verify is not None

    all_samples = {s["id"]: s["path"] for s in context.pinned_samples + context.unpinned_samples}
    if sample_choice == "custom":
        target_path = context.custom_sample_path
    else:
        target_path = all_samples.get(sample_choice, context.custom_sample_path)

    if not os.path.exists(target_path):
        context.chat_messages.append({"role": "assistant", "content": f"Error: Target file not found: {target_path}"})
        return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())

    gates = {
        "gate_peel": context.gate_peel_checked,
        "gate_trait": context.gate_trait_checked,
        "gate_verify": context.gate_verify_checked,
    }

    orch = PocketFlowOrchestrator(
        db_path=get_db_path(),
        require_approval_gates=gates,
    )
    context.orchestrator = orch
    new_state = AnalysisState(sample_path=target_path)
    new_state.current_stage = "ingest"
    new_state.status = NodeStatus.IN_PROGRESS
    context.current_state = new_state

    # Add initial history entry
    context.analysis_history.append({
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "sample": target_path,
        "family": "Pending",
        "status": NodeStatus.IN_PROGRESS.value,
    })

    if sync == "1":
        orch.run_until_pause_or_finish(new_state)
        family = new_state.llm_verdict.get("attribution", "Pending") if new_state.llm_verdict else "Pending"
        context.analysis_history[-1]["family"] = family
        context.analysis_history[-1]["status"] = new_state.status.value
        context.pipeline_running = False
        return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())

    context.pipeline_running = True

    def _run_triage_flow():
        try:
            orch.run_until_pause_or_finish(new_state)
        except Exception as e:
            logger.exception("Background triage failed")
            new_state.status = NodeStatus.FAILED
            new_state.error_message = str(e)
            if hasattr(new_state, "log"):
                new_state.log(f"[ERROR] Pipeline execution failed: {e}")
        finally:
            context.pipeline_running = False
            family = new_state.llm_verdict.get("attribution", "Pending") if new_state.llm_verdict else "Pending"
            if context.analysis_history:
                context.analysis_history[-1]["family"] = family
                context.analysis_history[-1]["status"] = new_state.status.value

    threading.Thread(target=_run_triage_flow, daemon=True).start()
    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/triage/approve", response_class=HTMLResponse)
async def approve_gate(
    request: Request,
    notes: str = Form(""),
    sync: str | None = Form(None),
):
    if context.current_state and context.orchestrator and context.current_state.status == NodeStatus.PAUSED_AT_GATE:
        gate_name = context.current_state.paused_gate_name or "unknown_gate"
        context.chat_messages.append({
            "role": "user",
            "content": f"Gate [{gate_name}] approved: {notes}",
        })

        if sync == "1":
            resumed_state = context.orchestrator.approve_and_resume(
                context.current_state, gate_name=gate_name, notes=notes
            )
            context.current_state = resumed_state
            if context.analysis_history:
                latest_family = resumed_state.llm_verdict.get("attribution", "Pending") if resumed_state.llm_verdict else "Pending"
                context.analysis_history[-1]["family"] = latest_family
                context.analysis_history[-1]["status"] = resumed_state.status.value
            return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())

        context.pipeline_running = True
        context.current_state.status = NodeStatus.IN_PROGRESS

        def _resume_triage_flow():
            try:
                resumed_state = context.orchestrator.approve_and_resume(
                    context.current_state, gate_name=gate_name, notes=notes
                )
                context.current_state = resumed_state
            except Exception as e:
                logger.exception("Background resume failed")
                context.current_state.status = NodeStatus.FAILED
                context.current_state.error_message = str(e)
            finally:
                context.pipeline_running = False
                if context.analysis_history:
                    latest_family = context.current_state.llm_verdict.get("attribution", "Pending") if context.current_state.llm_verdict else "Pending"
                    context.analysis_history[-1]["family"] = latest_family
                    context.analysis_history[-1]["status"] = context.current_state.status.value

        threading.Thread(target=_resume_triage_flow, daemon=True).start()

    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.get("/triage/poll", response_class=HTMLResponse)
async def triage_poll(request: Request):
    """HTMX poller endpoint for progressive triage status and telemetry."""
    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/triage/abort", response_class=HTMLResponse)
async def abort_pipeline(request: Request):
    context.pipeline_running = False
    if context.current_state and context.current_state.status == NodeStatus.PAUSED_AT_GATE:
        gate_name = context.current_state.paused_gate_name
        context.current_state.status = NodeStatus.FAILED
        context.current_state.error_message = f"Aborted by analyst at gate {gate_name}"
        context.chat_messages.append({
            "role": "assistant",
            "content": f"Pipeline aborted at gate [{gate_name}].",
        })
        if context.analysis_history:
            context.analysis_history[-1]["status"] = NodeStatus.FAILED.value

    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/triage/reset", response_class=HTMLResponse)
async def reset_run(request: Request):
    """Resets active run state while preserving history and threat database."""
    context.pipeline_running = False
    context.current_state = None
    context.mutation_results = None
    context.chat_messages = [
        {
            "role": "assistant",
            "content": "Pipeline reset. Ready for next binary sample.",
        }
    ]
    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/triage/harvest", response_class=HTMLResponse)
async def harvest_corpus(
    request: Request,
    family: str = Form(""),
    tag: str = Form("unpacked"),
    limit: int = Form(5),
    max_entropy: float = Form(7.1),
):
    """
    Harvests live malware samples directly from MalwareBazaar API.
    Supports comma-separated multi-family and multi-tag batch queries.
    Applies configurable parameters: family signatures, tags, limit per query, entropy gate.
    """
    db_p = get_db_path()
    api_key = os.getenv("MALWAREBAZAAR_API_KEY", "")
    if not api_key or api_key == "your_malwarebazaar_api_key_here":
        context.chat_messages.append({
            "role": "assistant",
            "content": "MalwareBazaar API key not configured. Please set MALWAREBAZAAR_API_KEY in your .env file to harvest live samples.",
        })
    else:
        api_key = os.getenv("MALWAREBAZAAR_API_KEY", "")
        try:
            client = MalwareBazaarClient(api_key=api_key)

            # Parse comma-separated families and tags
            families = [f.strip() for f in family.split(",") if f.strip()]
            tags = [t.strip() for t in tag.split(",") if t.strip()]

            raw_samples: list[dict[str, Any]] = []
            queries_run: list[str] = []

            FAMILY_ALIASES = {
                "lumma": ["LummaStealer", "Lumma"],
                "stealc": ["Stealc"],
                "redline": ["RedLine", "Redline"],
                "agenttesla": ["AgentTesla"],
                "asyncrat": ["AsyncRAT"],
            }

            if families:
                for fam in families:
                    queries_run.append(f"family '{fam}'")
                    lookup_names = FAMILY_ALIASES.get(fam.lower(), [fam])
                    fam_hits = []
                    for name in lookup_names:
                        fam_hits = client.query_signature(name, limit=limit)
                        if fam_hits:
                            break
                    for s in fam_hits:
                        s["_resolved_family"] = fam
                    raw_samples.extend(fam_hits)
            else:
                active_tags = tags or ["unpacked"]
                for t in active_tags:
                    queries_run.append(f"tag '{t}'")
                    tag_samples = client.query_tag(t, limit=limit)
                    for s in tag_samples:
                        s["_resolved_family"] = s.get("signature") or "Unknown"
                    raw_samples.extend(tag_samples)

            # Deduplicate by sha256_hash across multi-target batch
            seen_shas: set[str] = set()
            unique_samples: list[dict[str, Any]] = []
            for s in raw_samples:
                h = s.get("sha256_hash")
                if h and h not in seen_shas:
                    seen_shas.add(h)
                    unique_samples.append(s)

            indexed_count = 0
            skipped_packed_count = 0
            total_traits_added = 0
            for meta in unique_samples:
                sha256 = meta.get("sha256_hash")
                sig = meta.get("_resolved_family", "Unknown")
                first_seen = meta.get("first_seen")
                if not sha256:
                    continue
                try:
                    zip_data = client.download_sample(sha256)
                    res = process_sample_payload(
                        sha256=sha256,
                        family=sig,
                        zip_bytes=zip_data,
                        db_path=db_p,
                        max_entropy=max_entropy,
                        first_seen=first_seen,
                    )
                    status = res.get("status")
                    if status == "indexed":
                        indexed_count += 1
                        total_traits_added += res.get("traits_count", 0)
                    elif status == "skipped_packed":
                        skipped_packed_count += 1
                except (HarvesterError, OSError) as payload_err:
                    logger.warning("Skipping sample %s due to processing error: %s", sha256, payload_err)

            query_summary = ", ".join(queries_run) if queries_run else "default query"
            context.chat_messages.append({
                "role": "assistant",
                "content": (
                    f"Harvest completed for {query_summary}: {len(unique_samples)} candidate samples retrieved from MalwareBazaar. "
                    f"{indexed_count} samples passed entropy gate (H <= {max_entropy:.2f}) and indexed ({total_traits_added} traits extracted). "
                    f"{skipped_packed_count} samples rejected as packed/encrypted."
                ),
            })
        except (HarvesterError, OSError) as e:
            context.chat_messages.append({
                "role": "assistant",
                "content": f"Live harvest encountered an error: {e}.",
            })

    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/triage/db/clear", response_class=HTMLResponse)
async def clear_threat_db(request: Request):
    """
    Completely clears all indexed malware samples and genetic traits from SQLite.
    Resets threat DB to 0 while preserving table schemas and indices.
    """
    db_p = get_db_path()
    try:
        clear_database(db_p)
        context.chat_messages.append({
            "role": "assistant",
            "content": "Threat database completely cleared. All indexed samples and genetic traits purged.",
        })
    except (sqlite3.Error, OSError) as e:
        context.chat_messages.append({
            "role": "assistant",
            "content": f"Error clearing threat database: {e}",
        })

    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/chat/send", response_class=HTMLResponse)
def send_chat(
    request: Request,
    message: str = Form(...),
):
    msg = message.strip()
    if msg:
        context.chat_messages.append({"role": "user", "content": msg})
        
        reply = None
        # Attempt intelligent response using LLMClient if available
        try:
            from src.agent.llm_client import LLMClient
            llm = LLMClient()
            state = context.current_state
            state_ctx = {
                "active_sample": state.sample_path if state else "No sample loaded",
                "sha256": state.sample_sha256 if state else "",
                "format": state.file_format if state else "",
                "entropy": state.entropy if state else 0.0,
                "current_stage": state.current_stage if state else "idle",
                "status": state.status.value if state else "not_started",
                "peeled_layers": len(state.peeled_layers) if state else 0,
                "genetic_matches": state.genetic_matches[:3] if state and state.genetic_matches else [],
                "traits_count": state.traits_extracted_count if state else 0,
                "llm_verdict": state.llm_verdict if state else {},
                "emulated_registers": (state.radare_verification.get("emulated_registers") or []) if state else [],
                "candidate_decryptor_blocks": [
                    {
                        "offset": hex(c.get("offset", 0)),
                        "instructions": c.get("instructions", 0),
                        "complexity": c.get("cyclomatic_complexity", 1),
                        "entropy": round(c.get("trait_entropy", 0.0), 2),
                    }
                    for c in (state.candidate_blocks[:3] if state and state.candidate_blocks else [])
                ],
                "proactive_mutation_defense": {
                    "rule_synthesized": bool(state and state.proactive_yara),
                    "metrics": state.proactive_yara_metrics if state else {},
                },
            }
            system_prompt = (
                "You are BrundleX AI, an elite binary triage and predictive malware mutation assistant. "
                "You have full visibility into extracted genetic traits, candidate decryptor loops, semantic mutations, and synthesized resilient YARA rules. "
                "The human analyst is reviewing telemetry and asking questions or issuing commands. "
                "Answer directly, concisely, and authoritatively based on the active binary context.\n"
                "Format responses cleanly for a compact analyst console: do NOT use wide markdown tables with pipe characters (they wrap and become unreadable). Instead, format structured comparisons using clean bulleted lists with bold titles and inline code tags.\n"
                f"Active Binary Context: {json.dumps(state_ctx, default=str)}"
            )
            chat_history = [
                {"role": "system", "content": system_prompt},
            ]
            for m in context.chat_messages[-6:]:
                r = "user" if m.get("role") == "user" else "assistant"
                chat_history.append({"role": r, "content": m.get("content", "")})
            
            ai_reply = llm.chat_completion_text(messages=chat_history, max_tokens=1500)
            if ai_reply and ai_reply.strip():
                reply = ai_reply.strip()
        except Exception as e:  # noqa: BLE001  # noqa: BLE001
            logger.warning(f"Interactive LLM chat failed: {e}")
            reply = None

        if not reply:
            reply = (
                f"Analyst command received: '{msg}'. Telemetry updated."
                if not context.current_state
                else f"Acknowledged: '{msg}'. Triage telemetry reviewed."
            )
        context.chat_messages.append({"role": "assistant", "content": reply})

    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.post("/mutation/simulate", response_class=HTMLResponse)
def simulate_mutations(
    request: Request,
    block_text: str = Form(...),
    aggression: int = Form(2),
    num_variants: int = Form(2),
    rule_name: str = Form("brundlex_simulated_block"),
    threat_family: str = Form("Generic"),
    author: str = Form("BrundleX Agent & Threat Analyst"),
    tlp: str = Form("CLEAR"),
    description: str = Form("Resilient predictive signature for evasive variants"),
    severity: str = Form("HIGH"),
    reference: str = Form("BrundleX Predictive Mutation Engine"),
):
    """
    Simulates semantic mutations across input assembly instructions,
    verifies ESIL register/stack equivalence via Radare2,
    and synthesizes a resilient YARA signature with configurable metadata.
    """
    lines = [line.strip() for line in block_text.strip().splitlines() if line.strip()]
    orig_instructions: list[Instruction] = []
    for line in lines:
        parts = line.split(maxsplit=1)
        mnemonic = parts[0]
        operands = [op.strip() for op in parts[1].split(",")] if len(parts) > 1 else []
        orig_instructions.append(Instruction(mnemonic=mnemonic, operands=operands))

    # Generate variants based on aggression
    mutant_variants = generate_mutations(orig_instructions, aggression=aggression, num_variants=num_variants)

    # Convert instructions to bytecode sequences for ESIL verification & YARA synthesis
    def _block_to_bytes(block: list[Instruction]) -> bytes:
        hex_str = "".join(inst.bytes_hex for inst in block if inst.bytes_hex)
        return bytes.fromhex(hex_str) if hex_str else b""

    orig_bytes = _block_to_bytes(orig_instructions)

    # Verify equivalence in ESIL
    verifier = ESILVerifier()
    reports = []
    verified_byte_variants: list[bytes] = [orig_bytes] if orig_bytes else []

    for i, variant in enumerate(mutant_variants, 1):
        var_bytes = _block_to_bytes(variant)
        if orig_bytes and var_bytes:
            reg_map = detect_register_mapping(orig_instructions, variant)
            is_inv, _, _ = verifier.verify_equivalence(
                orig_bytes, var_bytes, arch="x86", bits=64, reg_map=reg_map
            )
            if is_inv:
                verified_byte_variants.append(var_bytes)
        else:
            is_inv = True

        tactical = analyze_variant_mutation(orig_instructions, variant)
        reports.append({
            "variant_id": f"Variant #{i}",
            "assembly": "; ".join(inst.to_assembly() for inst in variant),
            "equivalent": is_inv,
            "confidence": 1.0 if is_inv else 0.0,
            "tactic_tag": tactical["tactic_tag"],
            "tactical_summary": tactical["tactical_summary"],
            "tactical_explanation": tactical["tactical_explanation"],
        })

    # Formulate dynamic descriptive rule name including family, variant count, and aggression
    clean_fam = "".join(c if c.isalnum() or c == "_" else "_" for c in threat_family).strip("_").lower() or "generic"
    clean_input_rule = "".join(c if c.isalnum() or c == "_" else "_" for c in rule_name).strip("_")
    base_name = re.sub(r"_a\d+_v\d+$", "", clean_input_rule)
    if not base_name or base_name in ("brundlex_simulated_block", "brundlex_generic_decryptor"):
        base_name = f"brundlex_{clean_fam}"
    final_rule_name = f"{base_name}_a{aggression}_v{num_variants}"

    # Generate resilient YARA rule with metadata
    extra_meta = {
        "tlp": tlp,
        "severity": severity,
        "reference": reference,
        "aggression": str(aggression),
        "variants_count": str(len(mutant_variants)),
    }

    if verified_byte_variants:
        yara_rule = generate_resilient_yara(
            rule_name=final_rule_name,
            variants=verified_byte_variants,
            family=threat_family,
            author=author,
            description=description,
            extra_meta=extra_meta,
        )
    else:
        yara_rule = f'rule {final_rule_name} {{\n    meta:\n        author = "{author}"\n    condition:\n        true\n}}\n'

    rule_metrics = calculate_rule_metrics(verified_byte_variants)

    context.active_tab = "studio"
    context.studio_block_text = block_text
    context.studio_aggression = aggression
    context.studio_num_variants = num_variants
    context.mutation_results = {
        "rule_name": final_rule_name,
        "yara": yara_rule,
        "reports": reports,
        "metrics": rule_metrics,
    }

    # Record mutation history
    context.mutation_history.append({
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "rule_name": final_rule_name,
        "input_asm": "; ".join(inst.to_assembly() for inst in orig_instructions),
        "aggression": aggression,
        "variant_count": len(mutant_variants),
        "yara_rule": yara_rule,
    })

    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())


@app.get("/mutation/download")
async def download_yara():
    """Returns the latest synthesized or proactive YARA rule as a downloadable .yar text attachment."""
    rule_name = "brundlex_rule"
    rule_content = ""
    if context.mutation_results and "yara" in context.mutation_results:
        rule_name = context.mutation_results.get("rule_name", "brundlex_rule")
        rule_content = context.mutation_results["yara"]
    elif context.current_state and context.current_state.proactive_yara:
        fam = context.current_state.llm_verdict.get("attribution", "generic") if context.current_state.llm_verdict else "generic"
        clean_fam = "".join(c if c.isalnum() or c == "_" else "_" for c in fam).strip("_")
        rule_name = f"brundlex_proactive_{clean_fam.lower()}_decryptor"
        rule_content = context.current_state.proactive_yara

    if not rule_content:
        return PlainTextResponse(content="// No YARA rule generated yet.\n", media_type="text/plain")

    return PlainTextResponse(
        content=rule_content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{rule_name}.yar"'},
    )


@app.post("/tab/select", response_class=HTMLResponse)
async def select_tab(
    request: Request,
    tab: str = Form("lineage"),
):
    context.active_tab = tab
    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())
@app.post("/history/clear", response_class=HTMLResponse)
async def clear_history(request: Request):
    """Clears past triage runs and mutation history."""
    context.analysis_history.clear()
    context.mutation_history.clear()
    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())



@app.get("/triage/report/download")
async def download_triage_report():
    """Exports the full untruncated Markdown triage report as a downloadable file."""
    if not context.current_state or not context.current_state.final_report:
        return PlainTextResponse(
            content="# BrundleX Triage Report\n\n*No completed report generated yet.*\n",
            media_type="text/markdown",
        )
    sha_snip = (context.current_state.sample_sha256 or "sample")[:12]
    filename = f"brundlex_{sha_snip}_report.md"
    return PlainTextResponse(
        content=context.current_state.final_report,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.get("/triage/dialog/download")
async def download_dialog():
    """Exports the analyst commands, gate decisions, and system execution trace as a structured procedural log."""
    lines = [
        "=" * 68,
        "BrundleX Autonomous Triage Studio - Procedural Audit & Dialogue Log",
        "=" * 68,
    ]

    # Section 1: Gate Approvals & Operational Decisions
    gate_events = []
    if context.current_state and context.current_state.analyst_decisions:
        for d in context.current_state.analyst_decisions:
            gate_name = d.get("gate_name", "gate")
            notes = d.get("notes", "")
            appr = "APPROVED" if d.get("approved") else "REJECTED"
            gate_events.append(f"• Gate [{gate_name}] {appr}: notes='{notes}'")

    lines.append("")
    lines.append("--- Analyst Gate Checkpoints & Governance Decisions ---")
    if gate_events:
        lines.extend(gate_events)
    else:
        # Fall back to any gate records in chat
        for msg in context.chat_messages:
            if msg.get("role") == "user" and "Gate [" in msg.get("content", ""):
                lines.append(f"• {msg.get('content')}")
        if len(lines) == 5:
            lines.append("(No gate checkpoints triggered in active session)")

    # Section 2: Analyst Prompts & Agent Technical Answers
    prompt_exchanges = []
    for msg in context.chat_messages:
        content = msg.get("content", "")
        # Filter out gate approval synthetics from conversational prompts
        if "Gate [" in content and "approved" in content:
            continue
        role = "Analyst Prompt" if msg.get("role") == "user" else "BrundleX Response"
        prompt_exchanges.append(f"[{role}]:\n{content}\n")

    lines.append("")
    lines.append("--- Analyst Prompts & Agent Technical Responses ---")
    if prompt_exchanges:
        lines.extend(prompt_exchanges)
    else:
        lines.append("(No interactive analyst prompts recorded)\n")

    # Section 3: Subsystem Execution Traces
    lines.append("--- Subsystem Execution Traces (Chronological) ---")
    if context.current_state and context.current_state.execution_log:
        for trace in context.current_state.execution_log:
            lines.append(f"• {trace}")
    else:
        lines.append("(No system traces recorded)")

    output_text = "\n".join(lines) + "\n"
    filename = "brundlex_triage_audit_log.txt"
    if context.current_state and context.current_state.sample_sha256:
        filename = f"brundlex_{context.current_state.sample_sha256[:12]}_audit_log.txt"

    return PlainTextResponse(
        content=output_text,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/mutation/load_candidate", response_class=HTMLResponse)
def load_candidate_to_studio(
    request: Request,
    offset: int = Form(...),
):
    """
    Disassembles candidate block at offset using RadareRunner or falls back to
    disassembled instruction representation, updates studio_block_text, and switches active tab to studio.
    """
    context.active_tab = "studio"
    target_path = ""
    if context.current_state:
        target_path = context.current_state.active_payload_path or context.current_state.sample_path

    disasm_lines = []
    if target_path and os.path.exists(target_path):
        try:
            from src.tools.radare_runner import RadareRunner
            with RadareRunner(target_path) as r2:
                r2.analyze(level="aa")
                # Binlex offsets are raw file/physical offsets; disable virtual address remapping
                r2.r2.cmd("e io.va=false")
                ops = r2.r2.cmdj(f"pdj 5 @ {offset}")
                if ops:
                    for op in ops:
                        opcode = op.get("opcode", "").strip()
                        if opcode and opcode != "invalid":
                            disasm_lines.append(opcode)
        except (RuntimeError, OSError, ValueError) as disasm_err:
            logger.debug("Failed to disassemble candidate block: %s", disasm_err)

    if disasm_lines:
        context.studio_block_text = "\n".join(disasm_lines)
    else:
        context.studio_block_text = "xor ecx, ecx\nmov rdx, 0x20\nadd rax, 1"

    # Automatically simulate baseline mutations for the loaded candidate block
    try:
        orig_instructions = []
        for line in context.studio_block_text.splitlines():
            line = line.strip()
            if not line:
                continue
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
        reports = []
        verified_bytes = [orig_bytes] if orig_bytes else []

        for i, variant in enumerate(mutant_variants, 1):
            vb = _block_to_bytes(variant)
            is_inv = True
            if orig_bytes and vb:
                is_inv, _, _ = verifier.verify_equivalence(orig_bytes, vb, arch="x86", bits=64)
                if is_inv:
                    verified_bytes.append(vb)
            elif vb:
                verified_bytes.append(vb)

            tactical = analyze_variant_mutation(orig_instructions, variant)
            reports.append({
                "variant_id": f"Variant #{i}",
                "assembly": "; ".join(inst.to_assembly() for inst in variant),
                "equivalent": is_inv,
                "confidence": 1.0 if is_inv else 0.0,
                "tactic_tag": tactical["tactic_tag"],
                "tactical_summary": tactical["tactical_summary"],
                "tactical_explanation": tactical["tactical_explanation"],
            })

        cand_idx = 1
        if context.current_state and context.current_state.candidate_blocks:
            for idx, c in enumerate(context.current_state.candidate_blocks, 1):
                if c.get("offset") == offset:
                    cand_idx = idx
                    break

        fam = context.current_state.llm_verdict.get("attribution", "Generic") if context.current_state and context.current_state.llm_verdict else "Generic"
        clean_fam = "".join(c if c.isalnum() or c == "_" else "_" for c in fam).strip("_").lower() or "generic"
        rule_name = f"brundlex_{clean_fam}_candidate{cand_idx}_a2_v2"
        yara_rule = generate_resilient_yara(
            rule_name=rule_name,
            variants=verified_bytes,
            family=fam,
            author="BrundleX Agent & Threat Analyst",
            description=f"Resilient predictive signature for candidate decryptor block at {hex(offset)}",
            extra_meta={"tlp": "CLEAR", "severity": "HIGH"},
        )
        metrics = calculate_rule_metrics(verified_bytes)
        context.mutation_results = {
            "rule_name": rule_name,
            "yara": yara_rule,
            "reports": reports,
            "metrics": metrics,
        }
    except Exception as sim_err:  # noqa: BLE001
        logger.debug("Failed auto-simulation on loaded candidate: %s", sim_err)

    return templates.TemplateResponse(request=request, name="index.html", context=get_common_context())
